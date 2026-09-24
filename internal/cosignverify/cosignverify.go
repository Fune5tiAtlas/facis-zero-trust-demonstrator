// Package cosignverify verifies container images against the demonstrator's one signing profile:
// cosign v2 classic layout (".sig" and ".att" tags), key-based ECDSA P-256, no transparency log,
// attestations as DSSE envelopes of in-toto Statement v0.1. Anything outside that profile is refused.
//
// A result names the admission reason code of the first check that failed, from the contracts'
// reason-code registry.
package cosignverify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/ociclient"
)

// Reason codes (docs/contracts/reason-codes.json).
const (
	CodeNotDigest          = "ADM-NOT-DIGEST"
	CodeRegistryDenied     = "ADM-REGISTRY-DENIED"
	CodeUnsigned           = "ADM-UNSIGNED"
	CodeSBOMMissing        = "ADM-SBOM-MISSING"
	CodeNoAttestation      = "ADM-NO-ATTESTATION"
	CodeAttestationInvalid = "ADM-ATTESTATION-INVALID"
	CodeProviderDown       = "ADM-PROVIDER-DOWN"
)

// Predicate types of the two required attestations.
const (
	PredicateSBOM = "https://cyclonedx.org/bom"
	PredicateMock = "https://facis.eu/ztd/mock-attestation/v1"
)

const (
	statementType      = "https://in-toto.io/Statement/v0.1"
	inTotoPayloadType  = "application/vnd.in-toto+json"
	simpleSigningType  = "application/vnd.dev.cosign.simplesigning.v1+json"
	dsseEnvelopeType   = "application/vnd.dsse.envelope.v1+json"
	signatureAnnot     = "dev.cosignproject.cosign/signature"
	cosignSignatureTyp = "cosign container image signature"
)

// Policy is the trust configuration. Revision identifies it in the cache: a new policy never sees a
// result computed under an old one.
type Policy struct {
	// Repositories lists allowed repository prefixes, "host/path" (e.g. "ghcr.io/org"); an image is
	// allowed when "host/repository" equals an entry or continues it with "/".
	Repositories []string
	Keys         []*ecdsa.PublicKey
	Revision     string
}

// ParsePublicKeys reads PEM "PUBLIC KEY" blocks (cosign.pub) and accepts only ECDSA P-256 keys.
func ParsePublicKeys(pemData []byte) ([]*ecdsa.PublicKey, error) {
	var keys []*ecdsa.PublicKey
	for {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}
		if block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("cosignverify: unexpected PEM block %q", block.Type)
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("cosignverify: %w", err)
		}
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok || key.Curve != elliptic.P256() {
			return nil, errors.New("cosignverify: only ECDSA P-256 keys are in the profile")
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, errors.New("cosignverify: no public key found")
	}
	return keys, nil
}

// Result of a verification. Code is empty when the image passed.
type Result struct {
	Code   string
	Detail string
	// Predicates holds the verified predicate of each required attestation, by predicate type.
	Predicates map[string]json.RawMessage
}

// OK reports whether the image passed.
func (r Result) OK() bool { return r.Code == "" }

// Stats counts cache use.
type Stats struct{ Hits, Misses atomic.Int64 }

// Verifier verifies images. Safe for concurrent use.
type Verifier struct {
	client *ociclient.Client
	policy atomic.Pointer[Policy]
	sem    chan struct{}
	now    func() time.Time

	PositiveTTL, NegativeTTL time.Duration
	Stats                    Stats

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	result  Result
	expires time.Time
}

// New returns a Verifier that makes at most concurrency registry verifications at once.
func New(client *ociclient.Client, policy *Policy, concurrency int) *Verifier {
	if concurrency < 1 {
		concurrency = 1
	}
	v := &Verifier{
		client:      client,
		sem:         make(chan struct{}, concurrency),
		now:         time.Now,
		PositiveTTL: 5 * time.Minute,
		NegativeTTL: 30 * time.Second,
		cache:       map[string]cached{},
	}
	v.SetPolicy(policy)
	return v
}

// SetPolicy replaces the trust policy and empties the cache.
func (v *Verifier) SetPolicy(p *Policy) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.policy.Store(p)
	v.cache = map[string]cached{}
}

// Ref is a parsed digest reference.
type Ref struct{ Registry, Repository, Digest string }

func (r Ref) String() string { return r.Registry + "/" + r.Repository + "@" + r.Digest }

// ParseRef accepts only "host/repository@sha256:<hex>" with an explicit registry host.
func ParseRef(image string) (Ref, bool) {
	name, digest, ok := strings.Cut(image, "@")
	if !ok || !ociclient.ValidDigest(digest) {
		return Ref{}, false
	}
	host, repo, ok := strings.Cut(name, "/")
	explicitHost := strings.ContainsAny(host, ".:") || host == "localhost" // never an implied Docker Hub
	if !ok || repo == "" || strings.Contains(repo, ":") || !explicitHost {
		return Ref{}, false
	}
	return Ref{Registry: host, Repository: repo, Digest: digest}, true
}

func (p *Policy) allows(r Ref) bool {
	name := r.Registry + "/" + r.Repository
	for _, prefix := range p.Repositories {
		if name == prefix || strings.HasPrefix(name, strings.TrimSuffix(prefix, "/")+"/") {
			return true
		}
	}
	return false
}

// VerifyImage runs the profile's checks in order and returns the first failure: digest reference,
// allowed repository (both before any network call), signature, SBOM attestation, mock attestation.
func (v *Verifier) VerifyImage(ctx context.Context, image string) Result {
	ref, ok := ParseRef(image)
	if !ok {
		return Result{Code: CodeNotDigest, Detail: "image must be referenced as host/repository@sha256:<digest>"}
	}
	policy := v.policy.Load()
	if !policy.allows(ref) {
		return Result{Code: CodeRegistryDenied, Detail: ref.Registry + "/" + ref.Repository}
	}
	key := ref.String() + " " + policy.Revision
	if r, ok := v.lookup(key); ok {
		return r
	}
	select {
	case v.sem <- struct{}{}:
		defer func() { <-v.sem }()
	case <-ctx.Done():
		return Result{Code: CodeProviderDown, Detail: "verification capacity exhausted"}
	}
	r := v.verify(ctx, ref, policy)
	v.store(key, policy, r)
	return r
}

func (v *Verifier) lookup(key string) (Result, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	c, ok := v.cache[key]
	if !ok || v.now().After(c.expires) {
		v.Stats.Misses.Add(1)
		return Result{}, false
	}
	v.Stats.Hits.Add(1)
	return c.result, true
}

const maxCacheEntries = 4096

// store caches verdicts; an infrastructure failure is not a verdict and is not cached.
//
// ponytail: at maxCacheEntries the expired entries are swept and, if that frees nothing, the cache is
// emptied; an LRU is the upgrade path if distinct-digest churn ever costs hit rate.
func (v *Verifier) store(key string, policy *Policy, r Result) {
	if r.Code == CodeProviderDown {
		return
	}
	ttl := v.PositiveTTL
	if !r.OK() {
		ttl = v.NegativeTTL
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.policy.Load() != policy {
		return // the policy changed while verifying
	}
	if len(v.cache) >= maxCacheEntries {
		now := v.now()
		for k, c := range v.cache {
			if now.After(c.expires) {
				delete(v.cache, k)
			}
		}
		if len(v.cache) >= maxCacheEntries {
			v.cache = map[string]cached{}
		}
	}
	v.cache[key] = cached{result: r, expires: v.now().Add(ttl)}
}

func (v *Verifier) verify(ctx context.Context, ref Ref, policy *Policy) Result {
	if r := v.verifySignature(ctx, ref, policy); !r.OK() {
		return r
	}
	predicates := map[string]json.RawMessage{}
	for _, want := range []struct{ predicate, missing string }{
		{PredicateSBOM, CodeSBOMMissing},
		{PredicateMock, CodeNoAttestation},
	} {
		p, r := v.verifyAttestation(ctx, ref, policy, want.predicate, want.missing)
		if !r.OK() {
			return r
		}
		predicates[want.predicate] = p
	}
	return Result{Predicates: predicates}
}

func tagFor(digest, suffix string) string { return strings.Replace(digest, ":", "-", 1) + "." + suffix }

// layers fetches the manifest at the cosign tag; a missing tag is "no layers", not an error.
func (v *Verifier) layers(ctx context.Context, ref Ref, suffix string) ([]ociclient.Descriptor, error) {
	m, err := v.client.ManifestByTag(ctx, ref.Registry, ref.Repository, tagFor(ref.Digest, suffix))
	if errors.Is(err, ociclient.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var im ociclient.ImageManifest
	if err := json.Unmarshal(m.Body, &im); err != nil {
		return nil, fmt.Errorf("cosign %s manifest: %w", suffix, err)
	}
	const maxLayers = 16
	if len(im.Layers) > maxLayers {
		im.Layers = im.Layers[:maxLayers]
	}
	return im.Layers, nil
}

func down(err error) Result {
	return Result{Code: CodeProviderDown, Detail: "registry: " + err.Error()}
}

type simpleSigning struct {
	Critical struct {
		Identity struct {
			DockerReference string `json:"docker-reference"`
		} `json:"identity"`
		Image struct {
			DockerManifestDigest string `json:"docker-manifest-digest"`
		} `json:"image"`
		Type string `json:"type"`
	} `json:"critical"`
}

func verifySig(keys []*ecdsa.PublicKey, digest [32]byte, sig []byte) bool {
	for _, k := range keys {
		if ecdsa.VerifyASN1(k, digest[:], sig) {
			return true
		}
	}
	return false
}

func (v *Verifier) verifySignature(ctx context.Context, ref Ref, policy *Policy) Result {
	layers, err := v.layers(ctx, ref, "sig")
	if err != nil {
		return down(err)
	}
	for _, l := range layers {
		if ctx.Err() != nil {
			return down(ctx.Err())
		}
		if l.MediaType != simpleSigningType {
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(l.Annotations[signatureAnnot])
		if err != nil || len(sig) == 0 {
			continue
		}
		payload, err := v.client.Blob(ctx, ref.Registry, ref.Repository, l.Digest)
		if err != nil {
			if errors.Is(err, ociclient.ErrNotFound) || errors.Is(err, ociclient.ErrDigestMismatch) || errors.Is(err, ociclient.ErrTooLarge) {
				continue
			}
			return down(err)
		}
		if !verifySig(policy.Keys, sha256.Sum256(payload), sig) {
			continue
		}
		var ss simpleSigning
		if json.Unmarshal(payload, &ss) != nil {
			continue
		}
		if ss.Critical.Type == cosignSignatureTyp &&
			ss.Critical.Image.DockerManifestDigest == ref.Digest &&
			ss.Critical.Identity.DockerReference == ref.Registry+"/"+ref.Repository {
			return Result{}
		}
	}
	return Result{Code: CodeUnsigned, Detail: "no valid signature by a trusted key for " + ref.String()}
}

type envelope struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
	Signatures  []struct {
		Sig string `json:"sig"`
	} `json:"signatures"`
}

type statement struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	Predicate json.RawMessage `json:"predicate"`
}

// pae is the DSSE pre-authentication encoding.
func pae(payloadType string, payload []byte) []byte {
	return []byte(fmt.Sprintf("DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload))
}

// verifyAttestation finds an attestation of the wanted predicate type that is signed by a trusted
// key and bound to this digest. A layer that claims the type but fails is reported as invalid, so a
// copied or tampered attestation is distinguishable from a missing one.
func (v *Verifier) verifyAttestation(ctx context.Context, ref Ref, policy *Policy, want, missing string) (json.RawMessage, Result) {
	layers, err := v.layers(ctx, ref, "att")
	if err != nil {
		return nil, down(err)
	}
	wantHex := strings.TrimPrefix(ref.Digest, "sha256:")
	claimed := false
	for _, l := range layers {
		if ctx.Err() != nil {
			return nil, down(ctx.Err())
		}
		if l.MediaType != dsseEnvelopeType {
			continue
		}
		if l.Annotations["predicateType"] == want {
			claimed = true
		}
		raw, err := v.client.Blob(ctx, ref.Registry, ref.Repository, l.Digest)
		if err != nil {
			if errors.Is(err, ociclient.ErrNotFound) || errors.Is(err, ociclient.ErrDigestMismatch) || errors.Is(err, ociclient.ErrTooLarge) {
				continue
			}
			return nil, down(err)
		}
		var env envelope
		if json.Unmarshal(raw, &env) != nil {
			continue
		}
		payload, err := base64.StdEncoding.DecodeString(env.Payload)
		if err != nil {
			continue
		}
		var st statement
		if json.Unmarshal(payload, &st) != nil || st.PredicateType != want {
			continue
		}
		claimed = true
		if env.PayloadType != inTotoPayloadType || st.Type != statementType {
			continue
		}
		// The PAE is hashed once, and only the first few signatures are tried, so an envelope padded
		// with signatures costs no more than a short one.
		const maxSignatures = 4
		sigs := env.Signatures
		if len(sigs) > maxSignatures {
			sigs = sigs[:maxSignatures]
		}
		digest := sha256.Sum256(pae(env.PayloadType, payload))
		signed := false
		for _, s := range sigs {
			if sig, err := base64.StdEncoding.DecodeString(s.Sig); err == nil && verifySig(policy.Keys, digest, sig) {
				signed = true
				break
			}
		}
		if !signed {
			continue
		}
		bound := false
		for _, s := range st.Subject {
			if h := s.Digest["sha256"]; len(h) == 64 && strings.EqualFold(h, wantHex) {
				bound = true
			}
		}
		var obj map[string]json.RawMessage
		if bound && json.Unmarshal(st.Predicate, &obj) == nil && obj != nil {
			return st.Predicate, Result{}
		}
	}
	if claimed {
		return nil, Result{Code: CodeAttestationInvalid, Detail: want + " attestation does not verify for " + ref.String()}
	}
	return nil, Result{Code: missing, Detail: "no " + want + " attestation for " + ref.String()}
}
