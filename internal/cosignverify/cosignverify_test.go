package cosignverify

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/ociclient"
)

// registry is an in-memory OCI registry for one repository.
type registry struct {
	mu        sync.Mutex
	manifests map[string][]byte // tag or digest -> body
	blobs     map[string][]byte
	requests  atomic.Int64
	down      atomic.Bool
}

func newRegistry(t *testing.T) (*registry, string) {
	t.Helper()
	reg := &registry{manifests: map[string][]byte{}, blobs: map[string][]byte{}}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reg.requests.Add(1)
		if reg.down.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		reg.mu.Lock()
		defer reg.mu.Unlock()
		parts := strings.Split(r.URL.Path, "/")
		ref := parts[len(parts)-1]
		var body []byte
		switch parts[len(parts)-2] {
		case "manifests":
			body = reg.manifests[ref]
		case "blobs":
			body = reg.blobs[ref]
		}
		if body == nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(ts.Close)
	return reg, strings.TrimPrefix(ts.URL, "http://")
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (r *registry) blob(b []byte) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	d := digest(b)
	r.blobs[d] = b
	return d
}

func (r *registry) manifest(ref string, m any) string {
	b, _ := json.Marshal(m)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.manifests[ref] = b
	r.manifests[digest(b)] = b
	return digest(b)
}

type layer struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int               `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

func imageManifest(layers ...layer) map[string]any {
	return map[string]any{"schemaVersion": 2, "mediaType": ociclient.MediaTypeOCIManifest,
		"config": layer{MediaType: "application/vnd.oci.image.config.v1+json", Digest: digest([]byte("{}")), Size: 2},
		"layers": layers}
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sign(t *testing.T, k *ecdsa.PrivateKey, message []byte) string {
	sum := sha256.Sum256(message)
	sig, err := ecdsa.SignASN1(rand.Reader, k, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

// fixture pushes an image and, by default, a valid signature and both attestations.
type fixture struct {
	t      *testing.T
	reg    *registry
	host   string
	key    *ecdsa.PrivateKey
	repo   string
	digest string
	sigs   []layer
	atts   []layer
}

func newFixture(t *testing.T) *fixture {
	reg, host := newRegistry(t)
	f := &fixture{t: t, reg: reg, host: host, key: newKey(t), repo: "team/app"}
	f.digest = reg.manifest("v1", imageManifest(layer{MediaType: "application/vnd.oci.image.layer.v1.tar", Digest: reg.blob([]byte("rootfs")), Size: 6}))
	return f
}

func (f *fixture) image() string { return f.host + "/" + f.repo + "@" + f.digest }

func (f *fixture) signaturePayload(digest, reference string) []byte {
	return []byte(fmt.Sprintf(`{"critical":{"identity":{"docker-reference":%q},"image":{"docker-manifest-digest":%q},"type":"cosign container image signature"},"optional":null}`, reference, digest))
}

func (f *fixture) addSignature(k *ecdsa.PrivateKey, payload []byte) {
	f.sigs = append(f.sigs, layer{MediaType: simpleSigningType, Digest: f.reg.blob(payload), Size: len(payload),
		Annotations: map[string]string{signatureAnnot: sign(f.t, k, payload)}})
}

func (f *fixture) statement(predicateType, subjectDigest, typ string, predicate string) []byte {
	return []byte(fmt.Sprintf(`{"_type":%q,"predicateType":%q,"subject":[{"name":%q,"digest":{"sha256":%q}}],"predicate":%s}`,
		typ, predicateType, f.host+"/"+f.repo, strings.TrimPrefix(subjectDigest, "sha256:"), predicate))
}

func (f *fixture) addAttestation(k *ecdsa.PrivateKey, predicateType string, stmt []byte) {
	env := map[string]any{"payloadType": inTotoPayloadType, "payload": base64.StdEncoding.EncodeToString(stmt),
		"signatures": []map[string]string{{"keyid": "", "sig": sign(f.t, k, pae(inTotoPayloadType, stmt))}}}
	f.addEnvelope(predicateType, env)
}

func (f *fixture) addEnvelope(predicateType string, env map[string]any) {
	b, _ := json.Marshal(env)
	f.atts = append(f.atts, layer{MediaType: dsseEnvelopeType, Digest: f.reg.blob(b), Size: len(b),
		Annotations: map[string]string{"predicateType": predicateType}})
}

func (f *fixture) valid() *fixture {
	f.addSignature(f.key, f.signaturePayload(f.digest, f.host+"/"+f.repo))
	f.addAttestation(f.key, PredicateSBOM, f.statement(PredicateSBOM, f.digest, statementType, `{"bomFormat":"CycloneDX"}`))
	f.addAttestation(f.key, PredicateMock, f.statement(PredicateMock, f.digest, statementType, `{"mock":true}`))
	return f
}

func (f *fixture) publish() {
	tag := strings.Replace(f.digest, ":", "-", 1)
	if f.sigs != nil {
		f.reg.manifest(tag+".sig", imageManifest(f.sigs...))
	}
	if f.atts != nil {
		f.reg.manifest(tag+".att", imageManifest(f.atts...))
	}
}

func (f *fixture) verifier(keys ...*ecdsa.PublicKey) *Verifier {
	if keys == nil {
		keys = []*ecdsa.PublicKey{&f.key.PublicKey}
	}
	f.publish()
	client := ociclient.New(ociclient.Options{PlainHTTP: []string{f.host}})
	return New(client, &Policy{Repositories: []string{f.host + "/team"}, Keys: keys, Revision: "r1"}, 4)
}

func TestValidImage(t *testing.T) {
	f := newFixture(t).valid()
	r := f.verifier().VerifyImage(context.Background(), f.image())
	if !r.OK() {
		t.Fatalf("valid image refused: %+v", r)
	}
	if string(r.Predicates[PredicateSBOM]) != `{"bomFormat":"CycloneDX"}` || string(r.Predicates[PredicateMock]) != `{"mock":true}` {
		t.Errorf("predicates = %s", r.Predicates)
	}
}

func TestRefusals(t *testing.T) {
	other := "sha256:" + strings.Repeat("ab", 32)
	cases := []struct {
		name  string
		setup func(f *fixture)
		keys  func(f *fixture) []*ecdsa.PublicKey
		want  string
	}{
		{"unsigned", func(f *fixture) {
			f.addAttestation(f.key, PredicateSBOM, f.statement(PredicateSBOM, f.digest, statementType, `{}`))
			f.addAttestation(f.key, PredicateMock, f.statement(PredicateMock, f.digest, statementType, `{}`))
		}, nil, CodeUnsigned},
		{"signed by another key", func(f *fixture) { f.valid() },
			func(f *fixture) []*ecdsa.PublicKey { return []*ecdsa.PublicKey{&newKey(f.t).PublicKey} }, CodeUnsigned},
		{"signature for another digest", func(f *fixture) {
			f.addSignature(f.key, f.signaturePayload(other, f.host+"/"+f.repo))
		}, nil, CodeUnsigned},
		{"signature for another repository", func(f *fixture) {
			f.addSignature(f.key, f.signaturePayload(f.digest, f.host+"/team/other"))
		}, nil, CodeUnsigned},
		{"tampered signature payload", func(f *fixture) {
			f.valid()
			payload := f.signaturePayload(f.digest, f.host+"/"+f.repo)
			f.sigs[0].Annotations[signatureAnnot] = sign(f.t, f.key, append(payload, ' '))
		}, nil, CodeUnsigned},
		{"SBOM attestation missing", func(f *fixture) {
			f.addSignature(f.key, f.signaturePayload(f.digest, f.host+"/"+f.repo))
			f.addAttestation(f.key, PredicateMock, f.statement(PredicateMock, f.digest, statementType, `{}`))
		}, nil, CodeSBOMMissing},
		{"mock attestation missing", func(f *fixture) {
			f.addSignature(f.key, f.signaturePayload(f.digest, f.host+"/"+f.repo))
			f.addAttestation(f.key, PredicateSBOM, f.statement(PredicateSBOM, f.digest, statementType, `{}`))
		}, nil, CodeNoAttestation},
		{"wrong predicate type only", func(f *fixture) {
			f.addSignature(f.key, f.signaturePayload(f.digest, f.host+"/"+f.repo))
			f.addAttestation(f.key, "https://slsa.dev/provenance/v1", f.statement("https://slsa.dev/provenance/v1", f.digest, statementType, `{}`))
		}, nil, CodeSBOMMissing},
		{"attestation copied from another image", func(f *fixture) {
			f.addSignature(f.key, f.signaturePayload(f.digest, f.host+"/"+f.repo))
			f.addAttestation(f.key, PredicateSBOM, f.statement(PredicateSBOM, other, statementType, `{}`))
		}, nil, CodeAttestationInvalid},
		{"attestation signed by another key", func(f *fixture) {
			f.addSignature(f.key, f.signaturePayload(f.digest, f.host+"/"+f.repo))
			f.addAttestation(newKey(f.t), PredicateSBOM, f.statement(PredicateSBOM, f.digest, statementType, `{}`))
		}, nil, CodeAttestationInvalid},
		{"unsigned envelope", func(f *fixture) {
			f.addSignature(f.key, f.signaturePayload(f.digest, f.host+"/"+f.repo))
			stmt := f.statement(PredicateSBOM, f.digest, statementType, `{}`)
			f.addEnvelope(PredicateSBOM, map[string]any{"payloadType": inTotoPayloadType, "payload": base64.StdEncoding.EncodeToString(stmt), "signatures": []any{}})
		}, nil, CodeAttestationInvalid},
		{"tampered envelope", func(f *fixture) {
			f.addSignature(f.key, f.signaturePayload(f.digest, f.host+"/"+f.repo))
			stmt := f.statement(PredicateSBOM, f.digest, statementType, `{}`)
			tampered := f.statement(PredicateSBOM, f.digest, statementType, `{"extra":1}`)
			f.addEnvelope(PredicateSBOM, map[string]any{"payloadType": inTotoPayloadType, "payload": base64.StdEncoding.EncodeToString(tampered),
				"signatures": []map[string]string{{"sig": sign(f.t, f.key, pae(inTotoPayloadType, stmt))}}})
		}, nil, CodeAttestationInvalid},
		{"Statement v1 is out of profile", func(f *fixture) {
			f.addSignature(f.key, f.signaturePayload(f.digest, f.host+"/"+f.repo))
			f.addAttestation(f.key, PredicateSBOM, f.statement(PredicateSBOM, f.digest, "https://in-toto.io/Statement/v1", `{}`))
		}, nil, CodeAttestationInvalid},
		{"malformed predicate", func(f *fixture) {
			f.addSignature(f.key, f.signaturePayload(f.digest, f.host+"/"+f.repo))
			f.addAttestation(f.key, PredicateSBOM, f.statement(PredicateSBOM, f.digest, statementType, `"not an object"`))
		}, nil, CodeAttestationInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			tc.setup(f)
			var keys []*ecdsa.PublicKey
			if tc.keys != nil {
				keys = tc.keys(f)
			}
			if r := f.verifier(keys...).VerifyImage(context.Background(), f.image()); r.Code != tc.want {
				t.Errorf("code = %q (%s), want %q", r.Code, r.Detail, tc.want)
			}
		})
	}
}

func TestReferenceAndAllowListCheckedBeforeNetwork(t *testing.T) {
	f := newFixture(t).valid()
	v := f.verifier()
	for image, want := range map[string]string{
		f.host + "/team/app:v1":                                CodeNotDigest,
		"team/app@" + f.digest:                                 CodeNotDigest,
		f.host + "/team/app:v1@" + f.digest:                    CodeNotDigest,
		f.host + "/elsewhere/app@" + f.digest:                  CodeRegistryDenied,
		f.host + "/teamster/app@" + f.digest:                   CodeRegistryDenied,
		"evil.example/team/app@" + f.digest:                    CodeRegistryDenied,
		"evil.example/" + f.host + "/team/app@" + f.digest:     CodeNotDigest,
		f.host + "/team/app@sha256:" + strings.Repeat("A", 64): CodeNotDigest,
	} {
		if r := v.VerifyImage(context.Background(), image); r.Code != want {
			t.Errorf("%s: code %q, want %q", image, r.Code, want)
		}
	}
	if n := f.reg.requests.Load(); n != 0 {
		t.Errorf("%d registry requests for refused references, want 0", n)
	}
}

func TestCache(t *testing.T) {
	f := newFixture(t).valid()
	v := f.verifier()
	now := time.Now()
	v.now = func() time.Time { return now }
	ctx := context.Background()

	if !v.VerifyImage(ctx, f.image()).OK() {
		t.Fatal("first verification failed")
	}
	before := f.reg.requests.Load()
	if !v.VerifyImage(ctx, f.image()).OK() || f.reg.requests.Load() != before || v.Stats.Hits.Load() != 1 {
		t.Fatalf("second verification not served from cache: requests %d -> %d, hits %d", before, f.reg.requests.Load(), v.Stats.Hits.Load())
	}

	// A new trust policy (the key removed) is never answered from the old cache.
	v.SetPolicy(&Policy{Repositories: []string{f.host + "/team"}, Keys: []*ecdsa.PublicKey{&newKey(t).PublicKey}, Revision: "r2"})
	if r := v.VerifyImage(ctx, f.image()); r.Code != CodeUnsigned {
		t.Errorf("after key removal: %+v, want %s", r, CodeUnsigned)
	}

	// Positive entries expire.
	v.SetPolicy(&Policy{Repositories: []string{f.host + "/team"}, Keys: []*ecdsa.PublicKey{&f.key.PublicKey}, Revision: "r3"})
	v.VerifyImage(ctx, f.image())
	now = now.Add(v.PositiveTTL + time.Second)
	before = f.reg.requests.Load()
	v.VerifyImage(ctx, f.image())
	if f.reg.requests.Load() == before {
		t.Error("expired entry served from cache")
	}
}

func TestCacheBounded(t *testing.T) {
	f := newFixture(t)
	v := f.verifier()
	policy := v.policy.Load()
	for i := 0; i < maxCacheEntries+10; i++ {
		v.store(fmt.Sprintf("k%d", i), policy, Result{Code: CodeUnsigned})
	}
	if n := len(v.cache); n > maxCacheEntries {
		t.Errorf("cache holds %d entries, cap %d", n, maxCacheEntries)
	}
}

func TestSignaturesPerEnvelopeCapped(t *testing.T) {
	// A valid signature placed after the cap is not reached, so padding an envelope with
	// signatures cannot buy extra verification work.
	f := newFixture(t)
	f.addSignature(f.key, f.signaturePayload(f.digest, f.host+"/"+f.repo))
	stmt := f.statement(PredicateSBOM, f.digest, statementType, `{}`)
	sigs := []map[string]string{}
	for i := 0; i < 4; i++ {
		sigs = append(sigs, map[string]string{"sig": "AA=="})
	}
	sigs = append(sigs, map[string]string{"sig": sign(t, f.key, pae(inTotoPayloadType, stmt))})
	f.addEnvelope(PredicateSBOM, map[string]any{"payloadType": inTotoPayloadType,
		"payload": base64.StdEncoding.EncodeToString(stmt), "signatures": sigs})
	if r := f.verifier().VerifyImage(context.Background(), f.image()); r.Code != CodeAttestationInvalid {
		t.Errorf("valid signature past the cap: %+v, want %s", r, CodeAttestationInvalid)
	}
}

func TestRegistryDownFailsClosedAndIsNotCached(t *testing.T) {
	f := newFixture(t).valid()
	v := f.verifier()
	f.reg.down.Store(true)
	if r := v.VerifyImage(context.Background(), f.image()); r.Code != CodeProviderDown {
		t.Fatalf("registry down: %+v, want %s", r, CodeProviderDown)
	}
	f.reg.down.Store(false)
	if r := v.VerifyImage(context.Background(), f.image()); !r.OK() {
		t.Fatalf("after recovery: %+v", r)
	}
}

func TestParsePublicKeys(t *testing.T) {
	k := newKey(t)
	der, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	good := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if keys, err := ParsePublicKeys(good); err != nil || len(keys) != 1 {
		t.Fatalf("P-256 key: %v", err)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der384, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	if _, err := ParsePublicKeys(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der384})); err == nil {
		t.Error("P-384 key accepted")
	}
	if _, err := ParsePublicKeys([]byte("no pem")); err == nil {
		t.Error("empty input accepted")
	}
}
