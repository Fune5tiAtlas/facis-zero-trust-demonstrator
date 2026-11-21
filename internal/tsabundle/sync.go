package tsabundle

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/cosignverify"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/ociclient"
)

// Desired is the bundle Git declares active: a digest reference and the revision it must carry.
type Desired struct {
	Bundle   string `json:"bundle"`
	Revision string `json:"revision"`
}

// Syncer keeps the TSA on the desired bundle. Activation is transactional: nothing reaches the TSA's
// import before Open accepted it; evaluations are not forwarded while a bundle is being swapped; a
// bundle counts as active only once an evaluation reports its revision; and a candidate that does
// not is replaced by the last verified bundle, which the Syncer keeps for that purpose.
type Syncer struct {
	TSA    string // TSA base URL, pod-local
	Policy Coordinates
	Key    *ecdsa.PublicKey
	// Fetch returns the outer bundle of a digest reference, after the registry-side checks.
	Fetch func(ctx context.Context, ref string) ([]byte, error)
	HTTP  *http.Client
	Log   *slog.Logger

	serving atomic.Bool // the TSA evaluates the last verified bundle; evaluations may be forwarded
	last    []byte      // the last verified and activated bundle, its reference and revision
	ref     string
	rev     atomic.Value // string
	misses  int          // consecutive probes without an answer

	// InFlight counts evaluations being forwarded to the TSA; the gate keeps it.
	InFlight atomic.Int64
}

// ActivationWindow bounds the wait for an imported bundle to answer with its revision: the TSA
// recompiles the policy on every evaluation, which a loaded node makes slow.
var ActivationWindow = 30 * time.Second

// lostAfter is how many consecutive unanswered probes count as a TSA that lost its policy. A single
// slow or failed evaluation is not: restoring on it would make the pod flap under load.
const lostAfter = 3

// Active is the revision evaluations are served under, "" while none is (startup, a swap, a TSA
// that lost its policy).
func (s *Syncer) Active() string {
	if !s.serving.Load() {
		return ""
	}
	v, _ := s.rev.Load().(string)
	return v
}

func (s *Syncer) revision() string { v, _ := s.rev.Load().(string); return v }

// Probe evaluates an empty input: the policy denies it, naming the revision it evaluated with. This
// reads the revision the TSA actually uses, so a TSA restart (which empties it) is noticed. ok is
// false when the TSA gave no decision at all.
func (s *Syncer) Probe(ctx context.Context) (revision string, ok bool) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	d, err := Evaluate(ctx, s.HTTP, s.TSA+s.Policy.EvaluationPath(), []byte("{}"))
	if err != nil {
		return "", false
	}
	return d.BundleRevision, true
}

// load imports a verified bundle and waits until an evaluation reports its revision.
//
// The TSA replaces the policy under a lock but drops its policy cache asynchronously, and an
// evaluation that read the old policy before the swap can put it back into the cache afterwards,
// where it stays until the next change. So load first waits for the evaluations it forwarded to
// finish (the caller has stopped forwarding new ones), and imports again whenever the old revision is
// still answering after reimportAfter: each import drops the cache again.
func (s *Syncer) load(ctx context.Context, outer []byte, revision string) error {
	for deadline := time.Now().Add(10 * time.Second); s.InFlight.Load() > 0 && time.Now().Before(deadline); {
		time.Sleep(50 * time.Millisecond)
	}
	got := ""
	for deadline := time.Now().Add(ActivationWindow); time.Now().Before(deadline); {
		if err := s.importBundle(ctx, outer); err != nil {
			return err
		}
		for retry := time.Now().Add(reimportAfter); time.Now().Before(retry); time.Sleep(200 * time.Millisecond) {
			if got, _ = s.Probe(ctx); got == revision {
				return nil
			}
		}
	}
	return fmt.Errorf("imported bundle evaluates as revision %q, not %q", got, revision)
}

// reimportAfter is how long the previous revision may keep answering before load imports again.
var reimportAfter = 5 * time.Second

func (s *Syncer) importBundle(ctx context.Context, outer []byte) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, s.TSA+"/v1/policy/import", bytes.NewReader(outer))
	req.Header.Set("Content-Type", "application/zip")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("tsa import: %w", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("tsa import: %d %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// restore puts the last verified bundle back, or leaves nothing served if there is none or it fails.
func (s *Syncer) restore(ctx context.Context) {
	if s.last == nil {
		return
	}
	if err := s.load(ctx, s.last, s.revision()); err != nil {
		s.Log.Error("previous bundle not restored", "bundle", s.ref, "revision", s.revision(), "reason", err.Error())
		return
	}
	s.serving.Store(true)
	s.Log.Info("previous bundle restored", "bundle", s.ref, "revision", s.revision())
}

// Reconcile makes the declared reference and revision the active pair.
func (s *Syncer) Reconcile(ctx context.Context, d Desired) error {
	// The TSA must still evaluate the last verified bundle: a different revision is restored at once,
	// no answer only after lostAfter polls in a row (a restarted TSA is empty and keeps failing).
	got, ok := s.Probe(ctx)
	if ok {
		s.misses = 0
	} else {
		s.misses++
	}
	if s.last == nil || (ok && got != s.revision()) || s.misses >= lostAfter {
		s.serving.Store(false)
		s.misses = 0
		s.restore(ctx)
	}
	if s.serving.Load() && d.Bundle == s.ref && d.Revision == s.revision() {
		return nil
	}
	refuse := func(err error) error {
		s.Log.Error("bundle refused", "bundle", d.Bundle, "revision", d.Revision, "active_bundle", s.ref, "active_revision", s.Active(), "reason", err.Error())
		return err
	}
	if d.Bundle == "" || d.Revision == "" {
		return refuse(errors.New("desired bundle and revision are required"))
	}
	outer, err := s.Fetch(ctx, d.Bundle)
	if err != nil {
		return refuse(err)
	}
	if err := Open(outer, Expect{Key: s.Key, Coordinates: s.Policy, Revision: d.Revision}); err != nil {
		return refuse(err)
	}
	previous := s.Active()
	s.serving.Store(false)
	if err := s.load(ctx, outer, d.Revision); err != nil {
		s.restore(ctx)
		return refuse(err)
	}
	s.last, s.ref = outer, d.Bundle
	s.rev.Store(d.Revision)
	s.serving.Store(true)
	s.Log.Info("bundle activated", "bundle", d.Bundle, "revision", d.Revision, "previous_revision", previous)
	return nil
}

// Decision is the part of an IF-05 decision the probe reads.
type Decision struct {
	BundleRevision string `json:"bundle_revision"`
}

// EvaluateRaw posts input to a TSA evaluation URL and returns the policy's "decision" member, raw.
func EvaluateRaw(ctx context.Context, client *http.Client, url string, input []byte) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(input))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("tsa unavailable")
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10+1))
	if err != nil || len(raw) > 64<<10 {
		return nil, errors.New("tsa response unreadable")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tsa status %d", resp.StatusCode)
	}
	var result struct {
		Decision json.RawMessage `json:"decision"`
	}
	if json.Unmarshal(raw, &result) != nil || len(result.Decision) == 0 {
		return nil, errors.New("tsa result has no decision")
	}
	return result.Decision, nil
}

// Evaluate is EvaluateRaw decoded into the revision the probe needs.
func Evaluate(ctx context.Context, client *http.Client, url string, input []byte) (Decision, error) {
	raw, err := EvaluateRaw(ctx, client, url, input)
	if err != nil {
		return Decision{}, err
	}
	var d Decision
	err = json.Unmarshal(raw, &d)
	return d, err
}

// RegistryFetch verifies a bundle's cosign signature by the trust root and returns its single layer.
func RegistryFetch(client *ociclient.Client, key *ecdsa.PublicKey, repository string) func(context.Context, string) ([]byte, error) {
	return func(ctx context.Context, image string) ([]byte, error) {
		ref, ok := cosignverify.ParseRef(image)
		if !ok {
			return nil, errors.New("bundle must be referenced as host/repository@sha256:<digest>")
		}
		name := ref.Registry + "/" + ref.Repository
		if name != repository && !strings.HasPrefix(name, strings.TrimSuffix(repository, "/")+"/") {
			return nil, errors.New("bundle repository is not the configured one")
		}
		if r := cosignverify.VerifySignature(ctx, client, ref, []*ecdsa.PublicKey{key}); !r.OK() {
			return nil, fmt.Errorf("%s: %s", r.Code, r.Detail)
		}
		m, err := client.ManifestByDigest(ctx, ref.Registry, ref.Repository, ref.Digest)
		if err != nil {
			return nil, err
		}
		var im ociclient.ImageManifest
		if json.Unmarshal(m.Body, &im) != nil || len(im.Layers) != 1 || im.Layers[0].MediaType != MediaType || im.Layers[0].Size > maxBundle {
			return nil, errors.New("artefact is not a single TSA bundle layer")
		}
		return client.Blob(ctx, ref.Registry, ref.Repository, im.Layers[0].Digest)
	}
}
