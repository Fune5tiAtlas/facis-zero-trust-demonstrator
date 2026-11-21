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

// Syncer keeps the TSA on the desired bundle.
//
// Each revision is imported under its own TSA key (Coordinates.At), next to the active one, and
// becomes active only when an evaluation under that key answers with that revision; activation is
// then the switch of the key the sidecar forwards evaluations to, an atomic step of its own. The
// TSA's own replace-in-place is avoided on purpose: in v1.1.4 it drops its policy cache through a
// notification that is lost when the import request ends first, so a replaced policy can keep
// answering indefinitely. A candidate that is refused, before or after import, is never switched to,
// so the previous bundle keeps serving throughout.
type Syncer struct {
	TSA    string // TSA base URL, pod-local
	Policy Coordinates
	Key    *ecdsa.PublicKey
	// Fetch returns the outer bundle of a digest reference, after the registry-side checks.
	Fetch func(ctx context.Context, ref string) ([]byte, error)
	HTTP  *http.Client
	Log   *slog.Logger

	active   atomic.Pointer[activeBundle] // what evaluations are forwarded to; nil when nothing is
	last     *activeBundle                // the last activated bundle, kept to re-import after a TSA restart
	misses   int                          // consecutive unanswered probes of the active revision
	failed   Desired                      // the last declaration that failed after import, and when
	failedAt time.Time
	imported map[string]string // revision -> reference of every bundle imported
}

type activeBundle struct {
	ref, revision string
	outer         []byte
}

// lostAfter is how many consecutive unanswered probes count as a TSA that lost its policies (it
// starts empty after a restart). A single slow evaluation is not.
const lostAfter = 3

// ActivationWindow bounds the wait for an imported revision to answer.
var ActivationWindow = 30 * time.Second

// RetryFailedAfter is how long a declaration that failed after import is left alone.
var RetryFailedAfter = 5 * time.Minute

// Active is the revision evaluations are forwarded to, "" when none.
func (s *Syncer) Active() string {
	if a := s.active.Load(); a != nil {
		return a.revision
	}
	return ""
}

// EvaluationPath is the TSA path of the active revision, "" when none.
func (s *Syncer) EvaluationPath() string {
	if a := s.active.Load(); a != nil {
		return s.Policy.At(a.revision).EvaluationPath()
	}
	return ""
}

// Probe evaluates an empty input under revision's key: the policy denies it, naming the revision it
// evaluated with. ok is false when the TSA gave no decision.
func (s *Syncer) Probe(ctx context.Context, revision string) (answered string, ok bool) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	d, err := Evaluate(ctx, s.HTTP, s.TSA+s.Policy.At(revision).EvaluationPath(), []byte("{}"))
	if err != nil {
		return "", false
	}
	return d.BundleRevision, true
}

// load imports a verified bundle under its revision's key and waits until that key answers with
// the revision.
func (s *Syncer) load(ctx context.Context, outer []byte, revision string) error {
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
	got := ""
	for deadline := time.Now().Add(ActivationWindow); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		var ok bool
		if got, ok = s.Probe(ctx, revision); ok {
			break
		}
	}
	if got != revision {
		return fmt.Errorf("imported bundle evaluates as revision %q, not %q", got, revision)
	}
	return nil
}

// Reconcile makes the declared reference and revision the active pair.
func (s *Syncer) Reconcile(ctx context.Context, d Desired) error {
	// The active revision must still answer; a restarted TSA is empty: re-import it from the cache.
	if s.last != nil {
		got, ok := s.Probe(ctx, s.last.revision)
		switch {
		case ok && got == s.last.revision:
			s.misses = 0
			s.active.Store(s.last)
		case !ok:
			s.misses++
		}
		if s.misses >= lostAfter || (ok && got != s.last.revision) {
			s.active.Store(nil)
			s.misses = 0
			if err := s.load(ctx, s.last.outer, s.last.revision); err != nil {
				s.Log.Error("active bundle not restored", "bundle", s.last.ref, "revision", s.last.revision, "reason", err.Error())
			} else {
				s.active.Store(s.last)
				s.Log.Info("active bundle restored", "bundle", s.last.ref, "revision", s.last.revision)
			}
		}
	}
	if s.last != nil && d.Bundle == s.last.ref && d.Revision == s.last.revision {
		return nil
	}
	refuse := func(err error) error {
		s.Log.Error("bundle refused", "bundle", d.Bundle, "revision", d.Revision, "active_revision", s.Active(), "reason", err.Error())
		return err
	}
	if d.Bundle == "" || d.Revision == "" {
		return refuse(errors.New("desired bundle and revision are required"))
	}
	// A revision names one bundle: its key in the TSA is taken, and decisions only carry the revision.
	if ref, ok := s.imported[d.Revision]; ok && ref != d.Bundle {
		return refuse(fmt.Errorf("revision %s was imported as %s; a revision is never reused for another bundle", d.Revision, ref))
	}
	if d == s.failed && time.Since(s.failedAt) < RetryFailedAfter {
		return refuse(fmt.Errorf("failed after import at %s; not retried before %s", s.failedAt.UTC().Format(time.RFC3339), s.failedAt.Add(RetryFailedAfter).UTC().Format(time.RFC3339)))
	}
	outer, err := s.Fetch(ctx, d.Bundle)
	if err != nil {
		return refuse(err)
	}
	if err := Open(outer, Expect{Key: s.Key, Coordinates: s.Policy, Revision: d.Revision}); err != nil {
		return refuse(err)
	}
	if s.imported == nil {
		s.imported = map[string]string{}
	}
	s.imported[d.Revision] = d.Bundle
	if err := s.load(ctx, outer, d.Revision); err != nil {
		s.failed, s.failedAt = d, time.Now()
		return refuse(err)
	}
	previous := s.Active()
	s.last = &activeBundle{ref: d.Bundle, revision: d.Revision, outer: outer}
	s.active.Store(s.last)
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
