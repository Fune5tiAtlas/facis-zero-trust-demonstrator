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

// Syncer keeps the TSA on the desired bundle. Nothing reaches the TSA's import before Open accepted
// it, so a refused bundle leaves the previous one active.
type Syncer struct {
	TSA    string // TSA base URL, pod-local
	Policy Coordinates
	Key    *ecdsa.PublicKey
	// Fetch returns the outer bundle of a digest reference, after the registry-side checks.
	Fetch  func(ctx context.Context, ref string) ([]byte, error)
	HTTP   *http.Client
	Log    *slog.Logger
	active atomic.Value // string: the revision the TSA evaluates with, "" when none
}

// Active is the revision the TSA last evaluated with ("" when it evaluates none).
func (s *Syncer) Active() string { v, _ := s.active.Load().(string); return v }

// Probe evaluates an empty input: the policy denies it, naming the revision it evaluated with. This
// reads the revision the TSA actually uses, so a TSA restart (which empties it) is noticed.
func (s *Syncer) Probe(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	d, err := Evaluate(ctx, s.HTTP, s.TSA+s.Policy.EvaluationPath(), []byte("{}"))
	if err != nil {
		return ""
	}
	return d.BundleRevision
}

// Reconcile imports the desired bundle when the TSA does not already evaluate its revision.
func (s *Syncer) Reconcile(ctx context.Context, d Desired) error {
	previous := s.Probe(ctx)
	s.active.Store(previous)
	if d.Revision != "" && previous == d.Revision {
		return nil
	}
	refuse := func(err error) error {
		s.Log.Error("bundle refused", "bundle", d.Bundle, "revision", d.Revision, "active_revision", previous, "reason", err.Error())
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
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, s.TSA+"/v1/policy/import", bytes.NewReader(outer))
	req.Header.Set("Content-Type", "application/zip")
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return refuse(fmt.Errorf("tsa import: %w", err))
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return refuse(fmt.Errorf("tsa import: %d %s", resp.StatusCode, strings.TrimSpace(string(body))))
	}
	// The TSA swaps the policy under a lock and drops its compiled query asynchronously; the bundle
	// counts as active once an evaluation reports its revision.
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if s.Probe(ctx) == d.Revision {
			s.active.Store(d.Revision)
			s.Log.Info("bundle activated", "bundle", d.Bundle, "revision", d.Revision, "previous_revision", previous)
			return nil
		}
	}
	return refuse(errors.New("imported bundle did not become active"))
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
