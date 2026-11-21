package tsabundle

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const policyDir = "../../policies/tsa/facis/guard/1.0"

var coords = Coordinates{Repository: "policies", Group: "facis", Name: "guard", Version: "1.0"}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// sign signs as `cosign sign-blob` does: ECDSA over the SHA-256 of the signing input.
func sign(t *testing.T, k *ecdsa.PrivateKey, innerZip []byte) []byte {
	t.Helper()
	d := sha256.Sum256(SigningInput(innerZip))
	sig, err := ecdsa.SignASN1(rand.Reader, k, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func bundle(t *testing.T, k *ecdsa.PrivateKey, revision string) []byte {
	t.Helper()
	innerZip, err := Pack(policyDir, "", coords, revision, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	outer, err := Seal(innerZip, sign(t, k, innerZip), &k.PublicKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return outer
}

// rebuild re-packs a bundle's inner zip through edit, keeping the original signature.
func rebuild(t *testing.T, outer []byte, edit func([]file) []file) []byte {
	t.Helper()
	files, err := unzip(outer)
	if err != nil {
		t.Fatal(err)
	}
	parts, err := unzip(files[0].body)
	if err != nil {
		t.Fatal(err)
	}
	var entries [][2]string
	for _, p := range edit(parts) {
		entries = append(entries, [2]string{p.name, string(p.body)})
	}
	innerZip, _ := zipOf(entries, time.Now())
	out, _ := zipOf([][2]string{{inner, string(innerZip)}, {signature, string(files[1].body)}}, time.Now())
	return out
}

func TestOpenAcceptsOnlyWhatTheTrustRootSigned(t *testing.T) {
	trusted, other := newKey(t), newKey(t)
	good := bundle(t, trusted, "v1")
	expect := Expect{Key: &trusted.PublicKey, Coordinates: coords, Revision: "v1"}
	if err := Open(good, expect); err != nil {
		t.Fatalf("signed bundle refused: %v", err)
	}
	resign := func(b []byte) []byte { // a validly signed bundle with altered content
		files, _ := unzip(b)
		out, _ := Seal(files[0].body, sign(t, trusted, files[0].body), &trusted.PublicKey, time.Now())
		return out
	}
	withMeta := func(edit func(*metadata)) []byte {
		return resign(rebuild(t, good, func(ps []file) []file {
			var m metadata
			_ = json.Unmarshal(ps[0].body, &m)
			edit(&m)
			ps[0].body, _ = json.Marshal(m)
			return ps
		}))
	}
	for name, c := range map[string]struct {
		outer  []byte
		expect Expect
	}{
		"other key":         {bundle(t, other, "v1"), expect},
		"declared revision": {good, Expect{Key: &trusted.PublicKey, Coordinates: coords, Revision: "v2"}},
		"other policy":      {good, Expect{Key: &trusted.PublicKey, Coordinates: Coordinates{"policies", "facis", "guard", "2.0"}, Revision: "v1"}},
		"tampered policy": {rebuild(t, good, func(ps []file) []file {
			ps[1].body = []byte("package facis.guard\ndecision := {\"allow\": true}\n")
			return ps
		}), expect},
		"foreign key URL": {withMeta(func(m *metadata) { m.PublicKeyURL = "https://attacker.invalid/key.json" }), expect},
		"locked":          {withMeta(func(m *metadata) { m.Policy.Locked = true }), expect},
		"external data": {resign(rebuild(t, good, func(ps []file) []file {
			return append(ps, file{"data-config.json", []byte(`{"url":"https://attacker.invalid"}`)})
		})), expect},
		"metadata not first": {resign(rebuild(t, good, func(ps []file) []file { return []file{ps[1], ps[0], ps[2]} })), expect},
		"unsigned": {func() []byte {
			f, _ := unzip(good)
			o, _ := zipOf([][2]string{{inner, string(f[0].body)}}, time.Now())
			return o
		}(), expect},
		"not a zip": {[]byte("PK\x03\x04 nonsense"), expect},
	} {
		t.Run(name, func(t *testing.T) {
			if err := Open(c.outer, c.expect); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestPackRefusesAPresetRevision(t *testing.T) {
	dir := t.TempDir()
	data := dir + "/data.json"
	if err := os.WriteFile(data, []byte(`{"bundle":{"revision":"forged"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Pack(policyDir, data, coords, "v1", time.Now()); err == nil {
		t.Fatal("publisher revision overridable from data")
	}
}

// fakeTSA imports what it is given and evaluates like the policy does: the revision is
// data.bundle.revision, unless the Rego writes a literal bundle_revision of its own.
type fakeTSA struct {
	mu       sync.Mutex
	revision string
	imports  int
}

var literalRevision = regexp.MustCompile(`"bundle_revision": "([^"]+)"`)

func (f *fakeTSA) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/v1/policy/import":
		body, _ := io.ReadAll(r.Body)
		files, _ := unzip(body)
		parts, _ := unzip(files[0].body)
		var data struct{ Bundle struct{ Revision string } }
		_ = json.Unmarshal(parts[2].body, &data)
		f.revision, f.imports = data.Bundle.Revision, f.imports+1
		if m := literalRevision.FindSubmatch(parts[1].body); m != nil {
			f.revision = string(m[1])
		}
	case coords.EvaluationPath():
		if f.revision == "" {
			http.Error(w, "policy not found", http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, `{"decision":{"bundle_revision":"`+f.revision+`"}}`)
	}
}

// lying is a correctly signed bundle whose data says revision but whose Rego reports claims.
func lying(t *testing.T, k *ecdsa.PrivateKey, revision, claims string) []byte {
	t.Helper()
	dir := t.TempDir()
	rego, _ := os.ReadFile(policyDir + "/policy.rego")
	rego = []byte(strings.ReplaceAll(string(rego), `"bundle_revision": revision`, `"bundle_revision": "`+claims+`"`))
	if !strings.Contains(string(rego), `"bundle_revision": "`+claims+`"`) {
		t.Fatal("the policy no longer takes its revision from data; update the lying candidate")
	}
	data, _ := os.ReadFile(policyDir + "/data.json")
	if err := os.WriteFile(dir+"/policy.rego", rego, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/data.json", data, 0o600); err != nil {
		t.Fatal(err)
	}
	innerZip, err := Pack(dir, "", coords, revision, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	outer, err := Seal(innerZip, sign(t, k, innerZip), &k.PublicKey, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return outer
}

func TestSyncerActivatesVerifiedBundlesOnlyAndRollsBack(t *testing.T) {
	trusted, other := newKey(t), newKey(t)
	store := map[string][]byte{"v1": bundle(t, trusted, "v1"), "v1-resigned": bundle(t, trusted, "v1"), "v2": bundle(t, trusted, "v2"),
		"forged": bundle(t, other, "v3"), "lying": lying(t, trusted, "v3", "v2")}
	tsa := &fakeTSA{}
	srv := httptest.NewServer(tsa)
	defer srv.Close()
	s := &Syncer{TSA: srv.URL, Policy: coords, Key: &trusted.PublicKey, HTTP: srv.Client(), Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Fetch: func(_ context.Context, ref string) ([]byte, error) {
			if b, ok := store[ref]; ok {
				return b, nil
			}
			return nil, errors.New("not found")
		}}
	ctx := context.Background()
	step := func(d Desired, wantErr bool, want, wantRef string) {
		t.Helper()
		if err := s.Reconcile(ctx, d); (err != nil) != wantErr {
			t.Fatalf("%v: error %v", d, err)
		}
		if s.Active() != want || tsa.revision != want || s.ref != wantRef {
			t.Fatalf("%v: active %q (%s), tsa %q, want %q (%s)", d, s.Active(), s.ref, tsa.revision, want, wantRef)
		}
	}
	step(Desired{"v1", "v1"}, false, "v1", "v1")
	imports := tsa.imports
	step(Desired{"v1-resigned", "v1"}, false, "v1", "v1-resigned") // same revision, another digest: re-activated
	if tsa.imports != imports+1 {
		t.Fatal("a changed reference with the same revision was not imported")
	}
	step(Desired{"v2", "v2"}, false, "v2", "v2")
	step(Desired{"forged", "v3"}, true, "v2", "v2")  // signed by another key: refused before import
	step(Desired{"v1", "v5"}, true, "v2", "v2")      // a bundle that is not the declared revision
	step(Desired{"missing", "v4"}, true, "v2", "v2") // registry failure
	// Signed, data says v3, Rego answers v2: imported, found wrong, and the previous bundle restored.
	imports = tsa.imports
	step(Desired{"lying", "v3"}, true, "v2", "v2")
	if tsa.imports != imports+2 {
		t.Fatalf("lying candidate: %d imports, want the candidate and the restore", tsa.imports-imports)
	}
	if !bytes.Equal(s.last, store["v2"]) {
		t.Fatal("the cached bundle is not the last verified one")
	}
	step(Desired{"v1", "v1"}, false, "v1", "v1") // rollback
	imports = tsa.imports
	step(Desired{"v1", "v1"}, false, "v1", "v1") // already active: no import
	if tsa.imports != imports {
		t.Fatal("an active pair was imported again")
	}
	tsa.revision = ""                               // the TSA restarted empty
	step(Desired{"forged", "v3"}, true, "v1", "v1") // restored from the cache even while the declaration is refused
	if strings.Contains(string(JWKS(&trusted.PublicKey)), "\"d\"") {
		t.Fatal("JWKS carries private material")
	}
}
