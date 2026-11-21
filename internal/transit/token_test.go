package transit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeLogin is OpenBao's /v1/auth/<mount>/login: it accepts the JWT "good-<n>" for role "r" and
// answers with token "tok-<login count>" and the given lease; status overrides the answer.
type fakeLogin struct {
	logins atomic.Int32
	status atomic.Int32
	lease  int
	jwts   []string
	mu     sync.Mutex
}

func (f *fakeLogin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var in struct{ Role, JWT string }
	if r.Method != http.MethodPost || r.URL.Path != "/v1/auth/kubernetes/login" ||
		json.NewDecoder(r.Body).Decode(&in) != nil || in.Role != "r" || !strings.HasPrefix(in.JWT, "good-") {
		http.Error(w, `{"errors":["permission denied canary-body"]}`, http.StatusForbidden)
		return
	}
	if s := f.status.Load(); s != 0 {
		http.Error(w, `{"errors":["canary-body"]}`, int(s))
		return
	}
	f.mu.Lock()
	f.jwts = append(f.jwts, in.JWT)
	f.mu.Unlock()
	n := f.logins.Add(1)
	_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{
		"client_token": fmt.Sprintf("tok-%d", n), "lease_duration": f.lease}})
}

func setup(t *testing.T, lease int, jwt string) (*KubernetesAuth, *fakeLogin, string, func(time.Duration)) {
	t.Helper()
	f := &fakeLogin{lease: lease}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	file := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(file, []byte(jwt+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var clock atomic.Int64
	clock.Store(time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC).UnixNano())
	now = func() time.Time { return time.Unix(0, clock.Load()) }
	t.Cleanup(func() { now = time.Now })
	return &KubernetesAuth{Addr: srv.URL, Role: "r", JWTFile: file}, f, file,
		func(d time.Duration) { clock.Add(int64(d)) }
}

// settle waits until no background login runs.
func settle(t *testing.T, k *KubernetesAuth) {
	t.Helper()
	for range 200 {
		k.mu.Lock()
		r := k.refreshing
		k.mu.Unlock()
		if !r {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("background login did not finish")
}

func TestKubernetesAuthCachesAndRenewsAtHalfLease(t *testing.T) {
	k, f, file, advance := setup(t, 60, "good-1")
	ctx := context.Background()
	for range 3 {
		if tok, err := k.Token(ctx); err != nil || tok != "tok-1" {
			t.Fatalf("first token: %q %v", tok, err)
		}
	}
	advance(29 * time.Second)
	if tok, _ := k.Token(ctx); tok != "tok-1" || f.logins.Load() != 1 {
		t.Fatalf("logged in again before half the lease: %q, %d logins", tok, f.logins.Load())
	}
	// The kubelet rotated the projected token: the next login sends the new one.
	if err := os.WriteFile(file, []byte("good-2"), 0o600); err != nil {
		t.Fatal(err)
	}
	advance(time.Second)
	// Due for renewal: the caller still gets the valid token at once, and one background login
	// replaces it.
	if tok, err := k.Token(ctx); err != nil || tok != "tok-1" {
		t.Fatalf("a caller waited for the renewal: %q %v", tok, err)
	}
	settle(t, k)
	if tok, err := k.Token(ctx); err != nil || tok != "tok-2" {
		t.Fatalf("renewal at half the lease: %q %v", tok, err)
	}
	if f.jwts[1] != "good-2" {
		t.Fatalf("renewal did not reread the rotated JWT: %v", f.jwts)
	}
}

func TestKubernetesAuthKeepsValidTokenWhileLoginFailsThenFailsClosed(t *testing.T) {
	k, f, _, advance := setup(t, 60, "good-1")
	ctx := context.Background()
	if _, err := k.Token(ctx); err != nil {
		t.Fatal(err)
	}
	f.status.Store(http.StatusServiceUnavailable)
	advance(40 * time.Second)
	if tok, err := k.Token(ctx); err != nil || tok != "tok-1" {
		t.Fatalf("a valid token was dropped on a failed renewal: %q %v", tok, err)
	}
	settle(t, k)
	if tok, err := k.Token(ctx); err != nil || tok != "tok-1" {
		t.Fatalf("a valid token was dropped after a failed background renewal: %q %v", tok, err)
	}
	settle(t, k)
	advance(15 * time.Second) // 55s: inside the expiry margin
	tok, err := k.Token(ctx)
	if err == nil || tok != "" {
		t.Fatalf("an expiring token was handed out: %q", tok)
	}
	if strings.Contains(err.Error(), "canary") || strings.Contains(err.Error(), "good-") {
		t.Fatalf("error carries the answer or the JWT: %v", err)
	}
	// OpenBao back: the next call logs in again, without a restart.
	f.status.Store(0)
	if tok, err := k.Token(ctx); err != nil || tok != "tok-2" {
		t.Fatalf("re-login after expiry: %q %v", tok, err)
	}
}

func TestKubernetesAuthRefusals(t *testing.T) {
	ctx := context.Background()
	k, _, _, _ := setup(t, 60, "wrong")
	if _, err := k.Token(ctx); err == nil || !strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "canary") {
		t.Fatalf("a refused JWT: %v", err)
	}
	k.JWTFile = filepath.Join(t.TempDir(), "absent")
	if _, err := k.Token(ctx); err == nil {
		t.Fatal("a missing JWT file logged in")
	}
	k, _, _, _ = setup(t, 0, "good-1")
	if _, err := k.Token(ctx); err == nil {
		t.Fatal("a token without a lease was accepted")
	}
	k, _, _, _ = setup(t, 60, "good-1")
	k.Mount = "../sys"
	if _, err := k.Token(ctx); err == nil {
		t.Fatal("an invalid mount was used")
	}
}

func TestKubernetesAuthOneLoginForConcurrentCallers(t *testing.T) {
	k, f, _, _ := setup(t, 60, "good-1")
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() { _, _ = k.Token(context.Background()) })
	}
	wg.Wait()
	if n := f.logins.Load(); n != 1 {
		t.Fatalf("%d logins for concurrent callers", n)
	}
}

// A client whose login fails answers ErrTokenSource, which the services' readiness reports as not
// ready; nothing reaches the transit path without a token.
func TestClientWithFailedLoginIsTokenSourceError(t *testing.T) {
	k, _, _, _ := setup(t, 60, "wrong")
	c, err := New(Config{Addr: k.Addr, Token: k.Token})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.LatestKey(context.Background(), "k"); !errors.Is(err, ErrTokenSource) {
		t.Fatalf("want ErrTokenSource, got %v", err)
	}
}

func TestFileToken(t *testing.T) {
	file := filepath.Join(t.TempDir(), "t")
	src := FileToken(file)
	if _, err := src(context.Background()); err == nil {
		t.Fatal("missing file read")
	}
	_ = os.WriteFile(file, []byte(" a \n"), 0o600)
	if tok, err := src(context.Background()); err != nil || tok != "a" {
		t.Fatalf("%q %v", tok, err)
	}
	_ = os.WriteFile(file, []byte("b"), 0o600)
	if tok, _ := src(context.Background()); tok != "b" {
		t.Fatalf("replaced token not reread: %q", tok)
	}
}
