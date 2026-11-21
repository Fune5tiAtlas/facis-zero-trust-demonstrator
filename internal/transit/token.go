package transit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// FileToken reads the token from path on every call, so a token replaced in the file is used at
// the next call without a restart.
func FileToken(path string) TokenSource {
	return func(context.Context) (string, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
}

// KubernetesAuth logs in to OpenBao's Kubernetes auth method with a projected service-account
// token (audience-bound, rotated by the kubelet) and hands out the client token it gets back.
type KubernetesAuth struct {
	Addr    string // scheme://host[:port], as Config.Addr
	Mount   string // the auth mount, default "kubernetes"
	Role    string
	JWTFile string // read at every login, so the kubelet's rotation is picked up
	// HTTPClient carries the login; nil is a client without a proxy that never follows a redirect.
	HTTPClient *http.Client

	mu         sync.Mutex // guards the fields below
	token      string
	renewAt    time.Time  // half the lease: log in again, in the background, from here on
	expires    time.Time  // the token is not used from here on
	refreshing bool       // a background login is running
	logging    sync.Mutex // one blocking login at a time
	clientOnce sync.Once
	client     *http.Client
}

// now is the clock; tests move it.
var now = time.Now

// expiryMargin keeps a token from being sent in the last seconds of its lease, so clock skew and a
// slow request do not reach OpenBao with an expired token.
const expiryMargin = 5 * time.Second

// refreshTimeout bounds a background login, which no caller's deadline covers.
const refreshTimeout = 30 * time.Second

// Token is the TokenSource. With no usable token it logs in, in the caller's context, and fails
// the call when the login fails: the caller's request fails, and readiness with it. A token past
// half its lease is still handed out while one background login replaces it, so a slow login never
// eats a caller's budget (a readiness probe's above all); a background login that fails is tried
// again by the next call, and the token is used until expiryMargin before its lease ends.
//
// ponytail: a token OpenBao revokes before its lease ends is used until renewAt; the services'
// readiness and startup report the refusal meanwhile. Add a drop-on-403 hook to Client if
// revocation mid-lease must heal faster than half a lease.
func (k *KubernetesAuth) Token(ctx context.Context) (string, error) {
	if tok, ok := k.cached(); ok {
		return tok, nil
	}
	k.logging.Lock()
	defer k.logging.Unlock()
	if tok, ok := k.cached(); ok { // another caller logged in meanwhile
		return tok, nil
	}
	t := now()
	token, lease, err := k.login(ctx)
	if err != nil {
		return "", err
	}
	k.store(t, token, lease)
	return token, nil
}

// cached hands out a token within its lease and starts the background login once it is due.
func (k *KubernetesAuth) cached() (string, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	t := now()
	if k.token == "" || !t.Before(k.expires) {
		return "", false
	}
	if !t.Before(k.renewAt) && !k.refreshing {
		k.refreshing = true
		go k.refresh()
	}
	return k.token, true
}

func (k *KubernetesAuth) refresh() {
	ctx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
	defer cancel()
	t := now()
	token, lease, err := k.login(ctx)
	if err == nil {
		k.store(t, token, lease)
	}
	k.mu.Lock()
	k.refreshing = false
	k.mu.Unlock()
}

func (k *KubernetesAuth) store(t time.Time, token string, lease time.Duration) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.token, k.renewAt, k.expires = token, t.Add(min(lease/2, lease-expiryMargin)), t.Add(lease-expiryMargin)
}

// login answers only what it needs: the token and its lease. Errors carry the HTTP status at
// most, never the JWT, the answer's text or the token.
func (k *KubernetesAuth) login(ctx context.Context) (string, time.Duration, error) {
	jwt, err := os.ReadFile(k.JWTFile)
	if err != nil {
		return "", 0, errors.New("kubernetes auth: service-account token unreadable")
	}
	mount := k.Mount
	if mount == "" {
		mount = "kubernetes"
	}
	if validMount(mount) != nil || k.Role == "" {
		return "", 0, errors.New("kubernetes auth: invalid mount or no role")
	}
	body, _ := json.Marshal(map[string]string{"role": k.Role, "jwt": strings.TrimSpace(string(jwt))})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimSuffix(k.Addr, "/")+"/v1/auth/"+mount+"/login", bytes.NewReader(body))
	if err != nil {
		return "", 0, errors.New("kubernetes auth: building request")
	}
	req.Header.Set("Content-Type", "application/json")
	k.clientOnce.Do(func() { k.client = safeHTTPClient(k.HTTPClient) })
	resp, err := k.client.Do(req)
	if err != nil {
		return "", 0, errors.New("kubernetes auth: request failed")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("kubernetes auth: login status %d", resp.StatusCode)
	}
	var out struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int64  `json:"lease_duration"`
		} `json:"auth"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&out) != nil ||
		out.Auth.ClientToken == "" || out.Auth.LeaseDuration <= 0 {
		return "", 0, errors.New("kubernetes auth: malformed login answer")
	}
	return out.Auth.ClientToken, time.Duration(out.Auth.LeaseDuration) * time.Second, nil
}
