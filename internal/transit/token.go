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

	mu      sync.Mutex
	client  *http.Client
	token   string
	renewAt time.Time // half the lease: log in again from here on
	expires time.Time // the token is not used from here on
}

// now is the clock; tests move it.
var now = time.Now

// expiryMargin keeps a token from being sent in the last seconds of its lease, so clock skew and a
// slow request do not reach OpenBao with an expired token.
const expiryMargin = 5 * time.Second

// Token is the TokenSource. It logs in when it holds no token or the token is past half its
// lease. A failed login keeps a token that is still within its lease minus expiryMargin, and
// returns the error once there is none: the caller's request fails, and readiness with it.
//
// ponytail: a token OpenBao revokes before its lease ends is used until renewAt; the services'
// readiness and startup report the refusal meanwhile. Add a drop-on-403 hook to Client if
// revocation mid-lease must heal faster than half a lease.
func (k *KubernetesAuth) Token(ctx context.Context) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	t := now()
	if k.token != "" && t.Before(k.renewAt) {
		return k.token, nil
	}
	token, lease, err := k.login(ctx)
	if err != nil {
		if k.token != "" && t.Before(k.expires) {
			return k.token, nil
		}
		k.token = ""
		return "", err
	}
	renew := min(lease/2, lease-expiryMargin)
	k.token, k.renewAt, k.expires = token, t.Add(renew), t.Add(lease-expiryMargin)
	return token, nil
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
	if k.client == nil {
		k.client = safeHTTPClient(k.HTTPClient)
	}
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
