// Package tokenverify validates an RFC 9068 access token bound by DPoP (RFC 9449) at a protected
// resource, against the Connector's published key set, without calling the Connector.
package tokenverify

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/dpopproof"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/replay"
)

// Config configures a Verifier. Every URL is configuration; nothing is taken from the token.
type Config struct {
	Issuer        string   // required iss
	JWKSURL       string   // the Connector's key set
	Audience      string   // must be in aud
	PublicBaseURL string   // htu is this plus the request path; Host and forwarded headers are ignored
	Scopes        []string // all required
	Proof         dpopproof.Policy
	Replay        replay.Store
	CacheTTL      time.Duration // default 5 min
	MaxStale      time.Duration // default 5 min; past it every request is refused
	MinRefresh    time.Duration // default 30 s between refreshes for an unknown kid
	HTTPClient    *http.Client
	Now           func() time.Time
}

// Identity is what a valid request carries into the handler.
type Identity struct {
	ClientID string
	Subject  string // the validated sub claim; the client id for both grants
	JKT      string
	Scopes   []string
	TokenID  string // the token's jti
	Expires  time.Time
}

// Errors, one per refusal; the middleware answers 401 with the matching WWW-Authenticate error,
// 403 for ErrScope and 503 for ErrKeySetUnavailable.
var (
	ErrNoToken           = errors.New("tokenverify: no DPoP token")
	ErrNoProof           = errors.New("tokenverify: no DPoP proof")
	ErrMalformed         = errors.New("tokenverify: malformed token")
	ErrSignature         = errors.New("tokenverify: signature or key not trusted")
	ErrExpired           = errors.New("tokenverify: token expired or not yet valid")
	ErrIssuer            = errors.New("tokenverify: wrong issuer")
	ErrAudience          = errors.New("tokenverify: wrong audience")
	ErrScope             = errors.New("tokenverify: insufficient scope")
	ErrKeyMismatch       = errors.New("tokenverify: proof key does not match cnf.jkt")
	ErrProof             = errors.New("tokenverify: proof invalid")
	ErrReplayed          = errors.New("tokenverify: proof replayed")
	ErrKeySetUnavailable = errors.New("tokenverify: key set stale or unavailable")
)

// RequestVerifier is what a protected service depends on, so it can be built and tested against a fake.
type RequestVerifier interface {
	Verify(r *http.Request) (Identity, error)
	Middleware(next http.Handler) http.Handler
}

// Verifier validates requests. Safe for concurrent use.
type Verifier struct {
	cfg  Config
	keys *keySet
}

var _ RequestVerifier = (*Verifier)(nil)

// New returns a Verifier.
func New(cfg Config) (*Verifier, error) {
	switch {
	case cfg.Issuer == "":
		return nil, errors.New("tokenverify: Issuer is required")
	case cfg.Audience == "":
		return nil, errors.New("tokenverify: Audience is required")
	case cfg.Replay == nil:
		return nil, errors.New("tokenverify: Replay is required")
	}
	if err := absoluteHTTP(cfg.JWKSURL); err != nil {
		return nil, fmt.Errorf("tokenverify: JWKSURL: %w", err)
	}
	if err := absoluteHTTP(cfg.PublicBaseURL); err != nil {
		return nil, fmt.Errorf("tokenverify: PublicBaseURL: %w", err)
	}
	cfg.PublicBaseURL = strings.TrimRight(cfg.PublicBaseURL, "/")
	cfg.CacheTTL = orDefault(cfg.CacheTTL, 5*time.Minute)
	cfg.MaxStale = orDefault(cfg.MaxStale, 5*time.Minute)
	cfg.MinRefresh = orDefault(cfg.MinRefresh, 30*time.Second)
	cfg.Proof.Lifespan = orDefault(cfg.Proof.Lifespan, defaultProofLifespan)
	cfg.Proof.Skew = orDefault(cfg.Proof.Skew, defaultProofSkew)
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	client := http.Client{Timeout: defaultFetchTimeout}
	if cfg.HTTPClient != nil {
		client = *cfg.HTTPClient
	}
	// The key set comes from JWKSURL and nowhere else: redirects are not followed.
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	cfg.HTTPClient = &client
	return &Verifier{cfg: cfg, keys: &keySet{cfg: &cfg}}, nil
}

// Verify validates r and returns the caller's identity.
func (v *Verifier) Verify(r *http.Request) (Identity, error) {
	token, proof, err := credentials(r)
	if err != nil {
		return Identity{}, err
	}
	now := v.cfg.Now()

	_, payload, err := jose.Verify(token, jose.HeaderPolicy{Typ: tokenTyp, KidNeeded: true}, func(h jose.Header) (*ecdsa.PublicKey, error) {
		return v.keys.key(h.Kid, now)
	})
	switch {
	case errors.Is(err, ErrKeySetUnavailable):
		return Identity{}, ErrKeySetUnavailable
	case errors.Is(err, jose.ErrMalformed):
		return Identity{}, ErrMalformed
	case err != nil:
		return Identity{}, ErrSignature
	}

	c, err := v.claims(payload, now)
	if err != nil {
		return Identity{}, err
	}

	// The proof is checked before scope so that only the key holder learns the token's scope is short.
	_, err = dpopproof.Verify(r.Context(), proof, dpopproof.Expect{
		Method:      r.Method,
		URI:         v.cfg.PublicBaseURL + r.URL.EscapedPath(),
		AccessToken: token,
		JKT:         c.jkt,
	}, v.cfg.Proof, now, v.cfg.Replay)
	switch {
	case errors.Is(err, dpopproof.ErrKeyMismatch):
		return Identity{}, ErrKeyMismatch
	case errors.Is(err, dpopproof.ErrReplayed):
		return Identity{}, ErrReplayed
	case errors.Is(err, dpopproof.ErrInvalid), errors.Is(err, dpopproof.ErrMismatch):
		return Identity{}, ErrProof
	case err != nil:
		return Identity{}, errReplayUnavailable
	}

	granted := strings.Fields(c.scope)
	for _, want := range v.cfg.Scopes {
		if !slices.Contains(granted, want) {
			return Identity{}, ErrScope
		}
	}
	return Identity{ClientID: c.clientID, Subject: c.sub, JKT: c.jkt, Scopes: granted, TokenID: c.jti, Expires: c.exp}, nil
}

// Middleware refuses invalid requests and passes valid ones with the Identity in their context.
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := v.Verify(r)
		if err == nil {
			next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), id)))
			return
		}
		status, challenge := refusal(err)
		if challenge != "" {
			w.Header().Set("WWW-Authenticate", challenge)
		}
		w.Header().Set("Cache-Control", "no-store")
		// The body is the status text only: never the token, the proof or the error detail.
		http.Error(w, http.StatusText(status), status)
	})
}

const (
	tokenTyp             = "at+jwt"
	maxCredential        = 8 << 10
	maxKeySetBytes       = 1 << 20
	defaultFetchTimeout  = 10 * time.Second
	defaultProofLifespan = 60 * time.Second
	defaultProofSkew     = 5 * time.Second
)

// errReplayUnavailable is a failed replay check: the request is refused, as a server fault.
var errReplayUnavailable = errors.New("tokenverify: replay check unavailable")

func refusal(err error) (status int, challenge string) {
	const algs = `algs="ES256"`
	switch {
	case errors.Is(err, ErrNoToken):
		return http.StatusUnauthorized, "DPoP " + algs // RFC 6750 3.1: no error code without credentials
	case errors.Is(err, ErrScope):
		return http.StatusForbidden, `DPoP error="insufficient_scope", ` + algs
	case errors.Is(err, ErrNoProof), errors.Is(err, ErrProof), errors.Is(err, ErrReplayed):
		return http.StatusUnauthorized, `DPoP error="invalid_dpop_proof", ` + algs
	case errors.Is(err, ErrMalformed), errors.Is(err, ErrSignature), errors.Is(err, ErrExpired),
		errors.Is(err, ErrIssuer), errors.Is(err, ErrAudience), errors.Is(err, ErrKeyMismatch):
		return http.StatusUnauthorized, `DPoP error="invalid_token", ` + algs
	default: // ErrKeySetUnavailable, a failed replay check
		return http.StatusServiceUnavailable, ""
	}
}

// credentials returns the DPoP access token and the proof, or the refusal.
func credentials(r *http.Request) (token, proof string, err error) {
	auth := r.Header.Values("Authorization")
	switch {
	case len(auth) == 0:
		return "", "", ErrNoToken
	case len(auth) > 1:
		return "", "", ErrMalformed
	}
	scheme, token, _ := strings.Cut(auth[0], " ")
	if !strings.EqualFold(scheme, "DPoP") {
		return "", "", ErrNoToken
	}
	if token == "" || len(token) > maxCredential || strings.ContainsAny(token, " \t,") {
		return "", "", ErrMalformed
	}
	proofs := r.Header.Values("DPoP")
	switch {
	case len(proofs) == 0:
		return "", "", ErrNoProof
	case len(proofs) > 1:
		return "", "", ErrProof
	}
	return token, proofs[0], nil
}

type tokenClaims struct {
	sub, clientID, jti, jkt, scope string
	exp                            time.Time
}

func (v *Verifier) claims(payload []byte, now time.Time) (tokenClaims, error) {
	m, err := jose.ParseObject(payload)
	if err != nil {
		return tokenClaims{}, ErrMalformed
	}
	var c tokenClaims
	if iss, _, _ := jose.String(m, "iss"); iss != v.cfg.Issuer {
		return tokenClaims{}, ErrIssuer
	}
	if !audienceHas(m["aud"], v.cfg.Audience) {
		return tokenClaims{}, ErrAudience
	}
	for _, f := range []struct {
		name string
		dst  *string
	}{{"sub", &c.sub}, {"client_id", &c.clientID}, {"jti", &c.jti}} {
		if *f.dst, _, _ = jose.String(m, f.name); *f.dst == "" {
			return tokenClaims{}, ErrMalformed
		}
	}
	scope, present, ok := jose.String(m, "scope")
	if present && !ok {
		return tokenClaims{}, ErrMalformed
	}
	c.scope = scope

	cnf, err := jose.ParseObject(m["cnf"])
	if err != nil {
		return tokenClaims{}, ErrMalformed
	}
	if c.jkt, _, _ = jose.String(cnf, "jkt"); c.jkt == "" {
		return tokenClaims{}, ErrMalformed
	}

	skew := v.cfg.Proof.Skew
	exp, okExp := numericDate(m, "exp", true)
	iat, okIat := numericDate(m, "iat", true)
	nbf, okNbf := numericDate(m, "nbf", false)
	if !okExp || !okIat || !okNbf {
		return tokenClaims{}, ErrMalformed
	}
	if !now.Before(exp.Add(skew)) || iat.After(now.Add(skew)) || (!nbf.IsZero() && nbf.After(now.Add(skew))) {
		return tokenClaims{}, ErrExpired
	}
	c.exp = exp
	return c, nil
}

// numericDate reads an integer NumericDate; an absent optional claim is the zero time.
func numericDate(m map[string]json.RawMessage, name string, required bool) (time.Time, bool) {
	raw, present := m[name]
	if !present {
		return time.Time{}, !required
	}
	// ponytail: integers only; a fractional NumericDate is refused, the Connector issues integers.
	n, err := strconv.ParseInt(string(bytes.TrimSpace(raw)), 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}, false
	}
	return time.Unix(n, 0), true
}

func audienceHas(raw json.RawMessage, want string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil && len(bytes.TrimSpace(raw)) > 0 && bytes.TrimSpace(raw)[0] == '"' {
		return one == want
	}
	var many []string
	if bytes.HasPrefix(bytes.TrimSpace(raw), []byte("[")) && json.Unmarshal(raw, &many) == nil {
		return slices.Contains(many, want)
	}
	return false
}

func absoluteHTTP(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("must be an absolute http(s) URL without query or fragment")
	}
	return nil
}

func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

type ctxKey struct{}

// WithIdentity returns ctx carrying id; FromContext reads it back.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// FromContext returns the identity a Middleware put in ctx.
func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(Identity)
	return id, ok
}
