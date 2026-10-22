// Package tokenverify validates an RFC 9068 access token bound by DPoP (RFC 9449) at a protected
// resource, against the Connector's published key set, without calling the Connector.
package tokenverify

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/dpopproof"
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
type Verifier struct{ cfg Config }

var _ RequestVerifier = (*Verifier)(nil)

// New returns a Verifier.
func New(cfg Config) (*Verifier, error) { panic("tokenverify.New: implemented in P4a") }

// Verify validates r and returns the caller's identity.
func (v *Verifier) Verify(r *http.Request) (Identity, error) {
	panic("tokenverify.Verify: implemented in P4a")
}

// Middleware refuses invalid requests and passes valid ones with the Identity in their context.
func (v *Verifier) Middleware(next http.Handler) http.Handler {
	panic("tokenverify.Middleware: implemented in P4a")
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
