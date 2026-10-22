// Package transit is the OpenBao client of the token path: ES256 signing with transit keys that never
// leave OpenBao, and create-only KV v2 secrets. Only public keys enter the process.
package transit

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net/http"
)

// KeyVersion names one version of a transit key; tokens bound to it keep working after rotation.
type KeyVersion struct {
	Name    string
	Version int
}

// Ref is the form stored in signing_key.key_ref: transit:<name>:v<version>.
func (k KeyVersion) Ref() string { return fmt.Sprintf("transit:%s:v%d", k.Name, k.Version) }

// ParseRef parses a Ref.
func ParseRef(ref string) (KeyVersion, error) { panic("transit.ParseRef: implemented in P3") }

// Signer signs with transit. Sign takes the full JWS signing input (sha2-256, prehashed=false,
// marshaling_algorithm=jws, key_version pinned), checks the returned version and returns exactly 64
// bytes R||S.
type Signer interface {
	Sign(ctx context.Context, key KeyVersion, signingInput []byte) ([]byte, error)
	PublicKey(ctx context.Context, key KeyVersion) (*ecdsa.PublicKey, error)
	// EnsureKey creates the key non-exportable as ecdsa-p256 if missing and returns its latest version.
	EnsureKey(ctx context.Context, name string) (KeyVersion, error)
}

// Secrets is KV v2 with create-only writes.
type Secrets interface {
	Create(ctx context.Context, path string, value []byte) error // cas=0; ErrExists when present
	Read(ctx context.Context, path string) ([]byte, error)       // ErrNotFound when absent
	Delete(ctx context.Context, path string) error               // all versions
	List(ctx context.Context, prefix string) ([]string, error)
}

// TokenSource yields the OpenBao token per call (Kubernetes auth in a cluster, a dev token in tests).
type TokenSource func(ctx context.Context) (string, error)

// Config configures a Client.
type Config struct {
	Addr         string
	TransitMount string // default "transit"
	KVMount      string // default "secret"
	Token        TokenSource
	HTTPClient   *http.Client
}

var (
	ErrExists          = errors.New("transit: secret exists")
	ErrNotFound        = errors.New("transit: not found")
	ErrVersionMismatch = errors.New("transit: signed with another key version")
)

// Client implements Signer and Secrets.
type Client struct{ cfg Config }

var (
	_ Signer  = (*Client)(nil)
	_ Secrets = (*Client)(nil)
)

// New returns a Client.
func New(cfg Config) (*Client, error) { panic("transit.New: implemented in P3") }

func (c *Client) Sign(ctx context.Context, key KeyVersion, signingInput []byte) ([]byte, error) {
	panic("implemented in P3")
}
func (c *Client) PublicKey(ctx context.Context, key KeyVersion) (*ecdsa.PublicKey, error) {
	panic("implemented in P3")
}
func (c *Client) EnsureKey(ctx context.Context, name string) (KeyVersion, error) {
	panic("implemented in P3")
}
func (c *Client) Create(ctx context.Context, path string, value []byte) error {
	panic("implemented in P3")
}
func (c *Client) Read(ctx context.Context, path string) ([]byte, error) { panic("implemented in P3") }
func (c *Client) Delete(ctx context.Context, path string) error         { panic("implemented in P3") }
func (c *Client) List(ctx context.Context, prefix string) ([]string, error) {
	panic("implemented in P3")
}
