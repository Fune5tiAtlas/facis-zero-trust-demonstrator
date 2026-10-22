// Package jose is the compact JWS (RFC 7515) and JWK (RFC 7517, RFC 7638) subset the token path uses:
// ES256 only, a fixed header allow-list, and signing through a caller-supplied function so that a
// private key never has to be held by this package. Standard library only.
package jose

import (
	"context"
	"crypto/ecdsa"
	"errors"
)

// AlgES256 is the only signature algorithm accepted or produced.
const AlgES256 = "ES256"

// JWK is a public P-256 key. Private members are never represented.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid,omitempty"`
}

// Header is the protected header. Members other than these are refused on verification.
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ,omitempty"`
	Kid string `json:"kid,omitempty"`
	JWK *JWK   `json:"jwk,omitempty"`
}

// HeaderPolicy says which header members a verification accepts.
type HeaderPolicy struct {
	Typ       string // required value of typ
	KidNeeded bool   // kid must be present
	JWKNeeded bool   // jwk must be present (DPoP proofs); otherwise jwk is refused
}

// SignFunc signs the JWS signing input and returns the 64-byte R||S signature.
type SignFunc func(ctx context.Context, signingInput []byte) ([]byte, error)

// KeyFunc resolves the verification key for a parsed header.
type KeyFunc func(Header) (*ecdsa.PublicKey, error)

var (
	ErrMalformed = errors.New("jose: malformed token")
	ErrHeader    = errors.New("jose: header not allowed")
	ErrSignature = errors.New("jose: signature does not verify")
)

// Sign builds a compact JWS of payload with header h.
func Sign(ctx context.Context, h Header, payload []byte, sign SignFunc) (string, error) {
	panic("jose.Sign: implemented in P4a")
}

// Verify checks the compact JWS against policy and the key from key, and returns its header and payload.
func Verify(token string, policy HeaderPolicy, key KeyFunc) (Header, []byte, error) {
	panic("jose.Verify: implemented in P4a")
}

// PublicJWK returns the public JWK of k.
func PublicJWK(k *ecdsa.PublicKey) JWK { panic("jose.PublicJWK: implemented in P4a") }

// Thumbprint returns the RFC 7638 SHA-256 thumbprint of j, base64url without padding.
func (j JWK) Thumbprint() (string, error) { panic("jose.JWK.Thumbprint: implemented in P4a") }

// PublicKey returns j as an ECDSA P-256 public key, refusing any other curve or an off-curve point.
func (j JWK) PublicKey() (*ecdsa.PublicKey, error) { panic("jose.JWK.PublicKey: implemented in P4a") }
