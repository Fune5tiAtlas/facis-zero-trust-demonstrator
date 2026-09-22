// Package dpoptest mints RFC 9449 DPoP proofs for tests, including
// deliberately defective ones. It uses the standard library only, so that it
// exercises an implementation from the outside.
package dpoptest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// Key is a P-256 proof-of-possession key.
type Key struct {
	private *ecdsa.PrivateKey
}

// NewKey generates a key.
func NewKey(t testing.TB) *Key {
	t.Helper()

	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	return &Key{private: private}
}

func (k *Key) jwk() map[string]string {
	// Uncompressed SEC 1 point: 0x04 || X || Y, 32 bytes each for P-256.
	point, err := k.private.PublicKey.Bytes()
	if err != nil || len(point) != 65 {
		panic("dpoptest: unexpected public key encoding")
	}

	return map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   b64(point[1:33]),
		"y":   b64(point[33:65]),
	}
}

// Thumbprint returns the RFC 7638 SHA-256 thumbprint of the public key.
func (k *Key) Thumbprint() string {
	jwk := k.jwk()

	// RFC 7638 section 3.2: required members only, in lexicographic order.
	canonical := fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q,"y":%q}`, jwk["crv"], jwk["kty"], jwk["x"], jwk["y"])
	digest := sha256.Sum256([]byte(canonical))

	return b64(digest[:])
}

// Proof describes the proof to mint. The zero value of an optional field
// leaves the corresponding claim out.
type Proof struct {
	Method string
	URL    string

	// IssuedAt defaults to now.
	IssuedAt time.Time

	// ID is the jti claim. A random one is generated when empty.
	ID string

	Nonce string

	// AccessToken, when set, produces the matching ath claim.
	AccessToken string

	// ATH overrides the ath claim verbatim, to produce a wrong one.
	ATH string
}

// Mint signs the proof with key.
func Mint(t testing.TB, key *Key, proof Proof) string {
	t.Helper()

	if proof.IssuedAt.IsZero() {
		proof.IssuedAt = time.Now()
	}

	if proof.ID == "" {
		proof.ID = randomID(t)
	}

	claims := map[string]any{
		"jti": proof.ID,
		"htm": proof.Method,
		"htu": proof.URL,
		"iat": proof.IssuedAt.Unix(),
	}

	if proof.Nonce != "" {
		claims["nonce"] = proof.Nonce
	}

	switch {
	case proof.ATH != "":
		claims["ath"] = proof.ATH
	case proof.AccessToken != "":
		claims["ath"] = AccessTokenHash(proof.AccessToken)
	}

	header := map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": key.jwk()}

	signingInput := b64(mustJSON(t, header)) + "." + b64(mustJSON(t, claims))
	digest := sha256.Sum256([]byte(signingInput))

	r, s, err := ecdsa.Sign(rand.Reader, key.private, digest[:])
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}

	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)

	return signingInput + "." + b64(signature)
}

// AccessTokenHash returns the ath claim value for an access token.
func AccessTokenHash(token string) string {
	digest := sha256.Sum256([]byte(token))

	return b64(digest[:])
}

func randomID(t testing.TB) string {
	t.Helper()

	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("generate jti: %v", err)
	}

	return b64(raw)
}

func mustJSON(t testing.TB, v any) []byte {
	t.Helper()

	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	return encoded
}

func b64(raw []byte) string { return base64.RawURLEncoding.EncodeToString(raw) }
