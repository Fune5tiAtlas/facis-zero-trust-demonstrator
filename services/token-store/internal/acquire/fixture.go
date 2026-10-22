package acquire

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
)

// Fixture is an OutcomeSource for tests and the demo: it signs a verified IF-03 outcome for every
// challenge with a configured key, with a new outcome_id per call. It is not a verifier; it attests
// whatever it is asked to.
type Fixture struct {
	Issuer   string
	Kid      string
	Key      *ecdsa.PrivateKey
	Claims   if03.Claims
	Validity time.Duration // 60 s to 120 s; zero means 90 s
	Now      func() time.Time
}

var _ OutcomeSource = Fixture{}

func (f Fixture) Outcome(ctx context.Context, ch Challenge) (string, error) {
	validity := f.Validity
	if validity == 0 {
		validity = 90 * time.Second
	}
	if validity < 60*time.Second || validity > 120*time.Second || f.Key == nil {
		return "", errors.New("acquire: fixture misconfigured")
	}
	now := time.Now
	if f.Now != nil {
		now = f.Now
	}
	at := now().UTC().Truncate(time.Second)
	payload, err := json.Marshal(map[string]any{
		"iss": f.Issuer, "outcome_id": newUUID(), "client_id": ch.ClientID, "challenge": ch.Value,
		"audience": ch.Audience, "claims": f.Claims, "status": "verified",
		"verified_at": at.Format(time.RFC3339), "expires_at": at.Add(validity).Format(time.RFC3339),
	})
	if err != nil {
		return "", err
	}
	return jose.Sign(ctx, jose.Header{Typ: if03.Typ, Kid: f.Kid}, payload, func(_ context.Context, in []byte) ([]byte, error) {
		return signES256(f.Key, in)
	})
}

// signES256 signs with a process key, R||S of 32 bytes each.
func signES256(key *ecdsa.PrivateKey, in []byte) ([]byte, error) {
	digest := sha256.Sum256(in)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return nil, err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return sig, nil
}

// newUUID is a random (version 4) UUID.
func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
