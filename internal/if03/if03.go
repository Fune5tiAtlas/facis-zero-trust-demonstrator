// Package if03 verifies IF-03 verification outcomes: a compact JWS with header exactly alg, kid, typ
// (docs/api-docs.md, IF-03; docs/contracts/if03-*.schema.json).
package if03

import (
	"crypto/ecdsa"
	"time"
)

// Typ is the outcome's typ header.
const Typ = "facis-verification-outcome+jws"

// Reason codes, as IF-03 names them.
const (
	CodeSignature   = "CRED-OUTCOME-SIGNATURE"
	CodeNotVerified = "CRED-OUTCOME-NOT-VERIFIED"
	CodeMismatch    = "CRED-OUTCOME-MISMATCH"
	CodeExpired     = "CRED-OUTCOME-EXPIRED"
	CodeConsumed    = "CRED-OUTCOME-CONSUMED"
)

// Claims is the outcome's role and optional entitlement.
type Claims struct {
	Role        string `json:"role"`
	Entitlement string `json:"entitlement,omitempty"`
}

// Outcome is a parsed, signature-checked outcome.
type Outcome struct {
	Issuer         string    `json:"iss"`
	OutcomeID      string    `json:"outcome_id"`
	ClientID       string    `json:"client_id"`
	Challenge      string    `json:"challenge"`
	Audience       string    `json:"audience"`
	Claims         Claims    `json:"claims"`
	VerifiedAt     time.Time `json:"verified_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	Status         string    `json:"status"`
	CredentialRefs []string  `json:"credential_refs,omitempty"`
	ReasonCode     string    `json:"reason_code,omitempty"`
	Raw            []byte    `json:"-"` // the payload as signed
}

// Issuers is the configured trust: issuer → kid → key. A kid belongs to exactly one issuer.
type Issuers map[string]map[string]*ecdsa.PublicKey

// Expect is the grant request the outcome must match.
type Expect struct {
	ClientID  string
	Challenge string
	Audience  string
}

// Error carries the IF-03 reason code.
type Error struct {
	Code string
	Err  error
}

func (e *Error) Error() string { return e.Code + ": " + e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// Verify checks signature (CodeSignature), payload schema, status (CodeNotVerified), the match with
// want (CodeMismatch) and the validity interval at now with 30 s skew and a 120 s maximum
// (CodeExpired). Consumption (CodeConsumed) is the caller's, inside its transaction.
func Verify(compact string, trusted Issuers, want Expect, now time.Time) (Outcome, error) {
	panic("if03.Verify: implemented in P5")
}
