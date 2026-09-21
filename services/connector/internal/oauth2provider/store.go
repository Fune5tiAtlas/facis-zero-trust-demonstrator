package oauth2provider

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned by stores when a record does not exist.
var ErrNotFound = errors.New("oauth2provider: not found")

// ClientStore persists clients.
type ClientStore interface {
	GetClient(ctx context.Context, id string) (Client, error)
	CreateClient(ctx context.Context, client Client) error
	UpdateClient(ctx context.Context, client Client) error
	DeleteClient(ctx context.Context, id string) error
}

// TokenRecord is the persisted state of an issued token.
type TokenRecord struct {
	RequestID   string
	ClientID    string
	RequestedAt time.Time

	RequestedScopes   []string
	GrantedScopes     []string
	RequestedAudience []string
	GrantedAudience   []string

	// Session is the implementation's serialized session state, including
	// expiry and any key binding. It is opaque to the store.
	Session []byte
}

// TokenStore persists token records by token signature. The signature is
// not the token: a store never sees a usable credential.
type TokenStore interface {
	CreateToken(ctx context.Context, signature string, record TokenRecord) error
	GetToken(ctx context.Context, signature string) (TokenRecord, error)
	DeleteToken(ctx context.Context, signature string) error
}

// DPoPNonceStore persists server-issued DPoP nonces.
type DPoPNonceStore interface {
	CreateNonce(ctx context.Context, nonce string, exp time.Time) error
	IsNonceValid(ctx context.Context, nonce string) (bool, error)
}

// DPoPReplayStore detects reuse of DPoP proofs.
type DPoPReplayStore interface {
	// MarkUsed atomically records key as used until exp and reports whether
	// it was already recorded and not yet expired. The check and the insert
	// happen in one critical section, so that of any number of concurrent
	// callers presenting the same key exactly one observes alreadyUsed ==
	// false. How a key is derived from a proof is the caller's concern.
	MarkUsed(ctx context.Context, key string, exp time.Time) (alreadyUsed bool, err error)
}

// Stores groups the persistence a Provider depends on.
type Stores struct {
	Clients            ClientStore
	AccessTokens       TokenStore
	RegistrationTokens TokenStore
	DPoPNonces         DPoPNonceStore
	DPoPReplay         DPoPReplayStore
}
