// Package pgstore keeps the connector's clients, issued tokens and DPoP nonces in the zone's
// authorization database (tables oauth2_client, oauth2_token, oauth2_dpop_nonce; schema owned by the
// token store's migrations). Tokens are keyed by signature, so the database never holds a usable
// credential, and client secrets are bcrypt hashes. Replay detection is not here: it is the shared
// proof_jti table (internal/replay), which the stores use through the provider's replay interface.
// Creates are insert-only: a second client, token or nonce under an existing key is
// an error, never an overwrite.
package pgstore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/replay"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
)

// New returns the PostgreSQL stores. Validity is evaluated against now, which defaults to time.Now
// when nil, and passed to the database as a parameter, so tests move one clock for every store.
// Replay detection is the zone's shared proof_jti record, the one the token store and the guard use.
func New(pool *pgxpool.Pool, now func() time.Time) oauth2provider.Stores {
	if now == nil {
		now = time.Now
	}

	return oauth2provider.Stores{
		Clients:            &clients{pool: pool},
		AccessTokens:       &tokens{pool: pool, kind: "access"},
		RegistrationTokens: &tokens{pool: pool, kind: "registration"},
		DPoPNonces:         &nonces{pool: pool, now: now},
		DPoPReplay:         replayStore{replay.NewPostgres(pool)},
	}
}

// replayStore presents the shared replay record as the provider's replay store. The two say the
// same thing the other way round: TryUse reports fresh, MarkUsed reports already used.
type replayStore struct{ store replay.Store }

func (s replayStore) MarkUsed(ctx context.Context, use oauth2provider.DPoPProofUse) (bool, error) {
	fresh, err := s.store.TryUse(ctx, replay.Use{
		JKT: use.Thumbprint, Method: use.Method, URI: use.URI, JTI: use.ID, NotAfter: use.NotAfter,
	})
	if err != nil {
		return false, err
	}
	return !fresh, nil
}

type clients struct{ pool *pgxpool.Pool }

func (s *clients) GetClient(ctx context.Context, id string) (oauth2provider.Client, error) {
	var c oauth2provider.Client
	err := s.pool.QueryRow(ctx, `SELECT client_id, secret_hash, grant_types, scopes, audience, dpop_bound, metadata
		FROM oauth2_client WHERE client_id = $1`, id).
		Scan(&c.ID, &c.SecretHash, &c.GrantTypes, &c.Scopes, &c.Audience, &c.DPoPBound, &c.Metadata)
	if errors.Is(err, pgx.ErrNoRows) {
		return oauth2provider.Client{}, oauth2provider.ErrNotFound
	}
	if err != nil {
		return oauth2provider.Client{}, fmt.Errorf("get client: %w", err)
	}

	return c, nil
}

func (s *clients) CreateClient(ctx context.Context, c oauth2provider.Client) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO oauth2_client
		(client_id, secret_hash, grant_types, scopes, audience, dpop_bound, metadata)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		c.ID, c.SecretHash, nonNil(c.GrantTypes), nonNil(c.Scopes), nonNil(c.Audience), c.DPoPBound, nullJSON(c.Metadata))
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}

	return nil
}

func (s *clients) UpdateClient(ctx context.Context, c oauth2provider.Client) error {
	tag, err := s.pool.Exec(ctx, `UPDATE oauth2_client SET secret_hash = $2, grant_types = $3, scopes = $4,
		audience = $5, dpop_bound = $6, metadata = $7, updated_at = now() WHERE client_id = $1`,
		c.ID, c.SecretHash, nonNil(c.GrantTypes), nonNil(c.Scopes), nonNil(c.Audience), c.DPoPBound, nullJSON(c.Metadata))
	if err != nil {
		return fmt.Errorf("update client: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return oauth2provider.ErrNotFound
	}

	return nil
}

func (s *clients) DeleteClient(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM oauth2_client WHERE client_id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete client: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return oauth2provider.ErrNotFound
	}

	return nil
}

type tokens struct {
	pool *pgxpool.Pool
	kind string
}

func (s *tokens) CreateToken(ctx context.Context, signature string, r oauth2provider.TokenRecord) error {
	if r.ExpiresAt.IsZero() {
		return errors.New("create token: no expiry")
	}

	_, err := s.pool.Exec(ctx, `INSERT INTO oauth2_token (kind, signature, request_id, client_id, requested_at,
		requested_scopes, granted_scopes, requested_audience, granted_audience, session, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		s.kind, signature, r.RequestID, r.ClientID, r.RequestedAt,
		nonNil(r.RequestedScopes), nonNil(r.GrantedScopes), nonNil(r.RequestedAudience), nonNil(r.GrantedAudience),
		r.Session, r.ExpiresAt)
	if err != nil {
		return fmt.Errorf("create %s token: %w", s.kind, err)
	}

	return nil
}

func (s *tokens) GetToken(ctx context.Context, signature string) (oauth2provider.TokenRecord, error) {
	var r oauth2provider.TokenRecord
	err := s.pool.QueryRow(ctx, `SELECT request_id, client_id, requested_at, requested_scopes, granted_scopes,
		requested_audience, granted_audience, session, expires_at
		FROM oauth2_token WHERE kind = $1 AND signature = $2`, s.kind, signature).
		Scan(&r.RequestID, &r.ClientID, &r.RequestedAt, &r.RequestedScopes, &r.GrantedScopes,
			&r.RequestedAudience, &r.GrantedAudience, &r.Session, &r.ExpiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return oauth2provider.TokenRecord{}, oauth2provider.ErrNotFound
	}
	if err != nil {
		return oauth2provider.TokenRecord{}, fmt.Errorf("get %s token: %w", s.kind, err)
	}

	return r, nil
}

// DeleteToken is idempotent, as the in-memory store's is.
func (s *tokens) DeleteToken(ctx context.Context, signature string) error {
	if _, err := s.pool.Exec(ctx, `DELETE FROM oauth2_token WHERE kind = $1 AND signature = $2`, s.kind, signature); err != nil {
		return fmt.Errorf("delete %s token: %w", s.kind, err)
	}

	return nil
}

type nonces struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

func (s *nonces) CreateNonce(ctx context.Context, nonce string, exp time.Time) error {
	if _, err := s.pool.Exec(ctx, `INSERT INTO oauth2_dpop_nonce (nonce, expires_at) VALUES ($1, $2)`, nonce, exp); err != nil {
		return fmt.Errorf("create nonce: %w", err)
	}

	return nil
}

func (s *nonces) IsNonceValid(ctx context.Context, nonce string) (bool, error) {
	var valid bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM oauth2_dpop_nonce WHERE nonce = $1 AND expires_at > $2)`,
		nonce, s.now()).Scan(&valid)
	if err != nil {
		return false, fmt.Errorf("check nonce: %w", err)
	}

	return valid, nil
}

// Sweep removes expired tokens and nonces and reports how many rows went. The binary runs it on a
// ticker; nothing reads an expired row, so sweeping is housekeeping, not a security control.
func Sweep(ctx context.Context, pool *pgxpool.Pool, now time.Time) (int64, error) {
	var total int64
	for _, q := range []string{
		`DELETE FROM oauth2_token WHERE expires_at <= $1`,
		`DELETE FROM oauth2_dpop_nonce WHERE expires_at <= $1`,
	} {
		tag, err := pool.Exec(ctx, q, now)
		if err != nil {
			return total, fmt.Errorf("sweep: %w", err)
		}
		total += tag.RowsAffected()
	}

	return total, nil
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func nullJSON(raw []byte) any {
	if len(raw) == 0 {
		return nil
	}
	return string(raw)
}
