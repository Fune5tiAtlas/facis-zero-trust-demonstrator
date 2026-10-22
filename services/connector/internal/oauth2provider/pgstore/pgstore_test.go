package pgstore

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/pgtest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
)

func newPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	pool, err := pgxpool.New(t.Context(), pgtest.MigratedURL(t, "pgstore"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	return pool
}

func TestClients_RoundTripAndNotFound(t *testing.T) {
	ctx := t.Context()
	stores := New(newPool(t), nil)

	registered := oauth2provider.Client{
		ID: "registered", SecretHash: []byte("$2a$hash"), GrantTypes: []string{"client_credentials"},
		Scopes: []string{"resource.read"}, Audience: []string{"https://b.example"}, DPoPBound: true,
		Metadata: json.RawMessage(`{"client_name":"participant"}`),
	}
	provisioned := oauth2provider.Client{ID: "provisioned"}

	for _, c := range []oauth2provider.Client{registered, provisioned} {
		if err := stores.Clients.CreateClient(ctx, c); err != nil {
			t.Fatal(err)
		}
	}

	got, err := stores.Clients.GetClient(ctx, "registered")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != registered.ID || string(got.SecretHash) != string(registered.SecretHash) || !got.DPoPBound ||
		len(got.Scopes) != 1 || got.Audience[0] != "https://b.example" || string(got.Metadata) != `{"client_name": "participant"}` {
		t.Errorf("got %+v", got)
	}

	if got, err := stores.Clients.GetClient(ctx, "provisioned"); err != nil || got.Metadata != nil || got.GrantTypes == nil {
		t.Errorf("provisioned client: %+v, %v (want no metadata, empty grant types)", got, err)
	}

	registered.Scopes = []string{"resource.read", "resource.write"}
	if err := stores.Clients.UpdateClient(ctx, registered); err != nil {
		t.Fatal(err)
	}
	if got, _ := stores.Clients.GetClient(ctx, "registered"); len(got.Scopes) != 2 {
		t.Errorf("scopes after update = %v", got.Scopes)
	}

	for name, err := range map[string]error{
		"get":    func() error { _, err := stores.Clients.GetClient(ctx, "absent"); return err }(),
		"update": stores.Clients.UpdateClient(ctx, oauth2provider.Client{ID: "absent"}),
		"delete": stores.Clients.DeleteClient(ctx, "absent"),
	} {
		if !errors.Is(err, oauth2provider.ErrNotFound) {
			t.Errorf("%s of an absent client: %v, want ErrNotFound", name, err)
		}
	}
}

// Access and registration tokens share a table and never see each other's rows; deleting a client
// takes its tokens with it.
func TestTokens_KindsAreSeparateAndFollowTheirClient(t *testing.T) {
	ctx := t.Context()
	stores := New(newPool(t), nil)

	if err := stores.Clients.CreateClient(ctx, oauth2provider.Client{ID: "c"}); err != nil {
		t.Fatal(err)
	}

	record := oauth2provider.TokenRecord{
		RequestID: "r", ClientID: "c", RequestedAt: time.Now(), Session: []byte(`{"v":1}`),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := stores.AccessTokens.CreateToken(ctx, "sig", record); err != nil {
		t.Fatal(err)
	}

	if _, err := stores.RegistrationTokens.GetToken(ctx, "sig"); !errors.Is(err, oauth2provider.ErrNotFound) {
		t.Errorf("registration store saw an access token: %v", err)
	}

	got, err := stores.AccessTokens.GetToken(ctx, "sig")
	if err != nil || got.ClientID != "c" || !got.ExpiresAt.Equal(record.ExpiresAt.Truncate(time.Microsecond)) {
		t.Errorf("got %+v, %v", got, err)
	}

	if err := stores.Clients.DeleteClient(ctx, "c"); err != nil {
		t.Fatal(err)
	}
	if _, err := stores.AccessTokens.GetToken(ctx, "sig"); !errors.Is(err, oauth2provider.ErrNotFound) {
		t.Errorf("token outlived its client: %v", err)
	}

	if err := stores.AccessTokens.DeleteToken(ctx, "sig"); err != nil {
		t.Errorf("deleting an absent token: %v, want idempotent", err)
	}
}

func TestTokens_ExpiryIsRequired(t *testing.T) {
	ctx := t.Context()
	stores := New(newPool(t), nil)

	if err := stores.Clients.CreateClient(ctx, oauth2provider.Client{ID: "c"}); err != nil {
		t.Fatal(err)
	}

	err := stores.AccessTokens.CreateToken(ctx, "sig", oauth2provider.TokenRecord{RequestID: "r", ClientID: "c", Session: []byte("{}")})
	if err == nil {
		t.Fatal("stored a token without an expiry")
	}
}

// Nonce validity follows the stores' clock, not the database's, so tests move one clock.
func TestNonces_ValidityFollowsTheClock(t *testing.T) {
	ctx := t.Context()
	now := time.Now()
	stores := New(newPool(t), func() time.Time { return now })

	if err := stores.DPoPNonces.CreateNonce(ctx, "n", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	if ok, err := stores.DPoPNonces.IsNonceValid(ctx, "n"); err != nil || !ok {
		t.Fatalf("fresh nonce: %v, %v", ok, err)
	}

	now = now.Add(2 * time.Minute)
	if ok, _ := stores.DPoPNonces.IsNonceValid(ctx, "n"); ok {
		t.Error("expired nonce accepted")
	}

	if ok, _ := stores.DPoPNonces.IsNonceValid(ctx, "never-issued"); ok {
		t.Error("unknown nonce accepted")
	}
}

func TestSweep_RemovesOnlyExpiredRows(t *testing.T) {
	ctx := t.Context()
	pool := newPool(t)
	stores := New(pool, nil)
	now := time.Now()

	if err := stores.Clients.CreateClient(ctx, oauth2provider.Client{ID: "c"}); err != nil {
		t.Fatal(err)
	}
	for sig, exp := range map[string]time.Time{"old": now.Add(-time.Minute), "live": now.Add(time.Hour)} {
		if err := stores.AccessTokens.CreateToken(ctx, sig, oauth2provider.TokenRecord{
			RequestID: sig, ClientID: "c", RequestedAt: now, Session: []byte("{}"), ExpiresAt: exp,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := stores.DPoPNonces.CreateNonce(ctx, "old", now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}

	n, err := Sweep(ctx, pool, now)
	if err != nil || n != 2 {
		t.Fatalf("swept %d, %v; want 2", n, err)
	}
	if _, err := stores.AccessTokens.GetToken(ctx, "live"); err != nil {
		t.Errorf("live token swept: %v", err)
	}
}
