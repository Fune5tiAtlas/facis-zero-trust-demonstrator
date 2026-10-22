package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/pgtest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/replay"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/tokenverify"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/dpoptest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider/pgstore"
)

const (
	audience           = "https://resource.example"
	scope              = "resource.read"
	canaryClientSecret = "canary-client-secret-0123456789"
)

// infra is a migrated database of the test's own and a fresh transit key on the dev OpenBao. The
// test skips without TOKEN_STORE_TEST_DATABASE_URL, TRANSIT_TEST_ADDR and TRANSIT_TEST_TOKEN.
type infra struct {
	dsn, openbao, tokenFile string
	key                     transit.KeyVersion
	pool                    *pgxpool.Pool
}

func newInfra(t *testing.T) infra {
	t.Helper()
	addr, token := os.Getenv("TRANSIT_TEST_ADDR"), os.Getenv("TRANSIT_TEST_TOKEN")
	if addr == "" || token == "" {
		t.Skip("TRANSIT_TEST_ADDR and TRANSIT_TEST_TOKEN not set")
	}
	dsn := pgtest.MigratedURL(t, "connector")
	pool, err := pgxpool.New(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	// pgtest applies the files directly; record them as the token store's runner would.
	if _, err := pool.Exec(t.Context(), `CREATE TABLE schema_migrations (version integer PRIMARY KEY, name text NOT NULL,
		checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now());
		INSERT INTO schema_migrations (version, name, checksum) SELECT v, 'm', '' FROM generate_series(1, `+strconv.Itoa(schemaVersion)+`) v`); err != nil {
		t.Fatal(err)
	}

	mount, _ := http.NewRequest(http.MethodPost, strings.TrimSuffix(addr, "/")+"/v1/sys/mounts/transit", strings.NewReader(`{"type":"transit"}`))
	mount.Header.Set("X-Vault-Token", token)
	resp, err := http.DefaultClient.Do(mount)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("enabling transit: status %d", resp.StatusCode)
	}
	client, err := transit.New(transit.Config{Addr: addr, Token: func(context.Context) (string, error) { return token, nil }})
	if err != nil {
		t.Fatal(err)
	}
	suffix := make([]byte, 6)
	_, _ = rand.Read(suffix)
	key, err := client.EnsureKey(t.Context(), "connector-at-"+hex.EncodeToString(suffix))
	if err != nil {
		t.Fatal(err)
	}
	return infra{dsn: dsn, openbao: addr, tokenFile: writeFile(t, "bao-token", token+"\n"), key: key, pool: pool}
}

func (in infra) args(t *testing.T, version int) []string {
	return append(baseArgs(t, in.dsn, in.openbao), "--openbao-token-file", in.tokenFile,
		"--signing-key", in.key.Name, "--signing-key-version", strconv.Itoa(version))
}

// The binary end to end against PostgreSQL and OpenBao: ready; its key set verifies a token it
// issues to a seeded DPoP-bound client, through tokenverify; it drains on SIGTERM; and no secret,
// token, proof or database URL reaches its records.
func TestServeIssuesTokensTheKeySetVerifies(t *testing.T) {
	in := newInfra(t)
	hash, err := bcrypt.GenerateFromPassword([]byte(canaryClientSecret), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := pgstore.New(in.pool, nil).Clients.CreateClient(t.Context(), oauth2provider.Client{
		ID: "participant", SecretHash: hash, GrantTypes: []string{"client_credentials"},
		Scopes: []string{scope}, Audience: []string{audience}, DPoPBound: true,
	}); err != nil {
		t.Fatal(err)
	}

	r := start(t, in.args(t, in.key.Version))
	waitReady(t, r)

	code, hdr, body := get(t, "http://"+r.addr+"/.well-known/jwks.json")
	if code != http.StatusOK || hdr.Get("Cache-Control") != "public, max-age=300" ||
		!strings.Contains(body, `"use":"sig"`) || !strings.Contains(body, `"alg":"ES256"`) {
		t.Errorf("jwks %d %v %s", code, hdr, body)
	}

	key := dpoptest.NewKey(t)
	tokenURL := "http://" + r.addr + "/oauth2/token"
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {scope}, "audience": {audience}}
	tokenRequest := func(nonce string) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-Request-Id", "token-call")
		req.SetBasicAuth("participant", canaryClientSecret)
		req.Header.Set("DPoP", dpoptest.Mint(t, key, dpoptest.Proof{Method: http.MethodPost, URL: tokenURL, Nonce: nonce}))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := tokenRequest("")
	_ = resp.Body.Close()
	if nonce := resp.Header.Get("DPoP-Nonce"); nonce != "" { // --dpop-nonce is on by default
		resp = tokenRequest(nonce)
	}
	var issued struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&issued)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || issued.TokenType != "DPoP" || issued.AccessToken == "" {
		t.Fatalf("token: %d %+v", resp.StatusCode, issued)
	}

	verifier, err := tokenverify.New(tokenverify.Config{
		Issuer: "https://connector.example", JWKSURL: "http://" + r.addr + "/.well-known/jwks.json",
		Audience: audience, PublicBaseURL: audience, Scopes: []string{scope}, Replay: replay.NewPostgres(in.pool),
	})
	if err != nil {
		t.Fatal(err)
	}
	proof := dpoptest.Mint(t, key, dpoptest.Proof{Method: http.MethodGet, URL: audience + "/data", AccessToken: issued.AccessToken})
	call, _ := http.NewRequest(http.MethodGet, audience+"/data", nil)
	call.Header.Set("Authorization", "DPoP "+issued.AccessToken)
	call.Header.Set("DPoP", proof)
	id, err := verifier.Verify(call)
	if err != nil || id.ClientID != "participant" || id.JKT != key.Thumbprint() {
		t.Fatalf("tokenverify: %+v, %v", id, err)
	}

	if code := r.stop(t); code != exitOK || !r.sawDraining {
		t.Errorf("exit %d after SIGTERM, readiness drained: %v", code, r.sawDraining)
	}
	logs := r.out.String() + r.errOut.String()
	for _, secret := range []string{in.dsn, "postgres://", strings.TrimSpace(canaryTokenSecret), canaryRegistrationSecret,
		canaryClientSecret, issued.AccessToken, proof, "Authorization", "Basic "} {
		if strings.Contains(logs, secret) {
			t.Errorf("%q reached the records", secret)
		}
	}
	for _, want := range []string{`"msg":"signer ready"`, `"msg":"ready"`, `"correlation_id":"token-call"`, `"path":"/oauth2/token"`, `"msg":"draining"`, `"window":"2m0s"`} {
		if !strings.Contains(logs, want) {
			t.Errorf("records lack %s:\n%s", want, logs)
		}
	}
}

// A pinned key version that does not exist keeps the connector not ready and serving no token.
func TestServeIsNotReadyWithoutTheKeyVersion(t *testing.T) {
	in := newInfra(t)
	r := start(t, in.args(t, in.key.Version+5))
	code, _, body := get(t, "http://"+r.opsAddr+"/readyz")
	if code != http.StatusServiceUnavailable || !strings.Contains(body, `"signing_key":"missing"`) || !strings.Contains(body, `"postgres":"ok"`) ||
		!strings.Contains(body, `"openbao":"ok"`) {
		t.Errorf("readyz %d %s", code, body)
	}
	if code, _, _ := get(t, "http://"+r.addr+"/.well-known/jwks.json"); code != http.StatusServiceUnavailable {
		t.Errorf("jwks %d, want 503", code)
	}
	if code := r.stop(t); code != exitOK {
		t.Errorf("exit %d after SIGTERM", code)
	}
}

func waitReady(t *testing.T, r *running) {
	t.Helper()
	var code int
	var body string
	for range 100 {
		if code, _, body = get(t, "http://"+r.opsAddr+"/readyz"); code == http.StatusOK {
			return
		}
		select {
		case <-r.exit:
			t.Fatalf("serve exited:\n%s", r.out.String())
		case <-t.Context().Done():
		default:
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("never ready: %d %s\n%s", code, body, r.out.String())
}
