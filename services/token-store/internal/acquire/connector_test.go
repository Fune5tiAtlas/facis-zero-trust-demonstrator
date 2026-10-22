package acquire

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/dpopproof"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/transit"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/testsupport"
)

// Zone B is the real connector binary (services/connector), built once per test run and started as
// a subprocess on a migrated database of its own, with a transit signing key, the registrar, the
// trusted-issuers file and the scope map. The store's client is registered through the registrar's
// DCR with the delegated verified-presentation scope, as a deployment registers it.

var (
	buildOnce    sync.Once
	connectorBin string
	buildErr     error
)

func connectorBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		_, self, _, _ := runtime.Caller(0)
		dir, err := os.MkdirTemp("", "connector-bin")
		if err != nil {
			buildErr = err
			return
		}
		connectorBin = filepath.Join(dir, "connector")
		cmd := exec.Command("go", "build", "-o", connectorBin, "./services/connector")
		cmd.Dir = filepath.Join(filepath.Dir(self), "..", "..", "..", "..")
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = errors.New(string(out))
		}
	})
	if buildErr != nil {
		t.Fatalf("building the connector: %v", buildErr)
	}
	return connectorBin
}

func TestMain(m *testing.M) {
	code := m.Run()
	if connectorBin != "" {
		_ = os.RemoveAll(filepath.Dir(connectorBin))
	}
	os.Exit(code)
}

type zoneB struct {
	base, clientID, clientSecret string
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// startConnector runs the connector on dsn (migrated by pgtest) and registers the store's client.
func startConnector(t *testing.T, dsn, baoAddr, baoToken string, issuer *ecdsa.PublicKey) zoneB {
	t.Helper()
	ctx := t.Context()
	// pgtest applies the files directly; record them as the token store's runner would, as the
	// connector's own tests do, so the binary's schema check is satisfied.
	files, _ := filepath.Glob(filepath.Join(migrationsDir(), "*.up.sql"))
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `CREATE TABLE schema_migrations (version integer PRIMARY KEY, name text NOT NULL,
		checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now());
		INSERT INTO schema_migrations (version, name, checksum) SELECT v, 'm', '' FROM generate_series(1, `+strconv.Itoa(len(files))+`) v`); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close(ctx)

	kv, err := transit.New(transit.Config{Addr: baoAddr, Token: func(context.Context) (string, error) { return baoToken, nil }})
	if err != nil {
		t.Fatal(err)
	}
	key, err := kv.EnsureKey(ctx, "acq-b-"+randHex(6))
	if err != nil {
		t.Fatal(err)
	}
	jwk := jose.PublicJWK(issuer)
	jwk.Kid = vpKid
	jwkJSON, _ := json.Marshal(jwk)
	scopeMap, _ := json.Marshal([]map[string]any{{"role": vpRole, "entitlement": vpEntitle, "scopes": []string{vpScope}}})

	apiAddr, opsAddr := freeAddr(t), freeAddr(t)
	base := "http://" + apiAddr
	endpoint := base + "/oauth2/register"
	registrarSecret := randHex(24)
	cmd := exec.Command(connectorBinary(t), "serve", "--addr", apiAddr, "--ops-addr", opsAddr,
		"--database-url", dsn, "--openbao-url", baoAddr, "--openbao-token-file", writeFile(t, "bao-token", baoToken+"\n"),
		"--issuer", bIssuer, "--signing-key", key.Name, "--signing-key-version", strconv.Itoa(key.Version),
		"--registration-endpoint", endpoint,
		"--token-secret-file", writeFile(t, "token-secret", randHex(24)),
		"--registration-secret-file", writeFile(t, "registration-secret", randHex(24)),
		"--registrar-id", "registrar", "--registrar-secret-file", writeFile(t, "registrar-secret", registrarSecret),
		"--registrar-scopes", "connector:client_registration", "--registrar-audiences", endpoint+","+audience,
		"--registrar-delegable-scopes", vpScope,
		"--vp-trusted-issuers-file", writeFile(t, "issuers.json", `{"`+vpIssuer+`":{"keys":[`+string(jwkJSON)+`]}}`),
		"--vp-scope-map-file", writeFile(t, "scopes.json", string(scopeMap)),
		"--drain-delay", "0s", "--shutdown-timeout", "2s")
	out := &testsupport.Buffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
	})
	for i := 0; ; i++ {
		resp, err := http.Get("http://" + opsAddr + "/readyz")
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if strings.Contains(string(body), `"ready":true`) {
				break
			}
		}
		if i == 150 {
			t.Fatalf("connector never ready:\n%s", out.String())
		}
		time.Sleep(100 * time.Millisecond)
	}

	// The registrar's DPoP-bound registration token, then DCR of the store's client.
	rk := newProcessKey(t)
	tokenURL := base + "/oauth2/token"
	resp, body := dpopPost(t, rk, tokenURL, "", func(r *http.Request) {
		r.SetBasicAuth("registrar", url.QueryEscape(registrarSecret))
	}, "application/x-www-form-urlencoded", url.Values{"grant_type": {"client_credentials"},
		"scope": {"connector:client_registration"}, "audience": {endpoint + " " + audience}}.Encode())
	var issued struct {
		AccessToken string `json:"access_token"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &issued) != nil {
		t.Fatalf("registrar token: status %d %s", resp.StatusCode, body)
	}
	metadata, _ := json.Marshal(map[string]any{
		"client_name": "zone-a token store", "grant_types": []string{VPGrantType},
		"token_endpoint_auth_method": "client_secret_basic", "scope": vpScope,
		"dpop_bound_access_tokens": true, "audience": []string{audience},
	})
	resp, body = dpopPost(t, rk, endpoint, issued.AccessToken, func(r *http.Request) {
		r.Header.Set("Authorization", "DPoP "+issued.AccessToken)
	}, "application/json", string(metadata))
	var client struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if resp.StatusCode != http.StatusCreated || json.Unmarshal(body, &client) != nil || client.ClientID == "" {
		t.Fatalf("registration: status %d %s", resp.StatusCode, body)
	}
	return zoneB{base: base, clientID: client.ClientID, clientSecret: client.ClientSecret}
}

func migrationsDir() string {
	_, self, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(self), "..", "schema", "migrations")
}

// processKey is a DPoP key held in the process, for the registrar.
type processKey struct{ k *ecdsa.PrivateKey }

func newProcessKey(t *testing.T) processKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return processKey{k}
}

func (p processKey) JWK() jose.JWK { return jose.PublicJWK(&p.k.PublicKey) }
func (p processKey) Sign(_ context.Context, in []byte) ([]byte, error) {
	return signES256(p.k, in)
}

// dpopPost posts body with a fresh proof, once more with the server's nonce when asked for one.
func dpopPost(t *testing.T, key dpopproof.Key, target, accessToken string, auth func(*http.Request), contentType, body string) (*http.Response, []byte) {
	t.Helper()
	nonce := ""
	for try := 0; ; try++ {
		c := dpopproof.Claims{HTM: http.MethodPost, HTU: target, Nonce: nonce}
		if accessToken != "" {
			c.ATH = athOf(accessToken)
		}
		proof, err := dpopproof.Build(context.Background(), key, c)
		if err != nil {
			t.Fatal(err)
		}
		req, _ := http.NewRequest(http.MethodPost, target, strings.NewReader(body))
		req.Header.Set("Content-Type", contentType)
		req.Header.Set("DPoP", proof)
		auth(req)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		_, _ = b.ReadFrom(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode < 300 || resp.Header.Get("DPoP-Nonce") == "" || try > 0 {
			return resp, b.Bytes()
		}
		nonce = resp.Header.Get("DPoP-Nonce")
	}
}

func athOf(token string) string {
	d := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(d[:])
}
