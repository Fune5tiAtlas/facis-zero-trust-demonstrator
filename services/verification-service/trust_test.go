package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/verificationtest"
)

const listed = "did:web:issuer.zone-a.test"

func entry(id, status string) map[string]any {
	return map[string]any{"TSPServices": map[string]any{"TSPService": []any{
		map[string]any{"ServiceTypeIdentifier": id, "ServiceCurrentStatus": status}}}}
}

func TestListsActiveFindsAnActiveServiceByItsTypeIdentifier(t *testing.T) {
	doc := map[string]any{"TrustServiceStatusList": map[string]any{"TrustServiceProviderList": map[string]any{
		"TrustServiceProvider": []any{entry(listed, "active"), entry("did:web:withdrawn.test", "withdrawn")}}}}
	if !listsActive(doc, listed) {
		t.Error("active entry not found")
	}
	if listsActive(doc, "did:web:withdrawn.test") || listsActive(doc, "did:web:absent.test") {
		t.Error("a withdrawn or absent issuer was listed")
	}
}

// The TCR answer in the shape of train-trust-validator's OpenAPI (POST /tcr/v1/resolve).
func TestTCRListsOnlyFromAVerifiedTrustList(t *testing.T) {
	var verified bool
	var status = http.StatusOK
	var got map[string]any
	tcr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/tcr/v1/resolve" {
			http.NotFound(w, r)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got)
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"trustSchemePointers": []any{map[string]any{"pointer": "trust.zone-a.test", "dids": []string{"did:web:tl.test"}}},
			"resolvedResults": []any{map[string]any{"did": "did:web:tl.test", "resolvedDoc": map[string]any{
				"document": map[string]any{}, "didVerified": true,
				"endpoints": []any{map[string]any{"vcUri": "https://tl.test/vc", "trustList": entry(listed, "active"), "vcVerified": verified}},
			}}},
		})
	}))
	defer tcr.Close()
	l := tcrList(tcr.Client(), tcr.URL, []string{"trust.zone-a.test"})

	if ok, err := l(context.Background(), listed); ok || err != nil {
		t.Errorf("an unverified trust list listed the issuer: %v %v", ok, err)
	}
	verified = true
	if ok, err := l(context.Background(), listed); !ok || err != nil {
		t.Errorf("a verified trust list did not list the issuer: %v %v", ok, err)
	}
	if got["issuer"] != listed || len(got["trustSchemePointers"].([]any)) != 1 {
		t.Errorf("request %v", got)
	}
	if ok, _ := l(context.Background(), "did:web:other.test"); ok {
		t.Error("an issuer the list does not name was listed")
	}
	status = http.StatusBadGateway
	if ok, err := l(context.Background(), listed); ok || err == nil {
		t.Errorf("a failing TCR listed the issuer: %v %v", ok, err)
	}
}

func TestTrustedKeepsOnlyListedIssuersAndFailsClosed(t *testing.T) {
	kit := verificationtest.Provision(t, "https://issuer.zone-a.test")
	keyed, err := readIssuers(kit.IssuerKeysFile)
	if err != nil || len(keyed) != 2 {
		t.Fatalf("%v %v", keyed, err)
	}
	set, dropped := trusted(context.Background(), keyed, pinnedList(kit.TrustListFile))
	if len(set) != 1 || set[kit.Issuer] == nil || len(dropped) != 1 || dropped[0] != kit.Unlisted {
		t.Errorf("set %v, dropped %v", set, dropped)
	}
	failing := func(context.Context, string) (bool, error) { return true, errors.New("down") }
	if set, _ := trusted(context.Background(), keyed, failing); len(set) != 0 {
		t.Errorf("a failing trust source trusted %v", set)
	}
	if _, err := pinnedList(kit.TrustListFile+".missing")(context.Background(), kit.Issuer); err == nil {
		t.Error("a missing trust list did not fail")
	}
}

func TestParseNeedsExactlyOneTrustSource(t *testing.T) {
	base := []string{"--openbao-url", "http://bao:8200", "--openbao-token-file", "/t", "--signing-key", "k", "--issuer", "https://v.test",
		"--public-url", "https://v.test", "--database-url", "postgres://x", "--callers", "spiffe://td/ns/a/sa/b",
		"--issuer-keys-file", "/k", "--accepted-vct", "urn:vct", "--status-prefixes", "https://status.test/"}
	env := func(string) string { return "" }
	for name, c := range map[string]struct {
		extra []string
		ok    bool
	}{
		"none":         {nil, false},
		"both":         {[]string{"--trust-list-file", "/l", "--tcr-url", "https://tcr", "--trust-scheme-pointers", "p"}, false},
		"tcr no ptr":   {[]string{"--tcr-url", "https://tcr"}, false},
		"fixture list": {[]string{"--trust-list-file", "/l"}, true},
		"tcr":          {[]string{"--tcr-url", "https://tcr", "--trust-scheme-pointers", "p"}, true},
	} {
		_, err := parse("serve", append(append([]string{}, base...), c.extra...), env, io.Discard)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
	o, err := parse("serve", []string{"--trust-list-file", "/l"}, func(k string) string {
		v := map[string]string{"VERIFICATION_SERVICE_OPENBAO_URL": "http://bao", "VERIFICATION_SERVICE_OPENBAO_TOKEN_FILE": "/t",
			"VERIFICATION_SERVICE_SIGNING_KEY": "k", "VERIFICATION_SERVICE_ISSUER": "https://v", "VERIFICATION_SERVICE_PUBLIC_URL": "https://v",
			"VERIFICATION_SERVICE_DATABASE_URL": "postgres://x", "VERIFICATION_SERVICE_CALLERS": "spiffe://td/ns/a/sa/b, spiffe://td/ns/a/sa/c",
			"VERIFICATION_SERVICE_ISSUER_KEYS_FILE": "/k", "VERIFICATION_SERVICE_ACCEPTED_VCT": "urn:vct",
			"VERIFICATION_SERVICE_STATUS_PREFIXES": "https://status.test/"}
		return v[k]
	}, io.Discard)
	if err != nil || len(o.callers) != 2 || !strings.HasSuffix(o.callers[1], "/sa/c") {
		t.Errorf("from the environment: %+v %v", o, err)
	}
}

// A refresh that cannot read the issuer keys, or reads an empty set, withdraws every issuer: the
// policy is cleared (not ready) rather than kept from the last good read. A refresh also asks the
// trust source again, so a delisted issuer is dropped at the next refresh.
func TestRefreshFailsClosedAndAsksTheTrustSourceEveryTime(t *testing.T) {
	kit := verificationtest.Provision(t, "https://issuer.zone-a.test")
	s := &server{log: slog.New(slog.NewJSONHandler(io.Discard, nil))}
	asked := 0
	listedNow := true
	tc := trustConfig{keysFile: kit.IssuerKeysFile, acceptedVCT: []string{verificationtest.CredentialVCT}, statusPrefixes: []string{kit.StatusPrefix},
		listed: func(_ context.Context, iss string) (bool, error) { asked++; return listedNow && iss == kit.Issuer, nil }}
	tc.refresh(context.Background(), s)
	if p := s.policy.Load(); p == nil || p.Trusted[kit.Issuer] == nil {
		t.Fatal("no policy after a good load")
	}
	good, _ := os.ReadFile(kit.IssuerKeysFile)
	for name, breakIt := range map[string]func(){
		"emptied":    func() { _ = os.WriteFile(kit.IssuerKeysFile, []byte("{}"), 0o600) },
		"unreadable": func() { _ = os.Remove(kit.IssuerKeysFile) },
	} {
		_ = os.WriteFile(kit.IssuerKeysFile, good, 0o600)
		tc.refresh(context.Background(), s)
		breakIt()
		tc.refresh(context.Background(), s)
		if s.policy.Load() != nil {
			t.Errorf("%s: the previous trust set is still in force", name)
		}
	}
	_ = os.WriteFile(kit.IssuerKeysFile, good, 0o600)
	tc.refresh(context.Background(), s)
	before := asked
	listedNow = false
	tc.refresh(context.Background(), s)
	if asked == before || s.policy.Load() != nil {
		t.Errorf("a delisted issuer is still trusted after a refresh (asked %d→%d)", before, asked)
	}
}
