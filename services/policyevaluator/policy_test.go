package policyevaluator

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/hook"
)

const (
	participant = "spiffe://zone-b.test/ns/m3/sa/participant"
	guardID     = "spiffe://zone-b.test/ns/m3/sa/guard"
	link        = "openid4vp://authorize?request_uri=https%3A%2F%2Fverifier.test%2Frequest"
)

func testConfig() Config {
	return Config{Revision: "test-1", Audience: "resource", Host: "resource.test", GuardCallers: []string{guardID}, ParticipantCallers: []string{participant},
		ScopeTenants: map[string]string{"report:read": "read", "report:summary": "summary"}, EventSource: "policy-b",
		BlockedClients: []string{"blocked-client"}, Presentation: &Presentation{Scopes: []string{"report:full"}, OID4VPLink: link}}
}

func validInput() hook.Input {
	tenant := "summary"
	return hook.Input{CorrelationID: "corr-1", Source: hook.Source{SPIFFEID: participant}, Request: hook.RequestInfo{Method: http.MethodPost, Path: "/demo", Host: "resource.test"}, Token: hook.Token{Present: true, ProofValid: true, Sub: "sub", ClientID: "client", JKT: "bound-key", Aud: "resource", Scope: "report:summary"}, Tenant: &tenant}
}

func TestPolicyDefaultsToDenyAndDoesNotElevateSummary(t *testing.T) {
	p, err := New(testConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if d := p.Decide(validInput()); !d.Allow || d.RuleID != "m3-report-summary" || d.BundleRevision != "test-1" {
		t.Fatalf("valid summary refused: %+v", d)
	}
	for name, tc := range map[string]struct {
		change func(*hook.Input)
		rule   string
	}{
		"wrong source":          {func(i *hook.Input) { i.Source.SPIFFEID = "spiffe://wrong.test/ns/x/sa/y" }, RuleDefaultDeny},
		"wrong audience":        {func(i *hook.Input) { i.Token.Aud = "other" }, RuleDefaultDeny},
		"missing proof":         {func(i *hook.Input) { i.Token.ProofValid = false }, RuleDefaultDeny},
		"wrong path":            {func(i *hook.Input) { i.Request.Path = "/admin" }, RuleDefaultDeny},
		"wrong method":          {func(i *hook.Input) { i.Request.Method = "GET" }, RuleDefaultDeny},
		"wrong host":            {func(i *hook.Input) { i.Request.Host = "caller.invalid" }, RuleDefaultDeny},
		"no token":              {func(i *hook.Input) { i.Token = hook.Token{} }, RuleDefaultDeny},
		"no scope":              {func(i *hook.Input) { i.Token.Scope = "" }, RuleScopeRequired},
		"unknown scope":         {func(i *hook.Input) { i.Token.Scope = "report:admin" }, RuleScopeRequired},
		"blocked client":        {func(i *hook.Input) { i.Token.ClientID = "blocked-client" }, RuleClientBlocked},
		"full report route":     {func(i *hook.Input) { v := "read"; i.Tenant = &v }, RuleTenantRoute},
		"absent route":          {func(i *hook.Input) { i.Tenant = nil }, RuleTenantRoute},
		"presentation required": {func(i *hook.Input) { i.Token.Scope = "report:full report:summary" }, RulePresentationRequired},
	} {
		t.Run(name, func(t *testing.T) {
			in := validInput()
			tc.change(&in)
			d := p.Decide(in)
			if d.Allow || d.Validate() != nil || d.RuleID != tc.rule || d.BundleRevision != "test-1" {
				t.Fatalf("got %+v, want denial by %s", d, tc.rule)
			}
			want := hook.ReasonRuleDeny
			if tc.rule == RulePresentationRequired {
				want = hook.ReasonPresentationRequired
				if d.DenyBody.OID4VPLink != link {
					t.Fatal("presentation denial without the OID4VP link")
				}
			}
			if d.ReasonCode != want {
				t.Fatalf("reason %s, want %s", d.ReasonCode, want)
			}
		})
	}
}

func TestConfigurationRefused(t *testing.T) {
	for _, change := range []func(*Config){
		func(c *Config) { c.EventSource = "guard-b" },
		func(c *Config) { c.Presentation.OID4VPLink = "javascript:alert(1)" },
		func(c *Config) { c.Presentation.Scopes = nil },
		func(c *Config) { c.Presentation.Scopes = []string{"report:read"} },
	} {
		c := testConfig()
		p := *c.Presentation
		c.Presentation = &p
		change(&c)
		if _, err := New(c, nil); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
}

type sink struct {
	ids []string
	ps  []hook.EventPayload
}

func (s *sink) Emit(id string, p hook.EventPayload) { s.ids, s.ps = append(s.ids, id), append(s.ps, p) }

// TestEveryDecisionIsRecorded: each answered decision is one event under the guard's correlation
// id, with the rule id and bundle revision that decided it.
func TestEveryDecisionIsRecorded(t *testing.T) {
	events := &sink{}
	p, err := New(testConfig(), events)
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"report:summary", "report:full"} {
		in := validInput()
		in.Token.Scope = scope
		body, _ := json.Marshal(in)
		req := httptest.NewRequest(http.MethodPost, "/decision", bytes.NewReader(body))
		req.Header.Set("X-Forwarded-Client-Cert", "URI="+guardID)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d", rec.Code)
		}
	}
	if len(events.ps) != 2 || events.ids[0] != "corr-1" {
		t.Fatalf("events: %+v %+v", events.ids, events.ps)
	}
	allowed, denied := events.ps[0], events.ps[1]
	if allowed.State != "allowed" || allowed.RuleID != "m3-report-summary" || allowed.BundleRevision != "test-1" || allowed.CallerSPIFFEID != participant || allowed.TokenSubject != "sub" || allowed.Resource != "POST resource.test/demo" {
		t.Fatalf("allowed event: %+v", allowed)
	}
	if denied.State != "denied" || denied.ReasonCode != hook.ReasonPresentationRequired || denied.RuleID != RulePresentationRequired {
		t.Fatalf("denied event: %+v", denied)
	}
	if strings.Contains(denied.Detail, link) {
		t.Fatal("link copied into the event")
	}
}
