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

// TestTenantMembership: with tenants configured, a request is allowed only for a member of the
// target tenant the guard's route names, in both directions; the event carries that tenant. Scope
// separation still holds inside a tenant.
func TestTenantMembership(t *testing.T) {
	const memberA, memberB = "spiffe://zone-a.test/ns/tenant-a/sa/ztd-participant", "spiffe://zone-a.test/ns/tenant-b/sa/ztd-participant"
	for _, own := range []struct{ tenant, member, other string }{{"tenant-a", memberA, memberB}, {"tenant-b", memberB, memberA}} {
		c := testConfig()
		c.ParticipantCallers = []string{memberA, memberB}
		c.TenantMembers = map[string][]string{own.tenant: {own.member}}
		c.ScopeTenants = map[string]string{"report:read": own.tenant + "-read", "report:summary": own.tenant + "-summary"}
		events := &sink{}
		p, err := New(c, events)
		if err != nil {
			t.Fatal(err)
		}
		in := validInput()
		route := own.tenant + "-summary"
		in.Tenant, in.TargetTenant, in.Source.SPIFFEID = &route, own.tenant, own.member
		if d := p.Decide(in); !d.Allow || d.RuleID != "m3-report-summary" {
			t.Fatalf("%s member refused: %+v", own.tenant, d)
		}
		for name, change := range map[string]func(*hook.Input){
			"other tenant's caller":        func(i *hook.Input) { i.Source.SPIFFEID = own.other },
			"no target tenant":             func(i *hook.Input) { i.TargetTenant = "" },
			"route of a tenant not served": func(i *hook.Input) { i.TargetTenant = "tenant-c" },
		} {
			bad := in
			change(&bad)
			if d := p.Decide(bad); d.Allow || d.RuleID != RuleTenantMembership || d.ReasonCode != hook.ReasonRuleDeny {
				t.Fatalf("%s %s: got %+v", own.tenant, name, d)
			}
		}
		// Scope separation inside the tenant: a summary token never selects the full-report route.
		full := own.tenant + "-read"
		in.Tenant = &full
		if d := p.Decide(in); d.Allow || d.RuleID != RuleTenantRoute {
			t.Fatalf("%s summary token on the full route: %+v", own.tenant, d)
		}
		cross := in
		cross.Source.SPIFFEID, cross.Tenant = own.other, &route
		p.record(cross, p.Decide(cross))
		if e := events.ps[len(events.ps)-1]; e.Tenant != own.tenant || e.RuleID != RuleTenantMembership || e.State != "denied" || e.CallerSPIFFEID != own.other {
			t.Fatalf("%s cross-tenant event: %+v", own.tenant, e)
		}
	}
	// A target tenant reaching a policy that serves no tenant is denied, not ignored.
	p, _ := New(testConfig(), nil)
	in := validInput()
	in.TargetTenant = "tenant-a"
	if d := p.Decide(in); d.Allow || d.RuleID != RuleTenantMembership {
		t.Fatalf("untenanted policy accepted a target tenant: %+v", d)
	}
	for _, members := range []map[string][]string{{"Tenant A": {participant}}, {"tenant-a": nil}, {"tenant-a": {"spiffe://zone-a.test/ns/x/sa/not-a-caller"}}} {
		c := testConfig()
		c.TenantMembers = members
		if _, err := New(c, nil); err == nil {
			t.Fatalf("tenant_members %v accepted", members)
		}
	}
}
