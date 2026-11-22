// Package policyevaluator serves a deny-default IF-05 rule set for the M3 resource.
//
// Decide is the rule source: one input in, one decision out carrying the rule id that decided and
// the bundle revision. ServeHTTP authenticates the guard, calls Decide and writes the IF-01 v2
// decision event; a different rule source (for example policy bundles) replaces Decide only.
package policyevaluator

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/meshcaller"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/policyhook/hook"
)

// Rule ids, one per reason a decision can have.
const (
	RuleDefaultDeny          = "m3-default-deny"
	RuleScopeRequired        = "m3-scope-required"
	RuleClientBlocked        = "m3-client-blocked"
	RulePresentationRequired = "m3-presentation-required"
	RuleTenantRoute          = "m3-tenant-route"
	RuleTenantMembership     = "m3-tenant-membership"
)

type Config struct {
	Revision           string            `json:"revision"`
	Audience           string            `json:"audience"`
	Host               string            `json:"host"`
	GuardCallers       []string          `json:"guard_callers"`
	ParticipantCallers []string          `json:"participant_callers"`
	ScopeTenants       map[string]string `json:"scope_tenants"`
	// EventSource names this evaluator on the IF-01 feed: policy-a or policy-b.
	EventSource string `json:"event_source"`
	// BlockedClients are clients denied by rule whatever their token says.
	BlockedClients []string `json:"blocked_clients,omitempty"`
	// Presentation, when set, denies a token carrying one of its scopes until the caller presents
	// a credential, answering with the OID4VP link.
	Presentation *Presentation `json:"presentation,omitempty"`
	// TenantMembers, when set, names the callers that are members of each tenant: a request is
	// allowed only for a member of the target tenant the guard's route names. Configured, a request
	// without a target tenant is denied; unconfigured, so is one with a target tenant.
	TenantMembers map[string][]string `json:"tenant_members,omitempty"`
}

// tenantName is a tenant as the contracts name it: a Kubernetes namespace name.
var tenantName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

type Presentation struct {
	Scopes     []string `json:"scopes"`
	OID4VPLink string   `json:"oid4vp_link"`
}

type Policy struct {
	cfg     Config
	callers *meshcaller.XFCC
	events  hook.EventSink
}

// New returns the evaluator. events may be nil.
func New(cfg Config, events hook.EventSink) (*Policy, error) {
	if cfg.Revision == "" || cfg.Audience == "" || cfg.Host == "" || len(cfg.GuardCallers) == 0 || len(cfg.ParticipantCallers) == 0 || cfg.ScopeTenants["report:read"] == "" || cfg.ScopeTenants["report:summary"] == "" || cfg.ScopeTenants["report:read"] == cfg.ScopeTenants["report:summary"] {
		return nil, errors.New("policy configuration incomplete")
	}
	if cfg.EventSource != "policy-a" && cfg.EventSource != "policy-b" {
		return nil, errors.New("policy event_source must be policy-a or policy-b")
	}
	if p := cfg.Presentation; p != nil {
		link, err := url.Parse(p.OID4VPLink)
		if len(p.Scopes) == 0 || err != nil || (link.Scheme != "https" && link.Scheme != "openid4vp") || len(p.OID4VPLink) > 2048 {
			return nil, errors.New("policy presentation needs scopes and an https or openid4vp link")
		}
		for _, s := range p.Scopes {
			if _, ok := cfg.ScopeTenants[s]; ok || s == "" {
				return nil, errors.New("a presentation scope cannot also select a tenant")
			}
		}
	}
	for tenant, members := range cfg.TenantMembers {
		if !tenantName.MatchString(tenant) || len(members) == 0 || slices.ContainsFunc(members, func(m string) bool { return !slices.Contains(cfg.ParticipantCallers, m) }) {
			return nil, errors.New("policy tenant_members needs namespace-named tenants whose members are participant callers")
		}
	}
	auth, err := meshcaller.NewXFCC(cfg.GuardCallers)
	if err != nil {
		return nil, err
	}
	if _, err = meshcaller.NewXFCC(cfg.ParticipantCallers); err != nil {
		return nil, err
	}
	return &Policy{cfg: cfg, callers: auth, events: events}, nil
}

func (p *Policy) deny(rule string) hook.Decision {
	return hook.Decision{Allow: false, ReasonCode: hook.ReasonRuleDeny, RuleID: rule, BundleRevision: p.cfg.Revision, DenyBody: &hook.DenyBody{Error: "access_denied"}}
}

// Decide answers one input. The checks run from the request's shape to the caller's entitlement,
// so insufficient scope (RuleScopeRequired) is never reported for a request a rule refuses anyway.
func (p *Policy) Decide(in hook.Input) hook.Decision {
	if !slices.Contains(p.cfg.ParticipantCallers, in.Source.SPIFFEID) || in.Request.Method != http.MethodPost || in.Request.Path != "/demo" || in.Request.Host != p.cfg.Host || !in.Token.Present || !in.Token.ProofValid || in.Token.Aud != p.cfg.Audience || in.Token.Sub == "" || in.Token.ClientID == "" || in.Token.JKT == "" {
		return p.deny(RuleDefaultDeny)
	}
	// Membership of the target tenant is decided here, from this policy's configuration: the guard
	// names the tenant of its route, never which callers belong to it.
	if (in.TargetTenant != "" || len(p.cfg.TenantMembers) > 0) && !slices.Contains(p.cfg.TenantMembers[in.TargetTenant], in.Source.SPIFFEID) {
		return p.deny(RuleTenantMembership)
	}
	if slices.Contains(p.cfg.BlockedClients, in.Token.ClientID) {
		return p.deny(RuleClientBlocked)
	}
	scopes := strings.Fields(in.Token.Scope)
	if pr := p.cfg.Presentation; pr != nil && slices.ContainsFunc(scopes, func(s string) bool { return slices.Contains(pr.Scopes, s) }) {
		return hook.Decision{Allow: false, ReasonCode: hook.ReasonPresentationRequired, RuleID: RulePresentationRequired, BundleRevision: p.cfg.Revision,
			DenyBody: &hook.DenyBody{Error: "presentation_required", OID4VPLink: pr.OID4VPLink}}
	}
	// A summary identity must select a summary-only acquisition route, never a full-report token.
	for _, scope := range []string{"report:read", "report:summary"} {
		if slices.Contains(scopes, scope) {
			if in.Tenant == nil || *in.Tenant != p.cfg.ScopeTenants[scope] {
				return p.deny(RuleTenantRoute)
			}
			return hook.Decision{Allow: true, RuleID: "m3-" + strings.ReplaceAll(scope, ":", "-"), BundleRevision: p.cfg.Revision, Obligations: []string{hook.ObligationSubstituteUpstreamToken}}
		}
	}
	return p.deny(RuleScopeRequired)
}

func (p *Policy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.URL.Path != "/decision" || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	if _, err := p.callers.Authenticate(r); err != nil {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	var in hook.Input
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024))
	dec.DisallowUnknownFields()
	if dec.Decode(&in) != nil || dec.Decode(&struct{}{}) != io.EOF {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	decision := p.Decide(in)
	p.record(in, decision)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(decision)
}

// record writes the decision event under the guard's correlation id. Caller-controlled strings
// are bounded or replaced so the event always satisfies its schema.
func (p *Policy) record(in hook.Input, d hook.Decision) {
	if p.events == nil {
		return
	}
	e := hook.EventPayload{State: "allowed", RuleID: d.RuleID, BundleRevision: d.BundleRevision, CallerSPIFFEID: bounded(in.Source.SPIFFEID, "spiffe://"),
		Resource: "UNKNOWN " + p.cfg.Host + "/"}
	if tenantName.MatchString(in.TargetTenant) {
		e.Tenant = in.TargetTenant
	}
	if !d.Allow {
		e.State, e.ReasonCode = "denied", d.ReasonCode
	}
	if in.Token.Present {
		e.TokenSubject = bounded(in.Token.Sub, "")
	}
	if slices.Contains([]string{http.MethodPost, http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch}, in.Request.Method) && in.Request.Host == p.cfg.Host && in.Request.Path == "/demo" {
		e.Resource = in.Request.Method + " " + p.cfg.Host + in.Request.Path
	}
	id := in.CorrelationID
	if len(id) > 128 || strings.IndexFunc(id, func(c rune) bool { return c <= ' ' || c > '~' }) >= 0 {
		id = ""
	}
	p.events.Emit(id, e)
}

// spiffeID is the v2 event schema's pattern for caller_spiffe_id.
var spiffeID = regexp.MustCompile(`^spiffe://[a-z0-9._-]+(/[A-Za-z0-9._~%!$&'()*+,;=:@-]+)+$`)

func bounded(v, prefix string) string {
	if prefix != "" && !spiffeID.MatchString(v) {
		return ""
	}
	if v == "" || len(v) > 256 || strings.IndexFunc(v, func(c rune) bool { return c <= ' ' || c > '~' }) >= 0 || v == hook.NotEvaluated {
		return ""
	}
	return v
}
