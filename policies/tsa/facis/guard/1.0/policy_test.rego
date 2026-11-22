# Tests of policy.rego in OPA (scripts/verify-tsa-policy/rego-test.sh), the cases of the built-in
# evaluator's TestTenantMembership (services/policyevaluator/policy_test.go). Not packed into a bundle:
# the bundle carries policy.rego and data.json only.
package facis.guard

import future.keywords.if

member_a := "spiffe://zone-a.test/ns/tenant-a/sa/ztd-participant"

member_b := "spiffe://zone-a.test/ns/tenant-b/sa/ztd-participant"

untenanted := {
	"audience": "https://guard.facis.invalid",
	"host": "ztd-guard:8080",
	"participant_callers": [member_a, member_b],
	"scope_tenants": {"report:read": "report-read", "report:summary": "report-summary"},
	"withdrawn_scopes": [],
}

tenant_a := object.union(untenanted, {
	"scope_tenants": {"report:read": "tenant-a-read", "report:summary": "tenant-a-summary"},
	"tenant_members": {"tenant-a": [member_a]},
})

request(caller, target, route) := r if {
	base := {
		"correlation_id": "c",
		"source": {"spiffe_id": caller},
		"request": {"method": "POST", "path": "/demo", "host": "ztd-guard:8080"},
		"token": {"present": true, "sub": "s", "client_id": "c", "jkt": "j", "scope": "report:summary", "aud": "https://guard.facis.invalid", "proof_valid": true},
		"tenant": route,
	}
	r := object.union(base, {"target_tenant": target})
}

untargeted(caller, route) := object.remove(request(caller, "", route), ["target_tenant"])

decide(cfg, in) := d if {
	d := decision with input as in with data.config as cfg with data.bundle.revision as "t"
}

membership_denied(d) if {
	d.allow == false
	d.rule_id == "m3-tenant-membership"
	d.reason_code == "POL-RULE-DENY"
}

test_member_allowed if {
	d := decide(tenant_a, request(member_a, "tenant-a", "tenant-a-summary"))
	d.allow == true
	d.rule_id == "m3-report-summary"
}

test_other_tenants_caller_denied if {
	membership_denied(decide(tenant_a, request(member_b, "tenant-a", "tenant-a-summary")))
}

test_no_target_tenant_denied if {
	membership_denied(decide(tenant_a, untargeted(member_a, "tenant-a-summary")))
}

test_route_of_a_tenant_not_served_denied if {
	membership_denied(decide(tenant_a, request(member_a, "tenant-c", "tenant-a-summary")))
}

test_untenanted_policy_refuses_a_target_tenant if {
	membership_denied(decide(untenanted, request(member_a, "tenant-a", "report-summary")))
}

test_untenanted_policy_without_target_unchanged if {
	d := decide(untenanted, untargeted(member_a, "report-summary"))
	d.allow == true
	d.rule_id == "m3-report-summary"
}

test_member_on_the_full_route_not_allowed if {
	d := decide(tenant_a, request(member_a, "tenant-a", "tenant-a-read"))
	d.allow == false
	d.rule_id == "m3-default-deny"
}

test_unlisted_caller_is_default_deny if {
	d := decide(tenant_a, request("spiffe://zone-a.test/ns/x/sa/y", "tenant-a", "tenant-a-summary"))
	d.rule_id == "m3-default-deny"
}
