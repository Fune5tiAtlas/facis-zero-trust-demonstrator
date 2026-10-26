package authelia

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/dpoptest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
)

// The operator may provision both roles. A registration token limited to one
// audience cannot register the other role, even if its issuing client may do so.
func TestRegistrationAudienceCeiling(t *testing.T) {
	h := newHarness(t, nil)
	const inbound = "https://guard.facis.invalid"
	const upstream = "https://resource.facis.invalid"
	h.seedClient("registrar", true, []string{oauth2provider.RegistrationScope, resourceScope}, []string{h.registerURL, inbound, upstream})
	key := dpoptest.NewKey(t)
	issued := h.token("registrar", h.tokenProof(key), []string{oauth2provider.RegistrationScope, resourceScope}, h.registerURL+" "+inbound)
	if issued.status != http.StatusOK {
		t.Fatalf("registration token status %d", issued.status)
	}
	auth := registrarToken{token: issued.str("access_token"), key: key}
	for _, aud := range []string{upstream, inbound} {
		metadata := participantMetadata()
		metadata["audience"] = []string{aud}
		got := h.registerWith(auth, metadata)
		if aud == upstream {
			if got.status != http.StatusBadRequest {
				t.Fatalf("registration crossed audience ceiling: status %d", got.status)
			}
			continue
		}
		if got.status != http.StatusCreated {
			t.Fatalf("guard registration status %d", got.status)
		}
		for _, requested := range []string{upstream, inbound} {
			token := h.tokenWithSecret(got.str("client_id"), got.str("client_secret"), h.tokenProof(key), url.Values{"grant_type": {"client_credentials"}, "scope": {resourceScope}, "audience": {requested}})
			if requested == upstream && token.status != http.StatusBadRequest {
				t.Fatalf("client crossed grant ceiling: status %d", token.status)
			}
			if requested == inbound && token.status != http.StatusOK {
				t.Fatalf("guard grant status %d", token.status)
			}
		}
	}
}

// Test both roles with valid signed presentations. Cross-audience grant refusals
// must occur without consuming the allowed challenge or minting a token.
func TestVerifiedPresentationAudienceIsolation(t *testing.T) {
	h := newVPHarness(t, nil)
	const inbound = "https://guard.facis.invalid"
	const upstream = "https://resource.facis.invalid"
	for _, role := range []struct{ id, allowed, forbidden string }{{"participant", inbound, upstream}, {"store", upstream, inbound}} {
		t.Run(role.id, func(t *testing.T) {
			h.seedVPClient(role.id)
			client, err := h.stores.Clients.GetClient(t.Context(), role.id)
			if err != nil {
				t.Fatal(err)
			}
			client.Audience = []string{role.allowed}
			if err := h.stores.Clients.UpdateClient(t.Context(), client); err != nil {
				t.Fatal(err)
			}
			if got := h.challenge(role.id, url.Values{"audience": {role.forbidden}}); got.status != http.StatusBadRequest {
				t.Fatalf("cross-audience challenge status %d", got.status)
			}
			key := dpoptest.NewKey(t)
			challenge := h.newChallenge(role.id, role.allowed)
			forbidden := h.sign(verifiedOutcome(role.id, challenge, role.forbidden))
			before := h.signer.signed.Load()
			got := h.grant(role.id, h.tokenProof(key), forbidden, challenge, role.forbidden)
			if got.status != http.StatusBadRequest || h.signer.signed.Load() != before {
				t.Fatal("cross-audience grant was not refused before signing")
			}
			allowed := h.sign(verifiedOutcome(role.id, challenge, role.allowed))
			granted := h.grant(role.id, h.tokenProof(key), allowed, challenge, role.allowed)
			if granted.status != http.StatusOK {
				t.Fatalf("allowed grant status %d", granted.status)
			}
			// A workload token cannot act as the provisioning registrar.
			metadata := participantMetadata()
			metadata["audience"] = []string{role.forbidden}
			registered := h.registerWith(registrarToken{token: granted.str("access_token"), key: key}, metadata)
			if registered.status < 400 || registered.status >= 500 {
				t.Fatalf("workload registered another client: status %d", registered.status)
			}
			// Renewal uses a fresh challenge and retains the same audience restriction.
			renewal := h.newChallenge(role.id, role.allowed)
			renewed := h.grant(role.id, h.tokenProof(key), h.sign(verifiedOutcome(role.id, renewal, role.allowed)), renewal, role.allowed)
			if renewed.status != http.StatusOK {
				t.Fatalf("allowed renewal status %d", renewed.status)
			}
		})
	}
}
