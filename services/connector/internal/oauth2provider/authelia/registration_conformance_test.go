package authelia

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/dpoptest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
)

// seedRegistrar provisions the client that is allowed to register others and
// returns a token for the registration endpoint.
func seedRegistrar(t *testing.T, h *harness) string {
	t.Helper()

	scopes := []string{oauth2provider.RegistrationScope, resourceScope}
	h.seedClient("registrar", false, scopes, []string{h.registerURL})

	issued := h.token("registrar", "", scopes, h.registerURL)
	if issued.status != http.StatusOK {
		t.Fatalf("registrar token: status %d, body %v", issued.status, issued.body)
	}

	return issued.str("access_token")
}

func participantMetadata() map[string]any {
	return map[string]any{
		"client_name":                "participant backend",
		"grant_types":                []string{"client_credentials"},
		"token_endpoint_auth_method": "client_secret_basic",
		"scope":                      resourceScope,
		"dpop_bound_access_tokens":   true,
	}
}

// Registration is not open. It takes an access token, issued by the token
// endpoint like any other, that names the registration endpoint as its
// audience and carries the registration scope.
func TestRegistration_RequiresAnAuthorisedToken(t *testing.T) {
	h := newHarness(t, nil)
	registrarToken := seedRegistrar(t, h)

	anonymous := h.register("", participantMetadata())
	if anonymous.status != http.StatusUnauthorized || anonymous.reason() != oauth2provider.CodeInvalidToken {
		t.Errorf("no token: status %d reason %q, want 401 %q", anonymous.status, anonymous.reason(), oauth2provider.CodeInvalidToken)
	}

	forged := h.register("Bearer connector_at_forged", participantMetadata())
	if forged.status != http.StatusUnauthorized || forged.reason() != oauth2provider.CodeInvalidToken {
		t.Errorf("forged token: status %d reason %q, want 401 %q", forged.status, forged.reason(), oauth2provider.CodeInvalidToken)
	}

	// A valid token for the right audience but without the registration scope.
	unscoped := h.token("registrar", "", []string{resourceScope}, h.registerURL)
	if unscoped.status != http.StatusOK {
		t.Fatalf("unscoped token: status %d, body %v", unscoped.status, unscoped.body)
	}

	refused := h.register("Bearer "+unscoped.str("access_token"), participantMetadata())
	if refused.status != http.StatusForbidden || refused.reason() != oauth2provider.CodeInsufficientScope {
		t.Errorf("unscoped token: status %d reason %q, want 403 %q", refused.status, refused.reason(), oauth2provider.CodeInsufficientScope)
	}

	registered := h.register("Bearer "+registrarToken, participantMetadata())
	if registered.status != http.StatusCreated {
		t.Fatalf("authorised token: status %d, body %v", registered.status, registered.body)
	}

	if registered.str("client_id") == "" || registered.str("client_secret") == "" {
		t.Errorf("registration response lacks credentials: %v", registered.body)
	}
}

// A participant backend registers itself and, with the credentials it is
// handed, obtains a token bound to its own key - with no operator involved.
func TestRegistration_RegisteredClientObtainsBoundToken(t *testing.T) {
	h := newHarness(t, nil)

	registered := h.register("Bearer "+seedRegistrar(t, h), participantMetadata())
	if registered.status != http.StatusCreated {
		t.Fatalf("registration: status %d, body %v", registered.status, registered.body)
	}

	if bound, _ := registered.body["dpop_bound_access_tokens"].(bool); !bound {
		t.Errorf("dpop_bound_access_tokens was not retained: %v", registered.body)
	}

	clientID, secret := registered.str("client_id"), registered.str("client_secret")
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {resourceScope}}

	withoutProof := h.tokenWithSecret(clientID, secret, "", form)
	if withoutProof.status == http.StatusOK {
		t.Fatal("the registered client obtained a token without a proof")
	}

	key := dpoptest.NewKey(t)

	issued := h.tokenWithSecret(clientID, secret, h.tokenProof(key), form)
	if issued.status != http.StatusOK || issued.str("token_type") != "DPoP" {
		t.Fatalf("token: status %d token_type %q body %v, want 200 DPoP", issued.status, issued.str("token_type"), issued.body)
	}

	token := issued.str("access_token")
	proof := dpoptest.Mint(t, key, dpoptest.Proof{Method: http.MethodGet, URL: h.resourceURL, AccessToken: token})

	accessed := h.resource("DPoP "+token, proof)
	if accessed.status != http.StatusOK || accessed.str("client_id") != clientID {
		t.Fatalf("resource: status %d body %v, want 200 for client %q", accessed.status, accessed.body, clientID)
	}
}

// The secret is returned to the registrant once and only its hash is kept.
func TestRegistration_SecretIsStoredHashed(t *testing.T) {
	h := newHarness(t, nil)

	registered := h.register("Bearer "+seedRegistrar(t, h), participantMetadata())
	if registered.status != http.StatusCreated {
		t.Fatalf("registration: status %d, body %v", registered.status, registered.body)
	}

	stored, err := h.stores.Clients.GetClient(t.Context(), registered.str("client_id"))
	if err != nil {
		t.Fatalf("stored client: %v", err)
	}

	if len(stored.SecretHash) == 0 || string(stored.SecretHash) == registered.str("client_secret") {
		t.Error("the client secret was not stored as a hash")
	}

	if wrong := h.tokenWithSecret(stored.ID, "not-the-secret", h.tokenProof(dpoptest.NewKey(t)), url.Values{"grant_type": {"client_credentials"}}); wrong.reason() != oauth2provider.CodeInvalidClient {
		t.Errorf("wrong secret: reason %q, want %q", wrong.reason(), oauth2provider.CodeInvalidClient)
	}
}

// A registrant cannot grant itself more than the registrar's token allows,
// nor a grant type the deployment does not offer.
func TestRegistration_CannotExceedTheRegistrar(t *testing.T) {
	testCases := []struct {
		name   string
		member string
		value  any
	}{
		{"scope beyond the registrar's", "scope", resourceScope + " admin"},
		{"the registration scope itself", "scope", oauth2provider.RegistrationScope},
		{"grant type not offered", "grant_types", []string{"password"}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, nil)

			metadata := participantMetadata()
			metadata[tc.member] = tc.value

			got := h.register("Bearer "+seedRegistrar(t, h), metadata)
			if got.status != http.StatusBadRequest || got.reason() != oauth2provider.CodeRegistrationRejected {
				t.Fatalf("status %d reason %q body %v, want 400 %q", got.status, got.reason(), got.body, oauth2provider.CodeRegistrationRejected)
			}
		})
	}
}
