package authelia

import (
	"net/http"
	"testing"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/dpoptest"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
)

func TestResource_BoundKeyIsAccepted(t *testing.T) {
	h := newHarness(t, nil)
	key := dpoptest.NewKey(t)
	token := h.boundToken(key)

	proof := dpoptest.Mint(t, key, dpoptest.Proof{Method: http.MethodGet, URL: h.resourceURL, AccessToken: token})

	got := h.resource("DPoP "+token, proof)
	if got.status != http.StatusOK {
		t.Fatalf("status = %d, body %v", got.status, got.body)
	}

	if got.str("client_id") != "participant" {
		t.Errorf("client_id = %q, want participant", got.str("client_id"))
	}
}

// A stolen token is useless without the key it is bound to.
func TestResource_OtherKeyIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	token := h.boundToken(dpoptest.NewKey(t))

	thief := dpoptest.NewKey(t)
	proof := dpoptest.Mint(t, thief, dpoptest.Proof{Method: http.MethodGet, URL: h.resourceURL, AccessToken: token})

	got := h.resource("DPoP "+token, proof)
	if got.status != http.StatusUnauthorized || got.reason() != oauth2provider.CodeDPoPKeyMismatch {
		t.Fatalf("status %d reason %q, want 401 %q", got.status, got.reason(), oauth2provider.CodeDPoPKeyMismatch)
	}
}

// The right key is not enough: the proof must also be made for this token.
func TestResource_AccessTokenHash(t *testing.T) {
	testCases := []struct {
		name  string
		proof func(token string) dpoptest.Proof
	}{
		{"missing", func(string) dpoptest.Proof { return dpoptest.Proof{} }},
		{"wrong", func(string) dpoptest.Proof {
			return dpoptest.Proof{ATH: dpoptest.AccessTokenHash("some-other-token")}
		}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, nil)
			key := dpoptest.NewKey(t)
			token := h.boundToken(key)

			spec := tc.proof(token)
			spec.Method, spec.URL = http.MethodGet, h.resourceURL

			got := h.resource("DPoP "+token, dpoptest.Mint(t, key, spec))
			if got.status != http.StatusUnauthorized || got.reason() != oauth2provider.CodeDPoPInvalidATH {
				t.Fatalf("status %d reason %q, want 401 %q", got.status, got.reason(), oauth2provider.CodeDPoPInvalidATH)
			}
		})
	}
}

// A bound token must not be usable as a bearer token, with or without a
// proof alongside it.
func TestResource_BearerSchemeIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	key := dpoptest.NewKey(t)
	token := h.boundToken(key)

	proof := dpoptest.Mint(t, key, dpoptest.Proof{Method: http.MethodGet, URL: h.resourceURL, AccessToken: token})

	for name, presented := range map[string]string{"without proof": "", "with proof": proof} {
		t.Run(name, func(t *testing.T) {
			got := h.resource("Bearer "+token, presented)
			if got.status != http.StatusUnauthorized || got.reason() != oauth2provider.CodeInvalidToken {
				t.Fatalf("status %d reason %q, want 401 %q", got.status, got.reason(), oauth2provider.CodeInvalidToken)
			}
		})
	}
}

func TestResource_MissingProofIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	token := h.boundToken(dpoptest.NewKey(t))

	got := h.resource("DPoP "+token, "")
	if got.status != http.StatusUnauthorized || got.reason() != oauth2provider.CodeDPoPInvalidProof {
		t.Fatalf("status %d reason %q, want 401 %q", got.status, got.reason(), oauth2provider.CodeDPoPInvalidProof)
	}
}

func TestResource_UnknownTokenIsRefused(t *testing.T) {
	h := newHarness(t, nil)
	key := dpoptest.NewKey(t)

	proof := dpoptest.Mint(t, key, dpoptest.Proof{Method: http.MethodGet, URL: h.resourceURL, AccessToken: "connector_at_unknown"})

	got := h.resource("DPoP connector_at_unknown", proof)
	if got.status != http.StatusUnauthorized || got.reason() != oauth2provider.CodeInvalidToken {
		t.Fatalf("status %d reason %q, want 401 %q", got.status, got.reason(), oauth2provider.CodeInvalidToken)
	}
}
