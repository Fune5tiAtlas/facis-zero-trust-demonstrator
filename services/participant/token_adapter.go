package participant

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Token mode reasons. 401, 403 and 503 from the Resource each have their own name; the body of those
// answers is not trusted or forwarded.
const (
	ReasonTokenSessionNotReady     = "TOKEN_SESSION_NOT_READY"
	ReasonTokenAuthorizeFailed     = "TOKEN_AUTHORIZE_FAILED"
	ReasonTokenRejected            = "TOKEN_REJECTED"
	ReasonTokenForbidden           = "TOKEN_FORBIDDEN"
	ReasonTokenResourceUnavailable = "TOKEN_RESOURCE_UNAVAILABLE"
	ReasonTokenCredentialEchoed    = "TOKEN_CREDENTIAL_ECHOED"
)

// tokenExplanations replaces every Resource explanation in token mode: upstream text is never forwarded.
var tokenExplanations = map[string]string{
	"RESOURCE_REPORT_RETURNED":      "The Resource returned the report for the token's scopes.",
	"RESOURCE_SUMMARY_RETURNED":     "The Resource returned the report summary for the token's scopes.",
	"RESOURCE_SCENARIO_NOT_ALLOWED": "The Resource refused a sample scenario in token mode.",
	"RESOURCE_IDENTITY_MISSING":     "The Resource could not read the verified caller identity.",
}

const tokenFallbackExplanation = "The Resource answered with the documented result named by reasonCode."

// TokenAdapter calls the Resource with credentials from the lifecycle's TokenSession. It asks the
// session for a fresh Authorization and DPoP pair on every call and keeps neither.
type TokenAdapter struct {
	endpoint string
	client   *http.Client
	session  func() TokenSession
}

func NewTokenAdapter(resourceURL string, client *http.Client, session func() TokenSession) *TokenAdapter {
	base := NewHTTPSampleAdapter(resourceURL, client)
	return &TokenAdapter{endpoint: base.endpoint, client: base.client, session: session}
}

func (a *TokenAdapter) Request(ctx context.Context, request AdapterRequest) (*AdapterResult, error) {
	session := a.session()
	if session == nil {
		return tokenResult(OutcomeUnavailable, ReasonTokenSessionNotReady, "The Participant has no token session yet; see GET /state."), nil
	}
	request.Scenario = "" // scenarios are sample-mode only
	body, err := json.Marshal(DemoRequest(request))
	if err != nil {
		return nil, fmt.Errorf("encode protected resource request: %w", err)
	}
	authorization, proof, err := session.Authorize(ctx, http.MethodPost, a.endpoint)
	if err != nil {
		// The error text may carry upstream detail; only the fixed reason leaves this function.
		return tokenResult(OutcomeError, ReasonTokenAuthorizeFailed, "The token session could not authorize the request."), nil
	}
	outbound, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build protected resource request: %w", err)
	}
	outbound.Header.Set("Content-Type", "application/json")
	outbound.Header.Set("Accept", "application/json")
	outbound.Header.Set("Authorization", authorization)
	outbound.Header.Set("DPoP", proof)

	response, err := a.client.Do(outbound)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()

	switch response.StatusCode {
	case http.StatusUnauthorized:
		return tokenResult(OutcomeDenied, ReasonTokenRejected, "The Resource rejected the token or its proof."), nil
	case http.StatusForbidden:
		return tokenResult(OutcomeDenied, ReasonTokenForbidden, "The Resource refused the request for the token's scopes."), nil
	case http.StatusServiceUnavailable:
		return tokenResult(OutcomeUnavailable, ReasonTokenResourceUnavailable, "The Resource could not verify tokens or was unavailable."), nil
	}
	raw, err := readResourceBody(response)
	if err != nil {
		return nil, err
	}
	if echoesCredential(raw, authorization, proof) {
		return tokenResult(OutcomeError, ReasonTokenCredentialEchoed, "The Resource answer contained this request's credentials and was discarded."), nil
	}
	result, err := decodeResourceBody(response.StatusCode, raw, request, ModeToken)
	if err != nil {
		return nil, err
	}
	result.Explanation = tokenFallbackExplanation
	if text, ok := tokenExplanations[result.ReasonCode]; ok {
		result.Explanation = text
	}
	return result, nil
}

// echoesCredential reports whether the answer carries the Authorization value, the bare token or the
// DPoP proof, either raw or inside any JSON string (which may hide it behind escapes).
func echoesCredential(raw []byte, authorization, proof string) bool {
	secrets := []string{authorization, proof}
	if _, token, ok := strings.Cut(authorization, " "); ok {
		secrets = append(secrets, token)
	}
	texts := []string{string(raw)}
	var decoded any
	if json.Unmarshal(raw, &decoded) == nil {
		texts = appendStrings(texts, decoded)
	}
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		for _, text := range texts {
			if strings.Contains(text, secret) {
				return true
			}
		}
	}
	return false
}

func appendStrings(out []string, value any) []string {
	switch v := value.(type) {
	case string:
		out = append(out, v)
	case []any:
		for _, item := range v {
			out = appendStrings(out, item)
		}
	case map[string]any:
		for key, item := range v {
			out = appendStrings(append(out, key), item)
		}
	}
	return out
}

func tokenResult(outcome Outcome, reason, explanation string) *AdapterResult {
	return &AdapterResult{Outcome: outcome, ReasonCode: reason, Explanation: explanation, SafeData: emptySafeData()}
}
