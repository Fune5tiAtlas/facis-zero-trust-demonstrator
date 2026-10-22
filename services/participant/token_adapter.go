package participant

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// Token mode reasons. 401, 403 and 503 from the Resource each have their own name; the body of those
// answers is not trusted or forwarded.
const (
	ReasonTokenSessionNotReady     = "TOKEN_SESSION_NOT_READY"
	ReasonTokenAuthorizeFailed     = "TOKEN_AUTHORIZE_FAILED"
	ReasonTokenRejected            = "TOKEN_REJECTED"
	ReasonTokenForbidden           = "TOKEN_FORBIDDEN"
	ReasonTokenResourceUnavailable = "TOKEN_RESOURCE_UNAVAILABLE"
)

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
	return decodeResourceResponse(response, request, ModeToken)
}

func tokenResult(outcome Outcome, reason, explanation string) *AdapterResult {
	return &AdapterResult{Outcome: outcome, ReasonCode: reason, Explanation: explanation, SafeData: emptySafeData()}
}
