package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/jose"
)

// checkIssuerSeparation compares public material, including every active store
// version and every published issuer key. Readiness fails closed on an unavailable
// or malformed set. Redirects cannot move this trust check to another endpoint.
func (s *Server) checkIssuerSeparation(ctx context.Context, storeKeys map[string]bool) string {
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	seen := map[string]bool{}
	for _, route := range s.cfg.Acquisition.Routes {
		endpoint := strings.TrimRight(route.ConnectorURL, "/") + "/.well-known/jwks.json"
		if seen[endpoint] {
			continue
		}
		seen[endpoint] = true
		state := issuerKeyState(ctx, client, endpoint, storeKeys)
		if state != checkOK {
			return state
		}
	}
	return checkOK
}

func issuerKeyState(ctx context.Context, client *http.Client, endpoint string, storeKeys map[string]bool) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return checkUnreachable
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return checkUnreachable
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return checkUnreachable
	}
	const limit = 64 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil || len(body) > limit {
		return checkUnreachable
	}
	object, err := jose.ParseObject(body)
	if err != nil {
		return checkUnreachable
	}
	var entries []json.RawMessage
	if json.Unmarshal(object["keys"], &entries) != nil || len(entries) == 0 {
		return checkUnreachable
	}
	for _, raw := range entries {
		members, err := jose.ParseObject(raw)
		if err != nil {
			return checkUnreachable
		}
		if _, private := members["d"]; private {
			return checkUnreachable
		}
		var key jose.JWK
		if json.Unmarshal(raw, &key) != nil {
			return checkUnreachable
		}
		thumbprint, err := key.Thumbprint()
		if err != nil {
			return checkUnreachable
		}
		if storeKeys[thumbprint] {
			return checkMismatch
		}
	}
	return checkOK
}
