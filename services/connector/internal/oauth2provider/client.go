package oauth2provider

import "encoding/json"

// Client is a registered OAuth 2.0 client as the connector persists it.
type Client struct {
	ID string

	// SecretHash is the bcrypt hash of the client secret. The plaintext is
	// never stored.
	SecretHash []byte

	GrantTypes []string
	Scopes     []string
	Audience   []string

	// DPoPBound is the dpop_bound_access_tokens client metadata value.
	DPoPBound bool

	// Metadata is the RFC 7591 client metadata document of a dynamically
	// registered client. It is nil for clients provisioned by other means.
	Metadata json.RawMessage
}
