// Package oauth2provider is the connector's own contract for its OAuth 2.0
// authorization surface: dynamic client registration (RFC 7591) and
// DPoP-bound access tokens (RFC 9449).
//
// The package declares the types, storage interfaces and reason codes the
// rest of the connector programs against. It deliberately imports no
// third-party OAuth 2.0 library: a concrete implementation lives in a
// subpackage (see the authelia subpackage) and is the only place such a
// library may be imported. That boundary is enforced by a test.
//
// The API is unstable and subject to change.
package oauth2provider
