package authelia

import (
	"context"
	"encoding/json"
	"fmt"

	"authelia.com/provider/oauth2"
	"golang.org/x/crypto/bcrypt"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/connector/internal/oauth2provider"
)

// toLibraryClient rebuilds the library's view of a persisted client. A
// dynamically registered client is rebuilt from its RFC 7591 metadata
// document, so nothing the registration strategy derived from it is lost.
func toLibraryClient(ctx context.Context, strategy oauth2.ClientRegistrationStrategy, client oauth2provider.Client) (oauth2.Client, error) {
	var secret oauth2.ClientSecret
	if len(client.SecretHash) != 0 {
		secret = oauth2.NewBCryptClientSecret(string(client.SecretHash))
	}

	if len(client.Metadata) == 0 {
		return &oauth2.DefaultClient{
			ID:                    client.ID,
			ClientSecret:          secret,
			GrantTypes:            client.GrantTypes,
			Scopes:                client.Scopes,
			Audience:              client.Audience,
			DPoPBoundAccessTokens: client.DPoPBound,
		}, nil
	}

	var metadata *oauth2.ClientRegistrationMetadata
	if err := json.Unmarshal(client.Metadata, &metadata); err != nil {
		return nil, fmt.Errorf("decode client metadata: %w", err)
	}

	return strategy.NewClient(ctx, client.ID, secret, metadata)
}

// fromLibraryClient converts a client the library asks us to persist. The
// secret is hashed here: the plaintext the registration handler generated is
// returned to the registrant once and never stored.
//
// existing is the currently persisted record when the client is being
// updated. An update that does not rotate the secret hands back the hashed
// secret, which cannot be hashed again, so the stored hash is kept.
func fromLibraryClient(ctx context.Context, strategy oauth2.ClientRegistrationStrategy, client oauth2.Client, existing *oauth2provider.Client) (oauth2provider.Client, error) {
	record := oauth2provider.Client{
		ID:         client.GetID(),
		GrantTypes: client.GetGrantTypes(),
		Scopes:     client.GetScopes(),
		Audience:   client.GetAudience(),
	}

	if dpop, ok := client.(oauth2.DPoPClient); ok {
		record.DPoPBound = dpop.GetEnableDPoPBoundAccessTokens()
	}

	if secret := client.GetClientSecret(); secret != nil && secret.Valid() {
		switch {
		case secret.IsPlainText():
			hash, err := hashSecret(secret)
			if err != nil {
				return oauth2provider.Client{}, err
			}

			record.SecretHash = hash
		case existing != nil:
			record.SecretHash = existing.SecretHash
		default:
			return oauth2provider.Client{}, fmt.Errorf("client secret is not available in a form that can be hashed")
		}
	}

	metadata, err := strategy.MetadataFromClient(ctx, client)
	if err != nil {
		return oauth2provider.Client{}, fmt.Errorf("render client metadata: %w", err)
	}

	if record.Metadata, err = json.Marshal(metadata); err != nil {
		return oauth2provider.Client{}, fmt.Errorf("encode client metadata: %w", err)
	}

	return record, nil
}

func hashSecret(secret oauth2.ClientSecret) ([]byte, error) {
	plain, err := secret.GetPlainTextValue()
	if err != nil {
		return nil, fmt.Errorf("read client secret: %w", err)
	}

	return bcrypt.GenerateFromPassword(plain, bcrypt.DefaultCost)
}
