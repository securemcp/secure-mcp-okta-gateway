package auth

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/securemcp/securemcp-okta-gateway/logging"
)

type Client struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	JWKSURI                 string   `json:"jwks_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	RegistrationAccessToken string   `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string   `json:"registration_client_uri,omitempty"`
}

func (a *Auth) SaveClient(ctx context.Context, clientID string, client *Client) *AuthError {
	log := logging.FromContext(ctx).With(
		slog.String("auth", "SaveClient"),
	)
	clientJSON, err := json.Marshal(client)
	if err != nil {
		return &AuthError{
			AuthJsonError: AuthJsonError{
				Code:        ServerError,
				Description: "Failed to marshal client",
			},
		}
	}

	if err := a.clientKVS.Set(ctx, clientID, clientJSON); err != nil {
		return &AuthError{
			AuthJsonError: AuthJsonError{
				Code:        ServerError,
				Description: "Failed to save client",
			},
		}
	}

	log.Info("Saved client", "client_id", clientID)
	return nil
}

func (a *Auth) GetClient(ctx context.Context, clientID string) (*Client, *AuthError) {
	if clientID == "" {
		return nil, &AuthError{
			AuthJsonError: AuthJsonError{
				Code:        InvalidRequest,
				Description: "client_id is required",
			},
		}
	}

	clientJSON, err := a.clientKVS.Get(ctx, clientID)
	if err != nil {
		return nil, &AuthError{
			AuthJsonError: AuthJsonError{
				Code:        ServerError,
				Description: "Failed to get client",
			},
		}
	}

	var client Client
	if err := json.Unmarshal([]byte(clientJSON), &client); err != nil {
		return nil, &AuthError{
			AuthJsonError: AuthJsonError{
				Code:        ServerError,
				Description: "Failed to unmarshal client",
			},
		}
	}
	return &client, nil
}
