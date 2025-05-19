package auth

import (
	"context"
	"encoding/json"
)

func (a *Auth) StoreAuthorization(ctx context.Context, sid string, authorization *AuthorizationParams) *AuthError {
	authorizationJSON, err := json.Marshal(authorization)
	if err != nil {
		return &AuthError{
			AuthJsonError: AuthJsonError{
				Code:        ServerError,
				Description: "Failed to marshal authorization",
			},
		}
	}
	if err := a.authorizationKVS.Set(ctx, sid, authorizationJSON); err != nil {
		return &AuthError{
			AuthJsonError: AuthJsonError{
				Code:        ServerError,
				Description: "Failed to store authorization",
			},
		}
	}
	return nil
}

func (a *Auth) GetAuthorization(ctx context.Context, sid string) (*AuthorizationParams, *AuthError) {
	authorizationJSON, err := a.authorizationKVS.Get(ctx, sid)
	if err != nil {
		return nil, &AuthError{
			AuthJsonError: AuthJsonError{
				Code:        ServerError,
				Description: "Failed to get authorization",
			},
		}
	}
	var authorization AuthorizationParams
	if err := json.Unmarshal([]byte(authorizationJSON), &authorization); err != nil {
		return nil, &AuthError{
			AuthJsonError: AuthJsonError{
				Code:        ServerError,
				Description: "Failed to unmarshal authorization",
			},
		}
	}
	return &authorization, nil
}
