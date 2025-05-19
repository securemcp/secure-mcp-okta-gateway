package auth

import (
	"context"
	"encoding/json"

	"github.com/securemcp/securemcp-okta-gateway/util"
)

type AuthorizationCodeParams struct {
	UID           string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
}

func (a *Auth) GenerateAuthorizationCode(ctx context.Context, params *AuthorizationCodeParams) (string, *AuthError) {
	code := util.RandString(32)
	codeDataJSON, err := json.Marshal(params)
	if err != nil {
		return "", &AuthError{
			AuthJsonError: AuthJsonError{
				Code:        ServerError,
				Description: "Failed to marshal authorization code",
			},
		}
	}
	if err := a.codeKVS.Set(ctx, code, codeDataJSON); err != nil {
		return "", &AuthError{
			AuthJsonError: AuthJsonError{
				Code:        ServerError,
				Description: "Failed to store authorization code",
			},
		}
	}

	return code, nil
}

func (a *Auth) VerifyAuthorizationCode(ctx context.Context, code, clientID, redirectURI, codeVerifier string) (string, *AuthError) {
	storedCodeDataJSON, err := a.codeKVS.GetDel(ctx, code)
	if err != nil {
		return "", &AuthError{
			AuthJsonError: AuthJsonError{
				Code:        ServerError,
				Description: "Failed to get authorization code",
			},
		}
	}

	var storedCodeData AuthorizationCodeParams
	if err := json.Unmarshal([]byte(storedCodeDataJSON), &storedCodeData); err != nil {
		return "", &AuthError{
			AuthJsonError: AuthJsonError{
				Code:        ServerError,
				Description: "Failed to unmarshal authorization code",
			},
		}
	}

	if storedCodeData.ClientID != clientID || storedCodeData.RedirectURI != redirectURI {
		return "", &AuthError{
			AuthJsonError: AuthJsonError{
				Code:        InvalidRequest,
				Description: "Invalid client or redirect URI",
			},
		}
	}

	hash := util.S256(codeVerifier)
	if hash != storedCodeData.CodeChallenge {
		return "", &AuthError{
			AuthJsonError: AuthJsonError{
				Code:        InvalidRequest,
				Description: "Invalid code challenge",
			},
		}
	}

	return storedCodeData.UID, nil
}
