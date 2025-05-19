package auth

import (
	"context"
	"slices"
	"strings"

	"github.com/securemcp/securemcp-okta-gateway/util"
)

type AuthorizationParams struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
}

func (a *Auth) ValidateAuthorizationClient(ctx context.Context, params *AuthorizationParams, client *Client) *AuthError {
	if !slices.Contains(client.RedirectURIs, params.RedirectURI) {
		return &AuthError{
			AuthJsonError: AuthJsonError{
				Code:        InvalidRequest,
				Description: "redirect_uri is invalid",
			},
		}
	}

	if !slices.Contains(client.ResponseTypes, params.ResponseType) {
		return &AuthError{
			AuthRedirectError: AuthRedirectError{
				RedirectURI:      params.RedirectURI,
				ErrorCode:        InvalidRequest,
				ErrorDescription: "unsupported response_type",
				State:            params.State,
			},
		}
	}

	return nil
}

func (a *Auth) ValidateAuthorizationParams(ctx context.Context, params *AuthorizationParams) *AuthError {
	if params.State == "" && params.CodeChallenge == "" {
		return &AuthError{
			AuthRedirectError: AuthRedirectError{
				RedirectURI:      params.RedirectURI,
				ErrorCode:        InvalidRequest,
				ErrorDescription: "state or code_challenge is required",
				State:            params.State,
			},
		}
	}

	if !a.supportedCodeChallengeMethods[params.CodeChallengeMethod] {
		methods := make([]string, 0, len(a.supportedCodeChallengeMethods))
		for k := range a.supportedCodeChallengeMethods {
			methods = append(methods, k)
		}
		return &AuthError{
			AuthRedirectError: AuthRedirectError{
				RedirectURI:      params.RedirectURI,
				ErrorCode:        InvalidRequest,
				ErrorDescription: "code_challenge_method must be " + strings.Join(methods, ", "),
				State:            params.State,
			},
		}
	}

	if !util.IsValidCodeChallengeOrVerifier(params.CodeChallenge) {
		return &AuthError{
			AuthRedirectError: AuthRedirectError{
				RedirectURI:      params.RedirectURI,
				ErrorCode:        InvalidRequest,
				ErrorDescription: "code_challenge must be 43-128 chars and only [A-Z/a-z/0-9/-/./_/~] allowed",
				State:            params.State,
			},
		}
	}

	return nil
}
