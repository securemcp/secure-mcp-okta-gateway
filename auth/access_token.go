package auth

import (
	"context"
	"log/slog"

	"github.com/securemcp/securemcp-okta-gateway/logging"
	"github.com/securemcp/securemcp-okta-gateway/util"
)

func (a *Auth) GenerateAccessToken(ctx context.Context, uid string) (string, *AuthError) {
	log := logging.FromContext(ctx).With(
		slog.String("auth", "GenerateAccessToken"),
	)
	accessToken := util.RandString(32)
	if err := a.accessTokenKVS.Set(ctx, accessToken, uid); err != nil {
		return "", &AuthError{
			AuthJsonError: AuthJsonError{
				Code:        ServerError,
				Description: "Failed to generate access token",
			},
		}
	}
	log.Info("Generated access token", "uid", uid)
	return accessToken, nil
}

func (a *Auth) VerifyAccessToken(ctx context.Context, accessToken string) (string, error) {
	uid, err := a.accessTokenKVS.Get(ctx, accessToken)
	if err != nil {
		return "", err
	}
	return uid, nil
}
