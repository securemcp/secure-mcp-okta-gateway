package auth

import (
	"context"
	"log/slog"

	"github.com/hi120ki/mcp-okta-gateway/gatewayv2/logging"
	"github.com/hi120ki/mcp-okta-gateway/gatewayv2/util"
)

func (a *Auth) GenerateRefreshToken(ctx context.Context, uid string) (string, *AuthError) {
	log := logging.FromContext(ctx).With(
		slog.String("auth", "GenerateRefreshToken"),
	)
	refreshToken := util.RandString(32)
	if err := a.refreshTokenKVS.Set(ctx, refreshToken, uid); err != nil {
		return "", &AuthError{
			AuthJsonError: AuthJsonError{
				Code:        ServerError,
				Description: "Failed to generate refresh token",
			},
		}
	}
	log.Info("Generated refresh token", "uid", uid)
	return refreshToken, nil
}

func (a *Auth) VerifyRefreshToken(ctx context.Context, refreshToken string) (string, *AuthError) {
	uid, err := a.refreshTokenKVS.Get(ctx, refreshToken)
	if err != nil {
		return "", &AuthError{
			AuthJsonError: AuthJsonError{
				Code:        ServerError,
				Description: "Failed to verify refresh token",
			},
		}
	}
	return uid, nil
}
