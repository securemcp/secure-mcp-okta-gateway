package handler

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
	"github.com/securemcp/securemcp-okta-gateway/auth"
	"github.com/securemcp/securemcp-okta-gateway/config"
	"github.com/securemcp/securemcp-okta-gateway/middleware"
	"github.com/securemcp/securemcp-okta-gateway/provider/okta"
)

type Handler struct {
	baseURL    string
	auth       *auth.Auth
	middleware *middleware.Middleware
	oauthOkta  *okta.OktaProvider
}

func NewHandler(
	ctx context.Context,
	rdb *redis.Client,
	config *config.Config,
	auth *auth.Auth,
	middleware *middleware.Middleware,
) (*Handler, error) {
	oauthOkta, err := okta.NewOktaProvider(ctx, &okta.OktaConfig{
		OktaURL:          config.OAuthOktaConfig.OktaURL,
		OktaClientID:     config.OAuthOktaConfig.OktaClientID,
		OktaClientSecret: config.OAuthOktaConfig.OktaClientSecret,
		OktaRedirectURI:  config.OAuthOktaConfig.OktaRedirectURI,
	}, rdb)
	if err != nil {
		return nil, fmt.Errorf("failed to create oauth okta provider: %w", err)
	}

	return &Handler{
		baseURL:    config.BaseURL,
		auth:       auth,
		middleware: middleware,
		oauthOkta:  oauthOkta,
	}, nil
}
