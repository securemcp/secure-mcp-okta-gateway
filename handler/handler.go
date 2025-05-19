package handler

import (
	"context"
	"fmt"

	"github.com/hi120ki/mcp-okta-gateway/gatewayv2/auth"
	"github.com/hi120ki/mcp-okta-gateway/gatewayv2/config"
	"github.com/hi120ki/mcp-okta-gateway/gatewayv2/middleware"
	"github.com/hi120ki/mcp-okta-gateway/gatewayv2/provider/okta"
	"github.com/redis/go-redis/v9"
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
