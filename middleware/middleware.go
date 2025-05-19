package middleware

import (
	"github.com/hi120ki/mcp-okta-gateway/gatewayv2/auth"
)

type Middleware struct {
	auth *auth.Auth
}

func NewMiddleware(auth *auth.Auth) *Middleware {
	return &Middleware{
		auth: auth,
	}
}

type contextKey string
