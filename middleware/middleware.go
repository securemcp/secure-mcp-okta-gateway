package middleware

import (
	"github.com/securemcp/securemcp-okta-gateway/auth"
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
