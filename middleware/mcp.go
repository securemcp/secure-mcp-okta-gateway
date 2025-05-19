package middleware

import (
	"context"
	"net/http"
	"strings"
)

func (m *Middleware) MCPBearerToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		bearerToken := strings.TrimPrefix(authHeader, "Bearer ")
		uid, err := m.auth.VerifyAccessToken(ctx, bearerToken)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		ctx = context.WithValue(ctx, uidKey, uid)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	}
}
