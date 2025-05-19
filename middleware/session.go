package middleware

import (
	"context"
	"net/http"

	"github.com/hi120ki/mcp-okta-gateway/gatewayv2/util"
)

const sidKey contextKey = "sid"
const uidKey contextKey = "uid"

func (m *Middleware) SetSid(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		var value string
		sid, err := r.Cookie("sid")
		if err != nil || sid.Value == "" {
			value = util.RandString(32)
			http.SetCookie(w, &http.Cookie{
				Name:     "sid",
				Value:    value,
				Path:     "/",
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})
		} else {
			value = sid.Value
		}

		ctx = context.WithValue(ctx, sidKey, value)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	}
}

func (m *Middleware) GetSid(ctx context.Context) string {
	sid, ok := ctx.Value(sidKey).(string)
	if !ok {
		return ""
	}
	return sid
}
