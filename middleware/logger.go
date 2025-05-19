package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/securemcp/securemcp-okta-gateway/logging"
)

func (m *Middleware) Logger(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		reqID := r.Header.Get("X-Request-Id")
		if reqID == "" {
			reqID = uuid.New().String()
		}

		ip := r.Header.Get("X-Forwarded-For")
		if ip == "" {
			ip = r.RemoteAddr
		}

		userAgent := r.UserAgent()

		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		start := time.Now()

		log := logging.FromContext(ctx).With(
			slog.String("middleware", "Logger"),
			slog.String("request_id", reqID),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.String("ip", ip),
			slog.String("user_agent", userAgent),
		)

		ctx = context.WithValue(ctx, logging.RequestIDKey, reqID)
		r = r.WithContext(ctx)

		defer func() {
			duration := time.Since(start)
			log.Info("Request completed",
				slog.Int("status", rw.statusCode),
				slog.Duration("duration", duration),
			)
		}()

		next.ServeHTTP(rw, r)
	}
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
