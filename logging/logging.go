// internal/logging/logging.go
package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
)

type contextKey struct{}

var key contextKey          // Key for context
var RequestIDKey contextKey // Key for request_id in context

// New builds a slog.Logger and sets it as default.
//
//	LOG_ENV   = development | production
//	LOG_LEVEL = DEBUG | INFO | WARN | ERROR   (case-insensitive)
func New(w ...io.Writer) *slog.Logger {
	env := strings.ToLower(os.Getenv("LOG_ENV"))
	level := parseLevel(strings.ToUpper(os.Getenv("LOG_LEVEL")))

	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: env == "development",
	}

	var h slog.Handler
	out := io.MultiWriter(append([]io.Writer{os.Stdout}, w...)...)
	if env == "development" {
		h = slog.NewTextHandler(out, opts)
	} else {
		h = slog.NewJSONHandler(out, opts)
	}

	l := slog.New(h)
	slog.SetDefault(l)
	return l
}

func parseLevel(s string) slog.Level {
	switch s {
	case "DEBUG":
		return slog.LevelDebug
	case "WARN":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// WithContext embeds a logger into ctx.
func WithContext(ctx context.Context, l *slog.Logger) context.Context {
	return context.WithValue(ctx, key, l)
}

// FromContext returns logger if present, otherwise slog.Default().
func FromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(key).(*slog.Logger); ok {
		return l
	}
	return slog.Default()
}
