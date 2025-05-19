package handler

import (
	"log/slog"
	"net/http"

	"github.com/securemcp/securemcp-okta-gateway/logging"
)

func (h *Handler) Healthz(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logging.FromContext(ctx).With(
		slog.String("handler", "Healthz"),
		slog.String("request_id", ctx.Value(logging.RequestIDKey).(string)),
	)

	log.Debug("healthz called")
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}
