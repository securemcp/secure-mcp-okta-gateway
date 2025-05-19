package handler

import (
	"encoding/json"
	"net/http"
	"net/url"

	"github.com/securemcp/securemcp-okta-gateway/auth"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func HandleAuthError(w http.ResponseWriter, r *http.Request, err *auth.AuthError) {
	if err.AuthJsonError.Code != "" {
		status := http.StatusOK
		if err.AuthJsonError.Code == auth.InvalidClientMetadata {
			status = http.StatusBadRequest
		}
		if err.AuthJsonError.Code == auth.InvalidRequest {
			status = http.StatusBadRequest
		}
		if err.AuthJsonError.Code == auth.UnauthorizedClient {
			status = http.StatusUnauthorized
		}
		if err.AuthJsonError.Code == auth.ServerError {
			status = http.StatusInternalServerError
		}
		writeJSON(w, status, err.AuthJsonError)
	} else {
		params := "?error=" + url.QueryEscape(err.AuthRedirectError.ErrorCode) + "&error_description=" + url.QueryEscape(err.AuthRedirectError.ErrorDescription)
		if err.AuthRedirectError.State != "" {
			params += "&state=" + url.QueryEscape(err.AuthRedirectError.State)
		}
		http.Redirect(w, r, err.AuthRedirectError.RedirectURI+params, http.StatusFound)
	}
}
