package handler

import (
	"net/http"
)

func (h *Handler) OAuthProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                              h.baseURL,
		"issuer":                                h.baseURL,
		"authorization_servers":                 []string{h.baseURL},
		"token_endpoint_auth_methods_supported": h.auth.GetSupportTokenEndpointAuthMethods(),
	})
}
