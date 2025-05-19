package handler

import "net/http"

func (h *Handler) OAuthAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                h.baseURL,
		"authorization_endpoint":                h.auth.GetAuthorizationURL(),
		"token_endpoint":                        h.auth.GetTokenURL(),
		"registration_endpoint":                 h.auth.GetDynamicRegistrationURL(),
		"response_types_supported":              h.auth.GetSupportResponseTypes(),
		"grant_types_supported":                 h.auth.GetSupportGrantTypes(),
		"token_endpoint_auth_methods_supported": h.auth.GetSupportTokenEndpointAuthMethods(),
		"code_challenge_methods_supported":      h.auth.GetSupportCodeChallengeMethods(),
	})
}
