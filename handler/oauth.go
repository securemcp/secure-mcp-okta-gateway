package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/securemcp/securemcp-okta-gateway/auth"
	"github.com/securemcp/securemcp-okta-gateway/logging"
)

func (h *Handler) OAuthRegister(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logging.FromContext(ctx).With(
		slog.String("handler", "OAuthRegister"),
		slog.String("request_id", ctx.Value(logging.RequestIDKey).(string)),
	)
	ctx = logging.WithContext(ctx, log)

	switch r.Method {
	case http.MethodPost:
		if ct := r.Header.Get("Content-Type"); ct == "" || !strings.HasPrefix(ct, "application/json") {
			log.Error("Invalid Content-Type", "content_type", ct)
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error":             "invalid_request",
				"error_description": "Content-Type must be application/json",
			})
			return
		}
		var metadata auth.ClientMetadata
		if err := json.NewDecoder(r.Body).Decode(&metadata); err != nil {
			log.Error("Failed to decode request body", "error", err)
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error":             "invalid_client_metadata",
				"error_description": "Failed to decode request body",
			})
			return
		}

		validatedMetadata, authErr := h.auth.RegisterValidate(ctx, &metadata)
		if authErr != nil {
			log.Error("Failed to validate client metadata", "error", authErr)
			HandleAuthError(w, r, authErr)
			return
		}

		client := h.auth.Register(ctx, validatedMetadata)

		if authErr := h.auth.SaveClient(ctx, client.ClientID, client); authErr != nil {
			log.Error("Failed to save client", "error", authErr)
			HandleAuthError(w, r, authErr)
			return
		}

		writeJSON(w, http.StatusOK, client)
	default:
		log.Error("Invalid request method", "method", r.Method)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{
			"error":             "invalid_request",
			"error_description": "Only POST is supported for this endpoint.",
		})
	}
}

func (h *Handler) OAuthAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logging.FromContext(ctx).With(
		slog.String("handler", "OAuthAuthorize"),
		slog.String("request_id", ctx.Value(logging.RequestIDKey).(string)),
	)
	ctx = logging.WithContext(ctx, log)

	log.Debug("OAuthAuthorize called")

	switch r.Method {
	case http.MethodGet:
		sid := h.middleware.GetSid(ctx)
		if sid == "" {
			// Wait for set-cookie will be set
			http.Redirect(w, r, r.URL.String(), http.StatusFound)
			return
		}
		q := r.URL.Query()
		params := &auth.AuthorizationParams{
			ClientID:            q.Get("client_id"),
			RedirectURI:         q.Get("redirect_uri"),
			ResponseType:        q.Get("response_type"),
			State:               q.Get("state"),
			CodeChallenge:       q.Get("code_challenge"),
			CodeChallengeMethod: q.Get("code_challenge_method"),
		}
		client, authErr := h.auth.GetClient(ctx, params.ClientID)
		if authErr != nil {
			log.Error("Failed to get client", "error", authErr)
			HandleAuthError(w, r, authErr)
			return
		}
		if authErr := h.auth.ValidateAuthorizationClient(ctx, params, client); authErr != nil {
			log.Error("Failed to validate authorization client", "error", authErr)
			HandleAuthError(w, r, authErr)
			return
		}
		if authErr := h.auth.ValidateAuthorizationParams(ctx, params); authErr != nil {
			log.Error("Failed to validate authorization params", "error", authErr)
			HandleAuthError(w, r, authErr)
			return
		}
		if authErr := h.auth.StoreAuthorization(ctx, sid, params); authErr != nil {
			log.Error("Failed to store authorization", "error", authErr)
			HandleAuthError(w, r, authErr)
			return
		}
		authCode, err := h.oauthOkta.GetAuthCodeURL(ctx, sid)
		if err != nil {
			log.Error("Failed to get auth code URL", "error", err)
			http.Error(w, "Failed to get auth code URL", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, authCode, http.StatusFound)
		return
	default:
		log.Error("Invalid request method", "method", r.Method)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{
			"error":             "invalid_request",
			"error_description": "Only GET is supported for this endpoint.",
		})
	}
}

func (h *Handler) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logging.FromContext(ctx).With(
		slog.String("handler", "OAuthCallback"),
		slog.String("request_id", ctx.Value(logging.RequestIDKey).(string)),
	)
	ctx = logging.WithContext(ctx, log)

	switch r.Method {
	case http.MethodGet:
		sid := h.middleware.GetSid(ctx)
		if sid == "" {
			log.Error("Failed to get session ID")
			http.Error(w, "Failed to get session ID", http.StatusInternalServerError)
			return
		}

		claims, err := h.oauthOkta.Callback(ctx, sid, r.URL.Query().Get("state"), r.URL.Query().Get("code"))
		if err != nil {
			log.Error("Failed to get user ID", "error", err)
			http.Error(w, "Failed to get user ID", http.StatusInternalServerError)
			return
		}

		authParams, authErr := h.auth.GetAuthorization(ctx, sid)
		if authErr != nil {
			log.Error("Failed to get authorization", "error", authErr)
			HandleAuthError(w, r, authErr)
			return
		}

		authCode, authErr := h.auth.GenerateAuthorizationCode(ctx, &auth.AuthorizationCodeParams{
			UID:           claims.Sub,
			ClientID:      authParams.ClientID,
			RedirectURI:   authParams.RedirectURI,
			CodeChallenge: authParams.CodeChallenge,
		})
		if authErr != nil {
			log.Error("Failed to generate authorization code", "error", authErr)
			HandleAuthError(w, r, authErr)
			return
		}

		urlParams := "?code=" + authCode
		if authParams.State != "" {
			urlParams += "&state=" + authParams.State
		}

		http.Redirect(w, r, authParams.RedirectURI+urlParams, http.StatusFound)
		return
	default:
		log.Error("Invalid request method", "method", r.Method)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{
			"error":             "invalid_request",
			"error_description": "Only GET is supported for this endpoint.",
		})
	}
}

func (h *Handler) OAuthToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	log := logging.FromContext(ctx).With(
		slog.String("handler", "OAuthToken"),
		slog.String("request_id", ctx.Value(logging.RequestIDKey).(string)),
	)
	ctx = logging.WithContext(ctx, log)

	switch r.Method {
	case http.MethodPost:
		if ct := r.Header.Get("Content-Type"); ct == "" || !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
			log.Error("Invalid Content-Type", "content_type", ct)
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error":             "invalid_request",
				"error_description": "Content-Type must be application/x-www-form-urlencoded",
			})
			return
		}
		switch r.FormValue("grant_type") {
		case "authorization_code":
			params := &auth.TokenRequestParams{
				GrantType:     r.FormValue("grant_type"),
				Code:          r.FormValue("code"),
				RedirectURI:   r.FormValue("redirect_uri"),
				ClientID:      r.FormValue("client_id"),
				CodeVerifier:  r.FormValue("code_verifier"),
				Authorization: r.Header.Get("Authorization"),
			}
			if authErr := h.auth.TokenValidateParams(ctx, params); authErr != nil {
				log.Error("Failed to validate token params", "error", authErr)
				HandleAuthError(w, r, authErr)
				return
			}
			client, authErr := h.auth.GetClient(ctx, params.ClientID)
			if authErr != nil {
				log.Error("Failed to get client", "error", authErr)
				HandleAuthError(w, r, authErr)
				return
			}
			if authErr := h.auth.TokenValidateClient(ctx, params, client); authErr != nil {
				log.Error("Failed to validate client", "error", authErr)
				HandleAuthError(w, r, authErr)
				return
			}
			if authErr := h.auth.TokenValidateClientSecret(ctx, params, client); authErr != nil {
				log.Error("Failed to validate client secret", "error", authErr)
				HandleAuthError(w, r, authErr)
				return
			}
			uid, authErr := h.auth.VerifyAuthorizationCode(ctx, params.Code, params.ClientID, params.RedirectURI, params.CodeVerifier)
			if authErr != nil {
				log.Error("Failed to verify authorization code", "error", authErr)
				HandleAuthError(w, r, authErr)
				return
			}
			accessToken, authErr := h.auth.GenerateAccessToken(ctx, uid)
			if authErr != nil {
				log.Error("Failed to generate access token", "error", authErr)
				HandleAuthError(w, r, authErr)
				return
			}
			refreshToken, authErr := h.auth.GenerateRefreshToken(ctx, uid)
			if authErr != nil {
				log.Error("Failed to generate refresh token", "error", authErr)
				HandleAuthError(w, r, authErr)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"token_type":    "Bearer",
				"expires_in":    3600,
				"access_token":  accessToken,
				"refresh_token": refreshToken,
			})
		case "refresh_token":
			params := &auth.RefreshTokenRequestParams{
				GrantType:    r.FormValue("grant_type"),
				RefreshToken: r.FormValue("refresh_token"),
				ClientID:     r.FormValue("client_id"),
				ClientSecret: r.FormValue("client_secret"),
			}
			if authErr := h.auth.RefreshTokenValidateParams(ctx, params); authErr != nil {
				log.Error("Failed to validate refresh token params", "error", authErr)
				HandleAuthError(w, r, authErr)
				return
			}
			client, authErr := h.auth.GetClient(ctx, params.ClientID)
			if authErr != nil {
				log.Error("Failed to get client", "error", authErr)
				HandleAuthError(w, r, authErr)
				return
			}
			if authErr := h.auth.RefreshTokenValidateClient(ctx, params, client); authErr != nil {
				log.Error("Failed to validate refresh token client", "error", authErr)
				HandleAuthError(w, r, authErr)
				return
			}
			uid, authErr := h.auth.VerifyRefreshToken(ctx, params.RefreshToken)
			if authErr != nil {
				log.Error("Failed to verify refresh token", "error", authErr)
				HandleAuthError(w, r, authErr)
				return
			}
			accessToken, authErr := h.auth.GenerateAccessToken(ctx, uid)
			if authErr != nil {
				log.Error("Failed to generate access token", "error", authErr)
				HandleAuthError(w, r, authErr)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"token_type":    "Bearer",
				"expires_in":    3600,
				"access_token":  accessToken,
				"refresh_token": params.RefreshToken,
			})
		default:
			log.Error("Unsupported grant type", "grant_type", r.FormValue("grant_type"))
			HandleAuthError(w, r, &auth.AuthError{
				AuthJsonError: auth.AuthJsonError{
					Code:        "invalid_request",
					Description: "unsupported grant_type",
				},
			})
			return
		}
	default:
		log.Error("Invalid request method", "method", r.Method)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{
			"error":             "invalid_request",
			"error_description": "Only GET is supported for this endpoint.",
		})
	}
}
