package main

import (
	"context"
	"log"
	"net/http"

	"github.com/redis/go-redis/v9"
	"github.com/securemcp/securemcp-okta-gateway/auth"
	"github.com/securemcp/securemcp-okta-gateway/config"
	"github.com/securemcp/securemcp-okta-gateway/handler"
	"github.com/securemcp/securemcp-okta-gateway/logging"
	"github.com/securemcp/securemcp-okta-gateway/middleware"
	"github.com/securemcp/securemcp-okta-gateway/proxy"
)

func main() {
	logger := logging.New()
	ctx := logging.WithContext(context.Background(), logger)

	// Load config
	config, proxies, err := config.NewConfig()
	if err != nil {
		log.Fatalf("failed to create config: %v", err)
	}

	// Create Redis client
	rdb := redis.NewClient(&redis.Options{
		Addr:     config.KVSAddr,
		Password: config.KVSPassword,
	})

	// Create Auth
	auth := auth.NewAuth(config.BaseURL, rdb)

	// Create Middleware
	m := middleware.NewMiddleware(auth)

	// Create Handler
	h, err := handler.NewHandler(ctx, rdb, config, auth, m)
	if err != nil {
		log.Fatalf("failed to create handler: %v", err)
	}

	http.HandleFunc("/healthz", h.Healthz)

	// Oauth Authorization Server for MCP Clients
	http.HandleFunc("/.well-known/oauth-protected-resource", m.Logger(h.OAuthProtectedResourceMetadata))
	http.HandleFunc("/.well-known/oauth-authorization-server", m.Logger(h.OAuthAuthorizationServerMetadata))
	http.HandleFunc("/auth/register", m.Logger(h.OAuthRegister))
	http.HandleFunc("/auth/authorize", m.Logger(m.SetSid(h.OAuthAuthorize)))
	http.HandleFunc("/auth/callback", m.Logger(m.SetSid(h.OAuthCallback)))
	http.HandleFunc("/auth/token", m.Logger(h.OAuthToken))

	// Create Proxy
	for _, p := range proxies {
		localProxy := proxy.NewProxyService(p, m)
		http.HandleFunc(p.Pattern, m.Logger(m.MCPBearerToken(func(w http.ResponseWriter, r *http.Request) {
			localProxy.ServeHTTP(w, r)
		})))
	}

	logger.Info("Starting proxy server", "port", config.Port)
	if err := http.ListenAndServe(":"+config.Port, nil); err != nil {
		log.Fatalf("Error starting proxy server: %v", err)
	}
}
