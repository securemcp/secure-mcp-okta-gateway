package proxy

import (
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/hi120ki/mcp-okta-gateway/gatewayv2/config"
	"github.com/hi120ki/mcp-okta-gateway/gatewayv2/middleware"
)

type ProxyService struct {
	proxy *httputil.ReverseProxy
}

func NewProxyService(config *config.ProxyConfig, middleware *middleware.Middleware) *ProxyService {
	proxy := httputil.NewSingleHostReverseProxy(config.TargetURL)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		trimPrefix(req, config.Pattern)
	}
	return &ProxyService{proxy: proxy}
}

func (p *ProxyService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.proxy.ServeHTTP(w, r)
}

func trimPrefix(req *http.Request, pattern string) {
	req.URL.Path = strings.TrimPrefix(req.URL.Path, strings.TrimSuffix(pattern, "/"))
}
