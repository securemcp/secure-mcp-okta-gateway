package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/joho/godotenv"
	"github.com/kelseyhightower/envconfig"
)

type Config struct {
	BaseConfig
	OAuthOktaConfig
}

type BaseConfig struct {
	BaseURL     string `default:"http://localhost:8080" envconfig:"BASE_URL"`
	Port        string `default:"8080" envconfig:"PORT"`
	KVSAddr     string `default:"localhost:6379" envconfig:"KVS_ADDR"`
	KVSPassword string `envconfig:"KVS_PASSWORD"`
}

type OAuthOktaConfig struct {
	OktaURL          string `required:"true" envconfig:"OAUTH_OKTA_URL"`
	OktaClientID     string `required:"true" envconfig:"OAUTH_OKTA_CLIENT_ID"`
	OktaClientSecret string `required:"true" envconfig:"OAUTH_OKTA_CLIENT_SECRET"`
	OktaRedirectURI  string `required:"true" envconfig:"OAUTH_OKTA_REDIRECT_URI"`
}

type ProxyConfig struct {
	Pattern   string
	TargetURL *url.URL
}

func NewConfig() (*Config, []*ProxyConfig, error) {
	_ = godotenv.Load()

	var cfg Config
	if err := envconfig.Process("", &cfg); err != nil {
		return nil, nil, err
	}

	if strings.HasSuffix(cfg.BaseURL, "/") {
		return nil, nil, fmt.Errorf("base url must not end with a slash: %s", cfg.BaseURL)
	}

	if strings.HasSuffix(cfg.OAuthOktaConfig.OktaURL, "/") {
		return nil, nil, fmt.Errorf("okta url must not end with a slash: %s", cfg.OAuthOktaConfig.OktaURL)
	}

	if strings.HasSuffix(cfg.OAuthOktaConfig.OktaRedirectURI, "/") {
		return nil, nil, fmt.Errorf("okta redirect uri must not end with a slash: %s", cfg.OAuthOktaConfig.OktaRedirectURI)
	}

	// Load proxy settings from config.yaml if exists
	type proxyConfig struct {
		Pattern   string `yaml:"pattern"`
		TargetURL string `yaml:"target_url"`
	}
	f, err := os.Open("config.yaml")
	if err != nil {
		return &cfg, nil, nil
	}
	defer f.Close()
	d := yaml.NewDecoder(f)
	proxies := struct {
		Proxies []*proxyConfig `yaml:"proxies"`
	}{}
	if err := d.Decode(&proxies); err != nil {
		return &cfg, nil, fmt.Errorf("failed to decode config.yaml: %w", err)
	}
	proxyConfigs := []*ProxyConfig{}
	for _, p := range proxies.Proxies {
		if p.TargetURL == "" || p.Pattern == "" {
			return nil, nil, fmt.Errorf("target url and pattern are required for proxy: %v", p)
		}
		if !strings.HasPrefix(p.TargetURL, "http") {
			return nil, nil, fmt.Errorf("target url must start with http(s): %v", p)
		}
		if strings.HasSuffix(p.TargetURL, "/") {
			return nil, nil, fmt.Errorf("target url must not end with a slash: %v", p)
		}
		if !strings.HasPrefix(p.Pattern, "/") {
			return nil, nil, fmt.Errorf("pattern must start with a slash: %v", p)
		}
		if !strings.HasSuffix(p.Pattern, "/") {
			return nil, nil, fmt.Errorf("pattern must end with a slash: %v", p)
		}
		url, err := url.Parse(p.TargetURL)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse target url: %w", err)
		}
		proxyConfigs = append(proxyConfigs, &ProxyConfig{
			Pattern:   p.Pattern,
			TargetURL: url,
		})
	}
	return &cfg, proxyConfigs, nil
}
