package okta

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/hi120ki/mcp-okta-gateway/gatewayv2/kvs"
	"github.com/hi120ki/mcp-okta-gateway/gatewayv2/util"
	"github.com/redis/go-redis/v9"
	"golang.org/x/oauth2"
)

type OktaConfig struct {
	OktaURL          string
	OktaClientID     string
	OktaClientSecret string
	OktaRedirectURI  string
}

type OktaProvider struct {
	oktaStateKVS *kvs.KVS // key: sid, value: okta state
	oktaNonceKVS *kvs.KVS // key: sid, value: okta nonce
	oktaCodeKVS  *kvs.KVS // key: sid, value: okta code
	oidcConfig   *oauth2.Config
	verifier     *oidc.IDTokenVerifier
}

func NewOktaProvider(ctx context.Context, config *OktaConfig, rdb *redis.Client) (*OktaProvider, error) {
	oktaStateKVS := kvs.NewKVS(rdb, "okta_state", kvs.OAuthStateTTL)
	oktaNonceKVS := kvs.NewKVS(rdb, "okta_nonce", kvs.OAuthStateTTL)
	oktaCodeKVS := kvs.NewKVS(rdb, "okta_code", kvs.OAuthStateTTL)

	provider, err := oidc.NewProvider(ctx, config.OktaURL+"/oauth2/default")
	if err != nil {
		return nil, fmt.Errorf("failed to create oidc provider: %w", err)
	}

	oidcConfig := &oauth2.Config{
		ClientID:     config.OktaClientID,
		ClientSecret: config.OktaClientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{"openid", "profile", "email"},
		RedirectURL:  config.OktaRedirectURI,
	}

	verifier := provider.Verifier(&oidc.Config{ClientID: config.OktaClientID})

	return &OktaProvider{
		oktaStateKVS: oktaStateKVS,
		oktaNonceKVS: oktaNonceKVS,
		oktaCodeKVS:  oktaCodeKVS,
		oidcConfig:   oidcConfig,
		verifier:     verifier,
	}, nil
}

func (p *OktaProvider) GetAuthCodeURL(ctx context.Context, sid string) (string, error) {
	state := util.RandString(16)
	nonce := util.RandString(16)
	codeVerifier := util.RandString(96)
	hashedCodeVerifier := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hashedCodeVerifier[:])

	if err := p.oktaStateKVS.Set(ctx, sid, state); err != nil {
		return "", err
	}

	if err := p.oktaNonceKVS.Set(ctx, sid, nonce); err != nil {
		return "", err
	}

	if err := p.oktaCodeKVS.Set(ctx, sid, codeVerifier); err != nil {
		return "", err
	}

	return p.oidcConfig.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	), nil
}

type OktaClaims struct {
	Sub               string   `json:"sub"`
	Name              string   `json:"name"`
	Email             string   `json:"email"`
	Ver               int      `json:"ver"`
	Iss               string   `json:"iss"`
	Aud               string   `json:"aud"`
	Iat               int      `json:"iat"`
	Exp               int      `json:"exp"`
	Jti               string   `json:"jti"`
	Amr               []string `json:"amr"`
	Idp               string   `json:"idp"`
	Nonce             string   `json:"nonce"`
	PreferredUsername string   `json:"preferred_username"`
	AuthTime          int      `json:"auth_time"`
	AtHash            string   `json:"at_hash"`
}

func (p *OktaProvider) Callback(ctx context.Context, sid, state, code string) (*OktaClaims, error) {
	savedState, err := p.oktaStateKVS.GetDel(ctx, sid)
	if err != nil {
		return nil, err
	}

	codeVerifier, err := p.oktaCodeKVS.GetDel(ctx, sid)
	if err != nil {
		return nil, err
	}

	if savedState != state {
		return nil, fmt.Errorf("invalid state: %s", savedState)
	}

	oauth2Tok, err := p.oidcConfig.Exchange(
		ctx,
		code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	rawIDToken, ok := oauth2Tok.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("failed to get id_token")
	}

	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify id_token: %w", err)
	}

	var claims OktaClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	nonce, err := p.oktaNonceKVS.GetDel(ctx, sid)
	if err != nil {
		return nil, err
	}

	if claims.Nonce != nonce {
		return nil, fmt.Errorf("invalid nonce: %s", claims.Nonce)
	}

	return &claims, nil
}
