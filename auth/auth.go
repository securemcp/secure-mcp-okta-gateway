package auth

import (
	"github.com/hi120ki/mcp-okta-gateway/gatewayv2/kvs"
	"github.com/redis/go-redis/v9"
)

type Auth struct {
	baseURL                           string
	clientKVS                         *kvs.KVS // key: client_id, value: client
	codeKVS                           *kvs.KVS // key: code, value: code
	authorizationKVS                  *kvs.KVS // key: sid, value: authorization param
	accessTokenKVS                    *kvs.KVS // key: access_token, value: access_token
	refreshTokenKVS                   *kvs.KVS // key: refresh_token, value: refresh_token
	supportedTokenEndpointAuthMethods map[string]bool
	supportedGrantTypes               map[string]bool
	supportedResponseTypes            map[string]bool
	supportedCodeChallengeMethods     map[string]bool
}

func NewAuth(baseURL string, rdb *redis.Client) *Auth {
	clientKVS := kvs.NewKVS(rdb, "client", kvs.OAuthClientTTL)
	codeKVS := kvs.NewKVS(rdb, "code", kvs.OAuthStateTTL)
	authorizationKVS := kvs.NewKVS(rdb, "authorization", kvs.OAuthStateTTL)
	accessTokenKVS := kvs.NewKVS(rdb, "access_token", kvs.OAuthAccessTokenTTL)
	refreshTokenKVS := kvs.NewKVS(rdb, "refresh_token", kvs.OAuthRefreshTokenTTL)

	return &Auth{
		baseURL:          baseURL,
		clientKVS:        clientKVS,
		codeKVS:          codeKVS,
		authorizationKVS: authorizationKVS,
		accessTokenKVS:   accessTokenKVS,
		refreshTokenKVS:  refreshTokenKVS,
		supportedTokenEndpointAuthMethods: map[string]bool{
			"client_secret_basic": true,
			"client_secret_post":  true,
			"none":                true,
		},
		supportedGrantTypes: map[string]bool{
			"authorization_code": true,
			"refresh_token":      true,
		},
		supportedResponseTypes: map[string]bool{
			"code": true,
		},
		supportedCodeChallengeMethods: map[string]bool{
			"S256": true,
		},
	}
}
