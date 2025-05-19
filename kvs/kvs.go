package kvs

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	OAuthAccessTokenTTL    = 60 * time.Minute
	OAuthRefreshTokenTTL   = 30 * 24 * time.Hour
	OAuthStateTTL          = 5 * time.Minute
	OAuthClientTTL         = 90 * 24 * time.Hour
	SessionTTL             = 7 * 24 * time.Hour
	ResourceAccessTokenTTL = 30 * 24 * time.Hour
)

type KVS struct {
	rdb    *redis.Client
	prefix string
	ttl    time.Duration
}

func NewKVS(rdb *redis.Client, prefix string, ttl time.Duration) *KVS {
	return &KVS{
		rdb:    rdb,
		prefix: prefix + ":",
		ttl:    ttl,
	}
}

func (k *KVS) Get(ctx context.Context, key string) (string, error) {
	return k.rdb.Get(ctx, k.prefix+key).Result()
}

func (k *KVS) GetDel(ctx context.Context, key string) (string, error) {
	return k.rdb.GetDel(ctx, k.prefix+key).Result()
}

func (k *KVS) Set(ctx context.Context, key string, value any) error {
	return k.rdb.Set(ctx, k.prefix+key, value, k.ttl).Err()
}

func (k *KVS) Del(ctx context.Context, key string) error {
	return k.rdb.Del(ctx, k.prefix+key).Err()
}
