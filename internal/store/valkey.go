package store

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// Valkey is a Store backed by Valkey or Redis.
type Valkey struct{ c *redis.Client }

// NewValkey connects using a redis:// or rediss:// URL.
func NewValkey(url string) (*Valkey, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, err
	}
	return &Valkey{c: redis.NewClient(opts)}, nil
}

// SetNX implements Store with an atomic SET NX EX.
func (v *Valkey) SetNX(ctx context.Context, key, value string, ttl time.Duration) (bool, error) {
	err := v.c.SetArgs(ctx, key, value, redis.SetArgs{Mode: "NX", TTL: ttl}).Err()
	if errors.Is(err, redis.Nil) {
		return false, nil
	}
	return err == nil, err
}

// Set implements Store.
func (v *Valkey) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return v.c.Set(ctx, key, value, ttl).Err()
}

// Get implements Store.
func (v *Valkey) Get(ctx context.Context, key string) (string, bool, error) {
	s, err := v.c.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", false, nil
	}
	return s, err == nil, err
}

// Del implements Store.
func (v *Valkey) Del(ctx context.Context, key string) error { return v.c.Del(ctx, key).Err() }

var incrScript = redis.NewScript(`
local n = redis.call('INCRBY', KEYS[1], ARGV[1])
if n == tonumber(ARGV[1]) then redis.call('PEXPIRE', KEYS[1], ARGV[2]) end
return n`)

// Incr implements Store. The script makes the increment and the TTL atomic, so
// a crash cannot leave a counter that never expires.
func (v *Valkey) Incr(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error) {
	return incrScript.Run(ctx, v.c, []string{key}, delta, ttl.Milliseconds()).Int64()
}

// MGet implements Store.
func (v *Valkey) MGet(ctx context.Context, keys []string) ([]string, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	vals, err := v.c.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, err
	}
	out := make([]string, len(vals))
	for i, val := range vals {
		if s, ok := val.(string); ok {
			out[i] = s
		}
	}
	return out, nil
}

// Ping implements Store.
func (v *Valkey) Ping(ctx context.Context) error { return v.c.Ping(ctx).Err() }

// Close implements Store.
func (v *Valkey) Close() error { return v.c.Close() }
