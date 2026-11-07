// Package store holds short-lived state: redemptions, counters and evidence.
package store

import (
	"context"
	"time"
)

// Store is the minimal key-value contract. Every key carries a TTL, so nothing
// the service writes can outlive its purpose.
type Store interface {
	// SetNX stores value only if key is absent and reports whether it did.
	SetNX(ctx context.Context, key, value string, ttl time.Duration) (bool, error)
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	Get(ctx context.Context, key string) (string, bool, error)
	Del(ctx context.Context, key string) error
	// Incr adds delta and sets ttl when the key is created.
	Incr(ctx context.Context, key string, delta int64, ttl time.Duration) (int64, error)
	// MGet returns values for keys; missing keys yield empty strings.
	MGet(ctx context.Context, keys []string) ([]string, error)
	Ping(ctx context.Context) error
	Close() error
}
