package store

import (
	"context"
	"strconv"
	"sync"
	"time"
)

type entry struct {
	value   string
	expires time.Time
}

// Memory is a single-process Store for development and small deployments.
type Memory struct {
	mu   sync.Mutex
	data map[string]entry
	now  func() time.Time
	ops  int
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory { return &Memory{data: map[string]entry{}, now: time.Now} }

func (m *Memory) get(key string) (entry, bool) {
	e, ok := m.data[key]
	if ok && !e.expires.After(m.now()) {
		delete(m.data, key)
		return entry{}, false
	}
	return e, ok
}

// sweep drops expired keys occasionally so memory stays bounded.
func (m *Memory) sweep() {
	m.ops++
	if m.ops < 4096 {
		return
	}
	m.ops = 0
	now := m.now()
	for k, e := range m.data {
		if !e.expires.After(now) {
			delete(m.data, k)
		}
	}
}

// SetNX implements Store.
func (m *Memory) SetNX(_ context.Context, key, value string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweep()
	if _, ok := m.get(key); ok {
		return false, nil
	}
	m.data[key] = entry{value, m.now().Add(ttl)}
	return true, nil
}

// Set implements Store.
func (m *Memory) Set(_ context.Context, key, value string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweep()
	m.data[key] = entry{value, m.now().Add(ttl)}
	return nil
}

// Get implements Store.
func (m *Memory) Get(_ context.Context, key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.get(key)
	return e.value, ok, nil
}

// Del implements Store.
func (m *Memory) Del(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, key)
	return nil
}

// Incr implements Store.
func (m *Memory) Incr(_ context.Context, key string, delta int64, ttl time.Duration) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sweep()
	e, ok := m.get(key)
	if !ok {
		e = entry{"0", m.now().Add(ttl)}
	}
	n, err := strconv.ParseInt(e.value, 10, 64)
	if err != nil {
		return 0, err
	}
	n += delta
	e.value = strconv.FormatInt(n, 10)
	m.data[key] = e
	return n, nil
}

// MGet implements Store.
func (m *Memory) MGet(_ context.Context, keys []string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(keys))
	for i, k := range keys {
		if e, ok := m.get(k); ok {
			out[i] = e.value
		}
	}
	return out, nil
}

// Ping implements Store.
func (m *Memory) Ping(context.Context) error { return nil }

// Close implements Store.
func (m *Memory) Close() error { return nil }
