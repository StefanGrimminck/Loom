package ratelimit

import (
	"sync"
	"time"
)

// EventLimiter caps events per second per sensor with a token bucket, so a
// sensor cannot flood the store by packing large batches inside its request
// budget. A nil *EventLimiter allows everything.
type EventLimiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[string]*tokens
	nowFn   func() time.Time
}

type tokens struct {
	n    float64
	last time.Time
}

// NewEventLimiter returns nil (unlimited) when rate <= 0. burst is raised to at
// least minBurst so a single legal batch always fits.
func NewEventLimiter(rate, minBurst int) *EventLimiter {
	if rate <= 0 {
		return nil
	}
	burst := max(2*rate, minBurst)
	return &EventLimiter{
		rate: float64(rate), burst: float64(burst),
		buckets: make(map[string]*tokens), nowFn: time.Now,
	}
}

// AllowN reports whether n events from sensorID fit the budget, consuming them
// if so.
func (l *EventLimiter) AllowN(sensorID string, n int) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.nowFn()
	b, ok := l.buckets[sensorID]
	if !ok {
		b = &tokens{n: l.burst, last: now}
		l.buckets[sensorID] = b
	}
	b.n = min(l.burst, b.n+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if float64(n) > b.n {
		return false
	}
	b.n -= float64(n)
	return true
}
