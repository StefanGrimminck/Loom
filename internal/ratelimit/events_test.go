package ratelimit

import (
	"testing"
	"time"
)

func TestEventLimiter(t *testing.T) {
	if NewEventLimiter(0, 500) != nil || !(*EventLimiter)(nil).AllowN("s", 1e6) {
		t.Fatal("zero rate must disable the limiter")
	}
	l := NewEventLimiter(100, 500)
	now := time.Unix(0, 0)
	l.nowFn = func() time.Time { return now }
	if !l.AllowN("a", 500) {
		t.Fatal("a full batch must fit the initial burst")
	}
	if l.AllowN("a", 1) {
		t.Fatal("bucket should be empty")
	}
	if !l.AllowN("b", 500) {
		t.Fatal("sensors must have separate budgets")
	}
	now = now.Add(time.Second)
	if !l.AllowN("a", 100) || l.AllowN("a", 1) {
		t.Fatal("refill should be rate per second")
	}
}
