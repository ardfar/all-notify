package admin

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const maxTrackedIPs = 4096

// RateLimiter implements a bounded in-memory sliding-window limiter per client IP.
type RateLimiter struct {
	limit  int
	window time.Duration
	now    func() time.Time

	mu      sync.Mutex
	buckets map[string][]time.Time
}

func NewRateLimiter(limit int, window time.Duration, now func() time.Time) *RateLimiter {
	if now == nil {
		now = time.Now
	}
	return &RateLimiter{
		limit:   limit,
		window:  window,
		now:     now,
		buckets: make(map[string][]time.Time),
	}
}

// Allow checks whether key is under limit and, if so, records the event.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	t := rl.now()
	cutoff := t.Add(-rl.window)
	ts := pruneTimestamps(rl.buckets[key], cutoff)
	if len(ts) >= rl.limit {
		rl.buckets[key] = ts
		return false
	}
	rl.ensureCapacityLocked(cutoff)
	rl.buckets[key] = append(ts, t)
	return true
}

// IsLimited reports whether key has already reached the limit without recording a new event.
func (rl *RateLimiter) IsLimited(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := rl.now().Add(-rl.window)
	ts := pruneTimestamps(rl.buckets[key], cutoff)
	if len(ts) == 0 {
		delete(rl.buckets, key)
		return false
	}
	rl.buckets[key] = ts
	return len(ts) >= rl.limit
}

// Record records one event (e.g., a failed login attempt) for key.
func (rl *RateLimiter) Record(key string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	t := rl.now()
	cutoff := t.Add(-rl.window)
	ts := pruneTimestamps(rl.buckets[key], cutoff)
	rl.ensureCapacityLocked(cutoff)
	rl.buckets[key] = append(ts, t)
}

func (rl *RateLimiter) Reset(key string) {
	rl.mu.Lock()
	delete(rl.buckets, key)
	rl.mu.Unlock()
}

func (rl *RateLimiter) ensureCapacityLocked(cutoff time.Time) {
	if len(rl.buckets) < maxTrackedIPs {
		return
	}
	for k, v := range rl.buckets {
		pruned := pruneTimestamps(v, cutoff)
		if len(pruned) == 0 {
			delete(rl.buckets, k)
		} else {
			rl.buckets[k] = pruned
		}
	}
	if len(rl.buckets) >= maxTrackedIPs {
		// Evict only the single stalest bucket instead of clearing active bans.
		var oldestKey string
		var oldestTime time.Time
		first := true
		for k, v := range rl.buckets {
			last := v[len(v)-1]
			if first || last.Before(oldestTime) {
				oldestKey = k
				oldestTime = last
				first = false
			}
		}
		if !first {
			delete(rl.buckets, oldestKey)
		}
	}
}

func pruneTimestamps(in []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for i < len(in) && !in[i].After(cutoff) {
		i++
	}
	if i == 0 {
		return in
	}
	return append(in[:0], in[i:]...)
}

// ClientIP extracts the client IP address. When trustProxy is true, the rightmost valid IP
// in X-Forwarded-For is used (preventing spoofing of leading entries behind a reverse proxy).
func ClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				cand := strings.TrimSpace(parts[i])
				if ip := net.ParseIP(cand); ip != nil {
					return ip.String()
				}
			}
		}
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}
