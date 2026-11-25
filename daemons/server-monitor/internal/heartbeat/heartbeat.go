package heartbeat

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/jaewoook/server-monitor/internal/models"
)

const (
	defaultAttemptTimeout    = 5 * time.Second
	defaultTotalTimeout      = 15 * time.Second
	defaultMaxRetries        = 2
	defaultRetryBaseDelay    = 250 * time.Millisecond
	defaultFailRetryInterval = 15 * time.Second
)

// Sender manages periodic dead-man's-switch aliveness pings to an external uptime service.
type Sender struct {
	mu                sync.Mutex
	url               string
	interval          time.Duration
	lastTick          time.Time
	nextDue           time.Time
	lastErr           error
	method            string
	client            *http.Client
	logger            *log.Logger
	attemptTimeout    time.Duration
	maxRetries        int
	retryBaseDelay    time.Duration
	failRetryInterval time.Duration
}

// New creates a new Sender with the specified heartbeat ping URL and interval.
func New(url string, interval time.Duration) *Sender {
	return NewWithClient(url, interval, &http.Client{
		Timeout: defaultAttemptTimeout,
	})
}

// NewWithClient creates a new Sender with a custom http.Client (e.g. for testing).
func NewWithClient(url string, interval time.Duration, client *http.Client) *Sender {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	if client == nil {
		client = &http.Client{
			Timeout: defaultAttemptTimeout,
		}
	}
	return &Sender{
		url:               url,
		interval:          interval,
		client:            client,
		method:            http.MethodGet,
		attemptTimeout:    defaultAttemptTimeout,
		maxRetries:        defaultMaxRetries,
		retryBaseDelay:    defaultRetryBaseDelay,
		failRetryInterval: defaultFailRetryInterval,
	}
}

// SetLogger configures a custom logger for heartbeat warnings.
func (s *Sender) SetLogger(l *log.Logger) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logger = l
}

func (s *Sender) logf(format string, args ...any) {
	s.mu.Lock()
	l := s.logger
	s.mu.Unlock()
	if l != nil {
		l.Printf(format, args...)
		return
	}
	log.Printf(format, args...)
}

// URL returns the heartbeat ping URL.
func (s *Sender) URL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.url
}

// Interval returns the ping interval.
func (s *Sender) Interval() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.interval
}

// LastTick returns the timestamp of the last tick attempt.
func (s *Sender) LastTick() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastTick
}

// LastError returns the error from the most recent ping, if any.
func (s *Sender) LastError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastErr
}

// SetMethod sets the HTTP method used for pinging (e.g. GET or POST).
func (s *Sender) SetMethod(method string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.method = method
}

// SetClient replaces the internal HTTP client.
func (s *Sender) SetClient(client *http.Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if client != nil {
		s.client = client
	}
}

// SetTransport sets the transport on the internal HTTP client.
func (s *Sender) SetTransport(rt http.RoundTripper) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client != nil {
		s.client.Transport = rt
	}
}

// Reset clears the last tick timestamp, retry schedule, and last error.
func (s *Sender) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastTick = time.Time{}
	s.nextDue = time.Time{}
	s.lastErr = nil
}

// Ping sends an HTTP request to the configured heartbeat URL with bounded retries
// on transient network errors, timeouts, HTTP 429, and 5xx responses.
// Each attempt is bounded by attemptTimeout (default 5s) within an overall 15s budget
// if the provided context lacks a deadline.
func (s *Sender) Ping(ctx context.Context) error {
	s.mu.Lock()
	url := s.url
	method := s.method
	client := s.client
	attemptTimeout := s.attemptTimeout
	maxRetries := s.maxRetries
	retryBaseDelay := s.retryBaseDelay
	s.mu.Unlock()

	if url == "" {
		return errors.New("heartbeat URL is not configured")
	}

	if method == "" {
		method = http.MethodGet
	}
	if attemptTimeout <= 0 {
		attemptTimeout = defaultAttemptTimeout
	}

	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTotalTimeout)
		defer cancel()
	}

	maxAttempts := 1 + maxRetries
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			delay := retryBaseDelay << (attempt - 1)
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return lastErr
			case <-timer.C:
			}
		}

		attemptCtx, attemptCancel := context.WithTimeout(ctx, attemptTimeout)
		req, err := http.NewRequestWithContext(attemptCtx, method, url, nil)
		if err != nil {
			attemptCancel()
			return fmt.Errorf("failed to create heartbeat request: %w", err)
		}
		req.Header.Set("User-Agent", models.UserAgent)

		resp, err := client.Do(req)
		if err != nil {
			attemptCancel()
			lastErr = fmt.Errorf("heartbeat ping failed: %w", err)
			if ctx.Err() != nil {
				return lastErr
			}
			continue
		}

		// Drain up to 64KB to allow connection reuse
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
		_ = resp.Body.Close()
		attemptCancel()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		lastErr = fmt.Errorf("heartbeat endpoint returned status %d", resp.StatusCode)
		if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode < 500 {
			return lastErr
		}
	}

	return lastErr
}

// Tick checks whether the interval has elapsed and sends a ping if due.
func (s *Sender) Tick(now time.Time) bool {
	return s.TickContext(context.Background(), now)
}

// TickContext checks whether the next ping is due and sends it, honoring ctx.
// On ping failure, the next attempt is scheduled sooner (min(interval, failRetryInterval))
// so transient network blips do not cause a full interval gap.
func (s *Sender) TickContext(ctx context.Context, now time.Time) bool {
	if now.IsZero() {
		now = time.Now()
	}
	if ctx == nil {
		ctx = context.Background()
	}

	s.mu.Lock()
	url := s.url
	if url == "" {
		s.mu.Unlock()
		return false
	}
	if !s.nextDue.IsZero() && now.Before(s.nextDue) {
		s.mu.Unlock()
		return false
	}
	s.lastTick = now
	s.nextDue = now.Add(s.interval)
	retryDelay := s.failRetryInterval
	if retryDelay <= 0 || retryDelay > s.interval {
		retryDelay = s.interval
	}
	s.mu.Unlock()

	pingCtx, cancel := context.WithTimeout(ctx, defaultTotalTimeout)
	defer cancel()

	err := s.Ping(pingCtx)

	s.mu.Lock()
	s.lastErr = err
	if err != nil {
		s.nextDue = now.Add(retryDelay)
	}
	s.mu.Unlock()

	if err != nil {
		s.logf("[heartbeat] ping to %s failed: %v", url, err)
	}

	return true
}
