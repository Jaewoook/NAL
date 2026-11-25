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
	defaultMaxRetries     = 2
	defaultRetryBaseDelay = 250 * time.Millisecond
)

// Sender manages periodic dead-man's-switch aliveness pings to an external uptime service.
type Sender struct {
	mu             sync.Mutex
	url            string
	interval       time.Duration
	lastTick       time.Time
	lastErr        error
	method         string
	client         *http.Client
	logger         *log.Logger
	maxRetries     int
	retryBaseDelay time.Duration
}

// New creates a new Sender with the specified heartbeat ping URL and interval.
func New(url string, interval time.Duration) *Sender {
	return NewWithClient(url, interval, &http.Client{
		Timeout: 5 * time.Second,
	})
}

// NewWithClient creates a new Sender with a custom http.Client (e.g. for testing).
func NewWithClient(url string, interval time.Duration, client *http.Client) *Sender {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	if client == nil {
		client = &http.Client{
			Timeout: 5 * time.Second,
		}
	}
	return &Sender{
		url:            url,
		interval:       interval,
		client:         client,
		method:         http.MethodGet,
		maxRetries:     defaultMaxRetries,
		retryBaseDelay: defaultRetryBaseDelay,
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

// Reset clears the last tick timestamp and last error.
func (s *Sender) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastTick = time.Time{}
	s.lastErr = nil
}

// Ping sends an HTTP request to the configured heartbeat URL with bounded retries
// on transient network errors, HTTP 429, and 5xx responses.
// It enforces a 5-second timeout if the provided context lacks a deadline.
func (s *Sender) Ping(ctx context.Context) error {
	s.mu.Lock()
	url := s.url
	method := s.method
	client := s.client
	maxRetries := s.maxRetries
	retryBaseDelay := s.retryBaseDelay
	s.mu.Unlock()

	if url == "" {
		return errors.New("heartbeat URL is not configured")
	}

	if method == "" {
		method = http.MethodGet
	}

	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
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

		req, err := http.NewRequestWithContext(ctx, method, url, nil)
		if err != nil {
			return fmt.Errorf("failed to create heartbeat request: %w", err)
		}
		req.Header.Set("User-Agent", models.UserAgent)

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("heartbeat ping failed: %w", err)
			if ctx.Err() != nil {
				return lastErr
			}
			continue
		}

		// Drain up to 64KB to allow connection reuse
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
		_ = resp.Body.Close()

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

// TickContext checks whether the interval has elapsed and sends a ping if due,
// honoring ctx for cancellation and deadlines.
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
	if !s.lastTick.IsZero() && now.Sub(s.lastTick) < s.interval {
		s.mu.Unlock()
		return false
	}
	s.lastTick = now
	s.mu.Unlock()

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	err := s.Ping(pingCtx)

	s.mu.Lock()
	s.lastErr = err
	s.mu.Unlock()

	if err != nil {
		s.logf("[heartbeat] ping to %s failed: %v", url, err)
	}

	return true
}
