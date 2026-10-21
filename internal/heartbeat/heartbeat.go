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
)

// Sender manages periodic dead-man's-switch aliveness pings to an external uptime service.
type Sender struct {
	mu       sync.Mutex
	url      string
	interval time.Duration
	lastTick time.Time
	lastErr  error
	method   string
	client   *http.Client
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
		url:      url,
		interval: interval,
		client:   client,
		method:   http.MethodGet,
	}
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

// Ping sends an HTTP request to the configured heartbeat URL.
// It enforces a 5-second timeout if the provided context lacks a deadline.
func (s *Sender) Ping(ctx context.Context) error {
	s.mu.Lock()
	url := s.url
	method := s.method
	client := s.client
	s.mu.Unlock()

	if url == "" {
		return errors.New("heartbeat URL is not configured")
	}

	if method == "" {
		method = http.MethodGet
	}

	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return fmt.Errorf("failed to create heartbeat request: %w", err)
	}
	req.Header.Set("User-Agent", "server-monitor/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("heartbeat ping failed: %w", err)
	}
	defer resp.Body.Close()

	// Drain up to 64KB to allow connection reuse
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("heartbeat endpoint returned status %d", resp.StatusCode)
	}

	return nil
}

// Tick checks whether the interval has elapsed and sends a ping if due.
// It catches all network errors gracefully, records the error, and returns
// true if a ping was triggered, or false if skipped before interval.
func (s *Sender) Tick(now time.Time) bool {
	if now.IsZero() {
		now = time.Now()
	}

	s.mu.Lock()
	if s.url == "" {
		s.mu.Unlock()
		return false
	}
	if !s.lastTick.IsZero() && now.Sub(s.lastTick) < s.interval {
		s.mu.Unlock()
		return false
	}
	s.lastTick = now
	s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := s.Ping(ctx)

	s.mu.Lock()
	s.lastErr = err
	s.mu.Unlock()

	if err != nil {
		log.Printf("[heartbeat] ping to %s failed: %v", s.url, err)
	}

	return true
}
