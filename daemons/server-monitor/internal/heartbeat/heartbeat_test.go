package heartbeat

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestHeartbeatTick(t *testing.T) {
	var count int32
	sender := New("http://heartbeat.example.com/ping", 60*time.Second)
	sender.SetTransport(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		atomic.AddInt32(&count, 1)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("ok")),
			Header:     make(http.Header),
		}, nil
	}))
	t0 := time.Now()

	// First tick -> sends
	if !sender.Tick(t0) {
		t.Fatalf("expected first tick to send")
	}
	if atomic.LoadInt32(&count) != 1 {
		t.Fatalf("expected 1 ping")
	}

	// Before interval -> does not send
	if sender.Tick(t0.Add(30 * time.Second)) {
		t.Fatalf("should not send before interval")
	}

	// After interval -> sends
	if !sender.Tick(t0.Add(65 * time.Second)) {
		t.Fatalf("expected tick to send after interval")
	}
	if atomic.LoadInt32(&count) != 2 {
		t.Fatalf("expected 2 pings")
	}
}

func TestHeartbeatNetworkErrorGraceful(t *testing.T) {
	sender := New("http://unreachable.example.com/ping", 60*time.Second)
	sender.SetTransport(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, errors.New("connection refused")
	}))

	t0 := time.Now()
	// Tick should gracefully catch network error without panicking
	if !sender.Tick(t0) {
		t.Fatalf("expected tick to trigger even if network fails")
	}

	if sender.LastError() == nil {
		t.Fatalf("expected last error to record connection refused, got nil")
	}
	if !strings.Contains(sender.LastError().Error(), "connection refused") {
		t.Fatalf("expected connection refused error, got: %v", sender.LastError())
	}
}

func TestHeartbeatHTTPStatusError(t *testing.T) {
	sender := New("http://status500.example.com/ping", 60*time.Second)
	sender.SetTransport(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       io.NopCloser(strings.NewReader("server failure")),
			Header:     make(http.Header),
		}, nil
	}))

	ctx := context.Background()
	err := sender.Ping(ctx)
	if err == nil {
		t.Fatalf("expected error on HTTP 500 response, got nil")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Fatalf("expected error to mention status 500, got: %v", err)
	}
}

func TestHeartbeatEmptyURL(t *testing.T) {
	sender := New("", 60*time.Second)
	t0 := time.Now()

	if sender.Tick(t0) {
		t.Fatalf("expected tick to return false when URL is empty")
	}

	err := sender.Ping(context.Background())
	if err == nil {
		t.Fatalf("expected error when URL is empty, got nil")
	}
	if !strings.Contains(err.Error(), "not configured") {
		t.Fatalf("expected error to mention not configured, got: %v", err)
	}
}

func TestHeartbeatUserAgentAndMethod(t *testing.T) {
	var capturedUserAgent string
	var capturedMethod string

	sender := New("http://example.com/ping", 60*time.Second)
	sender.SetTransport(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		capturedUserAgent = r.Header.Get("User-Agent")
		capturedMethod = r.Method
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("ok")),
			Header:     make(http.Header),
		}, nil
	}))

	// Ping with nil context should default to 5s timeout internally
	if err := sender.Ping(nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if capturedUserAgent != "server-monitor/1.0" {
		t.Errorf("expected User-Agent 'server-monitor/1.0', got '%s'", capturedUserAgent)
	}
	if capturedMethod != http.MethodGet {
		t.Errorf("expected default method GET, got '%s'", capturedMethod)
	}

	// Test POST method configuration
	sender.SetMethod(http.MethodPost)
	if err := sender.Ping(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedMethod != http.MethodPost {
		t.Errorf("expected configured method POST, got '%s'", capturedMethod)
	}
}

func TestHeartbeatDefaultsAndReset(t *testing.T) {
	sender := New("http://example.com", 0)
	if sender.Interval() != 60*time.Second {
		t.Errorf("expected default interval 60s, got %v", sender.Interval())
	}
	if sender.URL() != "http://example.com" {
		t.Errorf("expected URL 'http://example.com', got '%s'", sender.URL())
	}

	senderNegative := NewWithClient("http://example.com", -10*time.Second, nil)
	if senderNegative.Interval() != 60*time.Second {
		t.Errorf("expected default interval 60s for negative interval, got %v", senderNegative.Interval())
	}

	customClient := &http.Client{Timeout: 10 * time.Second}
	sender.SetClient(customClient)

	t0 := time.Now()
	sender.SetTransport(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("ok")),
			Header:     make(http.Header),
		}, nil
	}))

	sender.Tick(t0)
	if sender.LastTick().IsZero() {
		t.Errorf("expected LastTick to be set")
	}

	sender.Reset()
	if !sender.LastTick().IsZero() {
		t.Errorf("expected LastTick to be reset to zero")
	}
	if sender.LastError() != nil {
		t.Errorf("expected LastError to be reset to nil")
	}
}

func TestHeartbeatConcurrentTicks(t *testing.T) {
	var count int32
	sender := New("http://concurrent.example.com", 60*time.Second)
	sender.SetTransport(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		atomic.AddInt32(&count, 1)
		time.Sleep(10 * time.Millisecond)
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("ok")),
			Header:     make(http.Header),
		}, nil
	}))

	t0 := time.Now()
	var wg sync.WaitGroup
	var sentCount int32

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if sender.Tick(t0) {
				atomic.AddInt32(&sentCount, 1)
			}
		}()
	}
	wg.Wait()

	if atomic.LoadInt32(&sentCount) != 1 {
		t.Errorf("expected exactly 1 tick to send concurrently, got %d", atomic.LoadInt32(&sentCount))
	}
	if atomic.LoadInt32(&count) != 1 {
		t.Errorf("expected exactly 1 ping to occur, got %d", atomic.LoadInt32(&count))
	}
}

func TestHeartbeatContextDeadlineEnforced(t *testing.T) {
	var hasDeadline bool
	sender := NewWithClient("http://example.com/ping", 60*time.Second, &http.Client{})
	sender.SetTransport(roundTripFunc(func(r *http.Request) (*http.Response, error) {
		_, hasDeadline = r.Context().Deadline()
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("ok")),
			Header:     make(http.Header),
		}, nil
	}))

	// Ping with context without deadline (context.Background())
	if err := sender.Ping(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasDeadline {
		t.Fatalf("expected request context to have deadline enforced")
	}
}

