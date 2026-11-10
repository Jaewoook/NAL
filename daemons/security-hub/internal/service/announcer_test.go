package service_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jaewoook/security-hub/internal/config"
	"github.com/jaewoook/security-hub/internal/service"
)

type announcePayload struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	Token     string `json:"token"`
	OSVersion string `json:"os_version"`
}

func TestStartAnnouncer_InitialAndHeartbeat(t *testing.T) {
	var mu sync.Mutex
	var received []announcePayload

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/nodes/announce" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var p announcePayload
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		mu.Lock()
		received = append(received, p)
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "approved"})
	}))
	defer srv.Close()

	cfg := &config.Config{
		NodeName:          "TestNode-Alpha",
		AgentToken:        "super-secret-token",
		HubURL:            srv.URL,
		AgentAdvertiseURL: "http://192.168.1.199:10247",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Use short ticker interval (15ms)
	errCh := service.StartAnnouncer(ctx, cfg, srv.Client(), 15*time.Millisecond)

	// Wait for at least 3 payloads (initial + 2 heartbeats)
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		count := len(received)
		mu.Unlock()
		if count >= 3 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	count := len(received)
	first := announcePayload{}
	if count > 0 {
		first = received[0]
	}
	mu.Unlock()

	if count < 3 {
		t.Fatalf("expected at least 3 announcements (initial + periodic heartbeats), got %d", count)
	}

	expectedOS := runtime.GOOS + "/" + runtime.GOARCH
	if first.Name != "TestNode-Alpha" {
		t.Errorf("expected Name %q, got %q", "TestNode-Alpha", first.Name)
	}
	if first.URL != "http://192.168.1.199:10247" {
		t.Errorf("expected URL %q, got %q", "http://192.168.1.199:10247", first.URL)
	}
	if first.Token != "super-secret-token" {
		t.Errorf("expected Token %q, got %q", "super-secret-token", first.Token)
	}
	if first.OSVersion != expectedOS {
		t.Errorf("expected OSVersion %q, got %q", expectedOS, first.OSVersion)
	}

	// Cancel context and assert goroutine terminates cleanly and closes channel
	cancel()

	done := make(chan struct{})
	go func() {
		for range errCh {
		}
		close(done)
	}()

	select {
	case <-done:
		// Terminated cleanly
	case <-time.After(1 * time.Second):
		t.Fatal("announcer goroutine failed to terminate cleanly after context cancellation")
	}
}

func TestStartAnnouncer_AutoDetectAdvertiseURL(t *testing.T) {
	var mu sync.Mutex
	var received []announcePayload

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p announcePayload
		_ = json.NewDecoder(r.Body).Decode(&p)
		mu.Lock()
		received = append(received, p)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "pending"})
	}))
	defer srv.Close()

	cfg := &config.Config{
		AgentToken: "tok-123",
		HubURL:     srv.URL + "/", // Test trailing slash handling
		Web: config.WebConfig{
			Port: 10247,
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := service.StartAnnouncer(ctx, cfg, srv.Client(), 20*time.Millisecond)

	// Wait for first announcement
	deadline := time.Now().Add(1 * time.Second)
	for {
		mu.Lock()
		count := len(received)
		mu.Unlock()
		if count >= 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	for range errCh {
	}

	mu.Lock()
	defer mu.Unlock()
	if len(received) == 0 {
		t.Fatal("expected at least 1 announcement")
	}

	first := received[0]
	if first.Name == "" {
		t.Errorf("expected non-empty default node name, got empty")
	}
	if !strings.HasPrefix(first.URL, "http://") || !strings.Contains(first.URL, ":10247") {
		t.Errorf("expected URL to format http://<ip-or-host>:10247, got %q", first.URL)
	}
	if first.Token != "tok-123" {
		t.Errorf("expected token %q, got %q", "tok-123", first.Token)
	}
}

func TestStartAnnouncer_ErrorEmittedOnHubFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := &config.Config{
		NodeName:          "FailNode",
		AgentToken:        "tok",
		HubURL:            srv.URL,
		AgentAdvertiseURL: "http://127.0.0.1:10247",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := service.StartAnnouncer(ctx, cfg, srv.Client(), 50*time.Millisecond)

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("expected non-nil error from failing hub")
		}
		if !strings.Contains(err.Error(), "500") {
			t.Errorf("expected error to mention 500, got: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for error on errCh")
	}

	cancel()
	for range errCh {
	}
}
