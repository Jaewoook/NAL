package httputil

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNoRedirectClient_DisablesRedirectsAndPreservesTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://example.com/evil", http.StatusFound)
	}))
	defer srv.Close()

	c := NoRedirectClient(nil, 4*time.Second)
	if c.Timeout != 4*time.Second {
		t.Fatalf("expected fallback timeout 4s, got %v", c.Timeout)
	}
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 without following redirect, got %d", resp.StatusCode)
	}

	base := &http.Client{Timeout: 9 * time.Second}
	c2 := NoRedirectClient(base, 4*time.Second)
	if c2.Timeout != 9*time.Second {
		t.Fatalf("expected preserved timeout 9s, got %v", c2.Timeout)
	}
}
