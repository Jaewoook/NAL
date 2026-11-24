package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	defaultHTTPTimeout    = 5 * time.Second
	maxResponseBodyBytes  = 64 * 1024
)

// httpPoster provides shared JSON HTTP POST delivery and transport configuration
// for HTTP-based notification channels.
type httpPoster struct {
	client *http.Client
}

func newHTTPPoster() httpPoster {
	return httpPoster{
		client: &http.Client{
			Timeout: defaultHTTPTimeout,
		},
	}
}

// SetTransport configures a custom HTTP transport (useful for tests or proxies).
func (p *httpPoster) SetTransport(rt http.RoundTripper) {
	p.client.Transport = rt
}

func (p *httpPoster) postJSON(ctx context.Context, url string, payload any, headers map[string]string) (int, []byte, error) {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	if ctx == nil {
		ctx = context.Background()
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultHTTPTimeout)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	// Always drain up to 64KB so HTTP keep-alive connections can be reused.
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	return resp.StatusCode, respBody, nil
}
