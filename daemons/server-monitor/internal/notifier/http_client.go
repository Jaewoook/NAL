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
	defaultMaxRetries     = 2
	defaultRetryBaseDelay = 250 * time.Millisecond
)

// httpPoster provides shared JSON HTTP POST delivery with bounded retries on
// transient failures (network errors, HTTP 429, and 5xx) and transport configuration.
type httpPoster struct {
	client         *http.Client
	maxRetries     int
	retryBaseDelay time.Duration
}

func newHTTPPoster() httpPoster {
	return httpPoster{
		client: &http.Client{
			Timeout: defaultHTTPTimeout,
		},
		maxRetries:     defaultMaxRetries,
		retryBaseDelay: defaultRetryBaseDelay,
	}
}

// SetTransport configures a custom HTTP transport (useful for tests or proxies).
func (p *httpPoster) SetTransport(rt http.RoundTripper) {
	p.client.Transport = rt
}

func isRetryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

func waitWithContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
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

	maxAttempts := 1 + p.maxRetries
	if maxAttempts < 1 {
		maxAttempts = 1
	}

	var (
		lastStatus int
		lastBody   []byte
		lastErr    error
	)

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			delay := p.retryBaseDelay << (attempt - 1)
			if err := waitWithContext(ctx, delay); err != nil {
				if lastErr != nil {
					return 0, nil, lastErr
				}
				return lastStatus, lastBody, nil
			}
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
			lastErr = err
			lastStatus = 0
			lastBody = nil
			if ctx.Err() != nil {
				return 0, nil, err
			}
			continue
		}

		// Always drain up to 64KB so HTTP keep-alive connections can be reused.
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
		_ = resp.Body.Close()

		lastStatus = resp.StatusCode
		lastBody = respBody
		lastErr = nil

		if !isRetryableStatus(resp.StatusCode) {
			return resp.StatusCode, respBody, nil
		}
	}

	return lastStatus, lastBody, lastErr
}
