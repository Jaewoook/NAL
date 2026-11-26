package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jaewoook/security-hub/internal/broker"
	"github.com/jaewoook/security-hub/internal/config"
	"github.com/jaewoook/security-hub/internal/httputil"
)

const (
	defaultPollRetryDelay = 3 * time.Second
	defaultPollHTTPWait   = 45 * time.Second
)

// JobExecutor handles a single reverse-polled Job on an agent node.
type JobExecutor func(ctx context.Context, job broker.Job) broker.JobResult

// StreamingJobExecutor handles a reverse-polled Job with a live log callback that streams lines to the Hub.
type StreamingJobExecutor func(ctx context.Context, job broker.Job, emitLog func(stream, line string)) broker.JobResult

// StartAgentPoller runs the outbound HTTP long-polling loop against the central Hub.
// When the Hub queues a scan/update/rollback job for this agent, the poller executes it
// via execFn and posts the JobResult back to POST /api/nodes/result.
func StartAgentPoller(ctx context.Context, cfg *config.Config, httpClient *http.Client, execFn JobExecutor, retryDelays ...time.Duration) <-chan error {
	if execFn == nil {
		return StartAgentPollerStreaming(ctx, cfg, httpClient, nil, retryDelays...)
	}
	return StartAgentPollerStreaming(ctx, cfg, httpClient, func(ctx context.Context, job broker.Job, _ func(string, string)) broker.JobResult {
		return execFn(ctx, job)
	}, retryDelays...)
}

// StartAgentPollerStreaming runs the outbound HTTP long-polling loop with real-time log streaming to POST /api/nodes/log.
func StartAgentPollerStreaming(ctx context.Context, cfg *config.Config, httpClient *http.Client, execFn StreamingJobExecutor, retryDelays ...time.Duration) <-chan error {
	retryDelay := defaultPollRetryDelay
	if len(retryDelays) > 0 && retryDelays[0] > 0 {
		retryDelay = retryDelays[0]
	}

	errCh := make(chan error, 16)

	go func() {
		defer close(errCh)

		if cfg == nil || strings.TrimSpace(cfg.HubURL) == "" || execFn == nil {
			return
		}

		hubURL := strings.TrimRight(config.NormalizeURL(cfg.HubURL), "/")
		nodeName := ResolveAgentNodeName(cfg)
		pollEndpoint := hubURL + "/api/nodes/poll?name=" + url.QueryEscape(nodeName)
		logEndpoint := hubURL + "/api/nodes/log"
		resultEndpoint := hubURL + "/api/nodes/result"

		pollClient := httputil.NoRedirectClient(httpClient, defaultPollHTTPWait)
		if pollClient.Timeout < defaultPollHTTPWait {
			pollClient.Timeout = defaultPollHTTPWait
		}
		resultClient := httputil.NoRedirectClient(httpClient, 30*time.Second)
		logClient := httputil.NoRedirectClient(httpClient, 5*time.Second)

		emitErr := func(err error) {
			if err != nil && ctx.Err() == nil {
				select {
				case errCh <- err:
				default:
				}
			}
		}

		sleepRetry := func() bool {
			timer := time.NewTimer(retryDelay)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return false
			case <-timer.C:
				return true
			}
		}

		for {
			if ctx.Err() != nil {
				return
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, pollEndpoint, nil)
			if err != nil {
				emitErr(fmt.Errorf("failed to build poll request: %w", err))
				if !sleepRetry() {
					return
				}
				continue
			}
			if cfg.AgentToken != "" {
				req.Header.Set("X-NAL-Node-Token", cfg.AgentToken)
			}

			resp, err := pollClient.Do(req)
			if err != nil {
				emitErr(fmt.Errorf("poll request to %q failed: %w", pollEndpoint, err))
				if !sleepRetry() {
					return
				}
				continue
			}

			if resp.StatusCode == http.StatusNoContent {
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
				resp.Body.Close()
				continue
			}

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
				resp.Body.Close()
				emitErr(fmt.Errorf("hub poll returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body))))
				if !sleepRetry() {
					return
				}
				continue
			}

			var job broker.Job
			decErr := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&job)
			resp.Body.Close()
			if decErr != nil || strings.TrimSpace(job.ID) == "" {
				emitErr(fmt.Errorf("invalid job payload from hub poll: %v", decErr))
				if !sleepRetry() {
					return
				}
				continue
			}

			emitJobLog := func(stream, line string) {
				_ = postJobLog(ctx, logClient, logEndpoint, cfg.AgentToken, broker.JobLogLine{
					JobID:  job.ID,
					Node:   nodeName,
					Stream: stream,
					Line:   line,
				})
			}

			res := execFn(ctx, job, emitJobLog)
			res.JobID = job.ID
			res.Node = nodeName

			if postErr := postJobResult(ctx, resultClient, resultEndpoint, cfg.AgentToken, res); postErr != nil {
				emitErr(postErr)
			}
		}
	}()

	return errCh
}

func postJobLog(ctx context.Context, client *http.Client, endpoint, token string, entry broker.JobLogLine) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-NAL-Node-Token", token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 512))
	resp.Body.Close()
	return nil
}

func postJobResult(ctx context.Context, client *http.Client, endpoint, token string, res broker.JobResult) error {
	data, err := json.Marshal(res)
	if err != nil {
		return fmt.Errorf("failed to marshal job result %q: %w", res.JobID, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to build result request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("X-NAL-Node-Token", token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to post job result %q to hub: %w", res.JobID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("hub result endpoint returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}
