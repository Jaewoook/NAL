package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/jaewoook/security-hub/internal/config"
)

const DefaultHeartbeatInterval = 60 * time.Second

type announcePayload struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	Token     string `json:"token"`
	OSVersion string `json:"os_version"`
}

// ResolveAgentAdvertiseURL returns cfg.AgentAdvertiseURL if set,
// or formats "http://<detected-ip-or-host>:<port>".
func ResolveAgentAdvertiseURL(cfg *config.Config) string {
	if cfg.AgentAdvertiseURL != "" {
		adv := strings.TrimSpace(cfg.AgentAdvertiseURL)
		if !strings.HasPrefix(adv, "http://") && !strings.HasPrefix(adv, "https://") {
			adv = "http://" + adv
		}
		return strings.TrimRight(adv, "/")
	}

	port := cfg.Web.Port
	if port <= 0 {
		port = 10247
	}

	host := detectLocalIPOrHost(cfg.Web.Host)
	return fmt.Sprintf("http://%s:%d", host, port)
}

// ResolveAgentNodeName returns cfg.NodeName or falls back to DefaultNodeName.
func ResolveAgentNodeName(cfg *config.Config) string {
	if strings.TrimSpace(cfg.NodeName) != "" {
		return strings.TrimSpace(cfg.NodeName)
	}
	return config.DefaultNodeName()
}

func detectLocalIPOrHost(bindHost string) string {
	if bindHost != "" && bindHost != "0.0.0.0" && bindHost != "::" && bindHost != "127.0.0.1" && bindHost != "localhost" {
		return bindHost
	}

	if ip := getOutboundIP(); ip != "" {
		return ip
	}

	if h, err := os.Hostname(); err == nil && strings.TrimSpace(h) != "" {
		return strings.TrimSuffix(strings.TrimSpace(h), ".local")
	}

	return "127.0.0.1"
}

func getOutboundIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue
			}
			return ip.String()
		}
	}
	return ""
}

func sendAnnouncement(ctx context.Context, client *http.Client, hubURL string, payload announcePayload) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal announcement payload: %w", err)
	}

	endpoint := strings.TrimRight(hubURL, "/") + "/api/nodes/announce"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("failed to create announcement request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send announcement to hub %q: %w", endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("hub returned status %d from %q: %s", resp.StatusCode, endpoint, strings.TrimSpace(string(body)))
	}
	return nil
}

// StartAnnouncer starts the agent self-introduction loop against the Hub.
// It sends an immediate announcement upon startup, then runs a periodic heartbeat ticker.
// If intervals are supplied, the first one overrides the default 60-second ticker.
func StartAnnouncer(ctx context.Context, cfg *config.Config, httpClient *http.Client, intervals ...time.Duration) <-chan error {
	interval := DefaultHeartbeatInterval
	if len(intervals) > 0 && intervals[0] > 0 {
		interval = intervals[0]
	}

	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: 10 * time.Second,
		}
	}

	errCh := make(chan error, 16)

	go func() {
		defer close(errCh)

		if strings.TrimSpace(cfg.HubURL) == "" {
			return
		}

		payload := announcePayload{
			Name:      ResolveAgentNodeName(cfg),
			URL:       ResolveAgentAdvertiseURL(cfg),
			Token:     cfg.AgentToken,
			OSVersion: runtime.GOOS + "/" + runtime.GOARCH,
		}

		// Immediate announcement on startup
		if err := sendAnnouncement(ctx, httpClient, cfg.HubURL, payload); err != nil {
			if ctx.Err() == nil {
				select {
				case errCh <- err:
				default:
				}
			}
		}

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := sendAnnouncement(ctx, httpClient, cfg.HubURL, payload); err != nil {
					if ctx.Err() == nil {
						select {
						case errCh <- err:
						default:
						}
					}
				}
			}
		}
	}()

	return errCh
}

// StartAnnouncerWithInterval starts the announcement loop with a custom heartbeat ticker.
func StartAnnouncerWithInterval(ctx context.Context, cfg *config.Config, httpClient *http.Client, interval time.Duration) <-chan error {
	return StartAnnouncer(ctx, cfg, httpClient, interval)
}
