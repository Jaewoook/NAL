package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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
	if cfg != nil && strings.TrimSpace(cfg.AgentAdvertiseURL) != "" {
		return config.NormalizeURL(cfg.AgentAdvertiseURL)
	}

	port := 10247
	bindHost := ""
	hubURL := ""
	if cfg != nil {
		if cfg.Web.Port > 0 {
			port = cfg.Web.Port
		}
		bindHost = cfg.Web.Host
		hubURL = cfg.HubURL
	}

	host := detectLocalIPOrHost(bindHost, hubURL)
	return fmt.Sprintf("http://%s:%d", host, port)
}

// ResolveAgentNodeName returns cfg.NodeName or falls back to DefaultNodeName.
func ResolveAgentNodeName(cfg *config.Config) string {
	if cfg != nil && strings.TrimSpace(cfg.NodeName) != "" {
		return strings.TrimSpace(cfg.NodeName)
	}
	return config.DefaultNodeName()
}

// IsVirtualInterface returns true if the network interface name matches known virtual/bridge patterns.
func IsVirtualInterface(name string) bool {
	lower := strings.ToLower(name)
	prefixes := []string{"docker", "br-", "br0", "br1", "bridge", "veth", "virbr", "cni", "tailscale", "tun", "utun", "tap", "flannel", "vmnet", "awdl", "llw"}
	for _, p := range prefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

func getOutboundIPToHost(hubURL string) string {
	hubURL = config.NormalizeURL(hubURL)
	u, err := url.Parse(hubURL)
	if err == nil && u.Host != "" {
		host := u.Host
		if _, _, err := net.SplitHostPort(host); err != nil {
			if u.Scheme == "https" {
				host = net.JoinHostPort(host, "443")
			} else {
				host = net.JoinHostPort(host, "80")
			}
		}
		conn, err := net.DialTimeout("udp", host, 2*time.Second)
		if err == nil {
			defer conn.Close()
			if localAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok && localAddr.IP != nil && !localAddr.IP.IsLoopback() {
				if ip4 := localAddr.IP.To4(); ip4 != nil {
					return ip4.String()
				}
			}
		}
	}
	return ""
}

func detectLocalIPOrHost(bindHost, hubURL string) string {
	if bindHost != "" && bindHost != "0.0.0.0" && bindHost != "::" && bindHost != "127.0.0.1" && bindHost != "localhost" {
		return bindHost
	}

	// 1. Preferred: Query kernel routing table towards Hub host
	if hubURL != "" {
		if ip := getOutboundIPToHost(hubURL); ip != "" {
			return ip
		}
	}

	// 2. Physical active non-virtual network interface
	if ip := getOutboundIP(); ip != "" {
		return ip
	}

	// 3. System hostname
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
		if IsVirtualInterface(iface.Name) {
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
	hubURL = config.NormalizeURL(hubURL)
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
				if strings.Contains(payload.URL, "127.0.0.1") {
					payload.URL = ResolveAgentAdvertiseURL(cfg)
				}
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
