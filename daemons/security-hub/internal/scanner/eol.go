package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jaewoook/security-hub/internal/models"
)

type EoLChecker struct {
	baseURL    string
	httpClient *http.Client
}

func NewEoLChecker(baseURL string, httpClient *http.Client) *EoLChecker {
	if baseURL == "" {
		baseURL = "https://endoflife.date/api/v1/products"
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &EoLChecker{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: httpClient,
	}
}

func mapItemToEoLProductAndCycle(item models.ManagedItem) (product, cycle string) {
	ver := cleanUpstreamVersion(item.CurrentVersion)
	parts := strings.Split(ver, ".")
	major := parts[0]
	majorMinor := major
	if len(parts) >= 2 {
		majorMinor = parts[0] + "." + parts[1]
	}

	baseName := stripAptArch(item.Name)
	ref := strings.ToLower(item.ImageRef + " " + baseName)
	switch {
	case strings.Contains(ref, "postgres"):
		return "postgresql", major
	case strings.Contains(ref, "authentik") || baseName == "auth":
		return "authentik", majorMinor
	case strings.Contains(ref, "home-assistant") || strings.Contains(ref, "homeassistant"):
		return "home-assistant", majorMinor
	case strings.Contains(ref, "gerrit"):
		return "gerrit", majorMinor
	case strings.HasPrefix(baseName, "node@") || baseName == "node" || baseName == "nodejs":
		return "nodejs", major
	case strings.HasPrefix(baseName, "openssl@") || baseName == "openssl":
		return "openssl", majorMinor
	case strings.HasPrefix(baseName, "python@") || baseName == "python" || baseName == "python3" || strings.HasPrefix(baseName, "python3."):
		return "python", majorMinor
	case baseName == "go" || strings.HasPrefix(baseName, "go@") || baseName == "golang" || baseName == "golang-go":
		return "go", majorMinor
	case item.TargetType == models.TargetMacOS:
		return "macos", major
	default:
		return "", ""
	}
}

func evaluateEoLWindow(eolDate, now time.Time, warningDays int) (models.EoLStatus, int) {
	todayUTC := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC)
	daysRem := int(eolDate.Sub(todayUTC).Hours() / 24)
	if daysRem < 0 {
		return models.EoLExpired, daysRem
	}
	if daysRem <= warningDays {
		return models.EoLExpiringSoon, daysRem
	}
	return models.EoLSupported, daysRem
}

func isHeldAptItem(item models.ManagedItem) bool {
	return item.TargetType == models.TargetApt && strings.Contains(item.EoL.Message, "Held via apt-mark")
}

func checkCloudflaredSupportWindow(version string, now time.Time, warningDays int) (models.EoLInfo, bool) {
	parts := strings.Split(strings.TrimPrefix(version, "v"), ".")
	if len(parts) < 2 {
		return models.EoLInfo{}, false
	}
	year, errY := strconv.Atoi(parts[0])
	month, errM := strconv.Atoi(parts[1])
	if errY != nil || errM != nil || year < 2020 || month < 1 || month > 12 {
		return models.EoLInfo{}, false
	}
	relDate := time.Date(year, time.Month(month), 15, 0, 0, 0, 0, time.UTC)
	eolDate := relDate.AddDate(1, 0, 0)
	status, daysRem := evaluateEoLWindow(eolDate, now, warningDays)
	return models.EoLInfo{
		Product:       "cloudflared",
		Cycle:         fmt.Sprintf("%d.%d", year, month),
		Status:        status,
		EoLDate:       eolDate.Format("2006-01-02"),
		DaysRemaining: daysRem,
		Message:       "Cloudflare 1-year version support window",
	}, true
}

func withHeldNotice(msg string, isHeld bool) string {
	if !isHeld {
		return msg
	}
	if msg == "" {
		return "Held via apt-mark (pinned)"
	}
	return msg + " · Held via apt-mark (pinned)"
}

func (e *EoLChecker) CheckEoL(ctx context.Context, items []models.ManagedItem, now time.Time, warningDays int) error {
	if warningDays <= 0 {
		warningDays = 30
	}
	type cachedReleases struct {
		releases map[string]string
		ok       bool
	}
	cache := make(map[string]cachedReleases)

	for i := range items {
		if items[i].EoL.Status == models.EoLExpired && items[i].EoL.Message != "" {
			continue
		}
		isHeldApt := isHeldAptItem(items[i])

		if strings.Contains(items[i].ImageRef, "cloudflared") || items[i].Name == "cloudflare-tunnel" {
			if info, ok := checkCloudflaredSupportWindow(items[i].CurrentVersion, now, warningDays); ok {
				info.Message = withHeldNotice(info.Message, isHeldApt)
				items[i].EoL = info
				continue
			}
		}

		prod, cycle := mapItemToEoLProductAndCycle(items[i])
		if prod == "" || cycle == "" || IsFloatingTag(cycle) {
			if items[i].EoL.Status == "" {
				items[i].EoL = models.EoLInfo{
					Status:  models.EoLUnknown,
					Message: "Unmapped / rolling track",
				}
			}
			continue
		}

		entry, cached := cache[prod]
		if !cached {
			rels, ok := e.fetchProductReleases(ctx, prod)
			entry = cachedReleases{releases: rels, ok: ok}
			cache[prod] = entry
		}
		if !entry.ok || len(entry.releases) == 0 {
			items[i].EoL = models.EoLInfo{
				Product: prod,
				Cycle:   cycle,
				Status:  models.EoLUnknown,
				Message: withHeldNotice("EoL status unavailable", isHeldApt),
			}
			continue
		}

		eolDateStr, found := entry.releases[cycle]
		if !found {
			items[i].EoL = models.EoLInfo{
				Product: prod,
				Cycle:   cycle,
				Status:  models.EoLUnknown,
				Message: withHeldNotice(fmt.Sprintf("Cycle %s %s not found in endoflife.date", prod, cycle), isHeldApt),
			}
			continue
		}
		if eolDateStr == "" {
			items[i].EoL = models.EoLInfo{
				Product: prod,
				Cycle:   cycle,
				Status:  models.EoLSupported,
				Message: withHeldNotice(fmt.Sprintf("Active %s %s track", prod, cycle), isHeldApt),
			}
			continue
		}

		eolTime, err := time.Parse("2006-01-02", eolDateStr)
		if err != nil {
			items[i].EoL = models.EoLInfo{
				Product: prod,
				Cycle:   cycle,
				Status:  models.EoLUnknown,
				Message: withHeldNotice("Invalid EoL date returned", isHeldApt),
			}
			continue
		}
		status, daysRem := evaluateEoLWindow(eolTime, now, warningDays)
		items[i].EoL = models.EoLInfo{
			Product:       prod,
			Cycle:         cycle,
			Status:        status,
			EoLDate:       eolDateStr,
			DaysRemaining: daysRem,
			Message:       withHeldNotice("", isHeldApt),
		}
	}
	return nil
}

func (e *EoLChecker) fetchProductReleases(ctx context.Context, product string) (map[string]string, bool) {
	out := make(map[string]string)
	if e.httpClient == nil {
		return out, false
	}
	reqURL := fmt.Sprintf("%s/%s", e.baseURL, url.PathEscape(product))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return out, false
	}
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return out, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, false
	}

	type relItem struct {
		Name    string `json:"name"`
		EoLFrom string `json:"eolFrom"`
	}
	var payload struct {
		Releases []relItem `json:"releases"`
		Result   struct {
			Releases []relItem `json:"releases"`
		} `json:"result"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&payload) != nil {
		return out, false
	}
	for _, rel := range payload.Releases {
		out[rel.Name] = rel.EoLFrom
	}
	for _, rel := range payload.Result.Releases {
		out[rel.Name] = rel.EoLFrom
	}
	return out, len(out) > 0
}
