package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jaewoook/system-updater/internal/models"
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
	ver := strings.TrimPrefix(item.CurrentVersion, "v")
	if idx := strings.IndexByte(ver, '-'); idx > 0 {
		ver = ver[:idx]
	}
	if idx := strings.IndexByte(ver, '_'); idx > 0 {
		ver = ver[:idx]
	}
	parts := strings.Split(ver, ".")
	major := parts[0]
	majorMinor := major
	if len(parts) >= 2 {
		majorMinor = parts[0] + "." + parts[1]
	}

	ref := strings.ToLower(item.ImageRef + " " + item.Name)
	switch {
	case strings.Contains(ref, "postgres"):
		return "postgresql", major
	case strings.Contains(ref, "authentik") || item.Name == "auth":
		return "authentik", majorMinor
	case strings.Contains(ref, "home-assistant") || strings.Contains(ref, "homeassistant"):
		return "home-assistant", majorMinor
	case strings.Contains(ref, "gerrit"):
		return "gerrit", majorMinor
	case strings.HasPrefix(item.Name, "node@") || item.Name == "node":
		return "nodejs", major
	case strings.HasPrefix(item.Name, "openssl@") || item.Name == "openssl":
		return "openssl", majorMinor
	case strings.HasPrefix(item.Name, "python@") || item.Name == "python":
		return "python", majorMinor
	case item.Name == "go" || strings.HasPrefix(item.Name, "go@"):
		return "go", majorMinor
	case item.TargetType == models.TargetMacOS:
		return "macos", major
	default:
		return "", ""
	}
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
	daysRem := int(eolDate.Sub(now).Hours() / 24)
	status := models.EoLSupported
	if daysRem < 0 {
		status = models.EoLExpired
	} else if daysRem <= warningDays {
		status = models.EoLExpiringSoon
	}
	return models.EoLInfo{
		Product:       "cloudflared",
		Cycle:         fmt.Sprintf("%d.%d", year, month),
		Status:        status,
		EoLDate:       eolDate.Format("2006-01-02"),
		DaysRemaining: daysRem,
		Message:       "Cloudflare 1-year version support window",
	}, true
}

func (e *EoLChecker) CheckEoL(ctx context.Context, items []models.ManagedItem, now time.Time, warningDays int) error {
	if warningDays <= 0 {
		warningDays = 30
	}
	cache := make(map[string]map[string]string)

	for i := range items {
		if items[i].EoL.Status == models.EoLExpired && items[i].EoL.Message != "" {
			continue
		}
		if strings.Contains(items[i].ImageRef, "cloudflared") || items[i].Name == "cloudflare-tunnel" {
			if info, ok := checkCloudflaredSupportWindow(items[i].CurrentVersion, now, warningDays); ok {
				items[i].EoL = info
				continue
			}
		}

		prod, cycle := mapItemToEoLProductAndCycle(items[i])
		if prod == "" || cycle == "" || IsFloatingTag(cycle) {
			if items[i].EoL.Status == "" || items[i].EoL.Status == models.EoLUnknown {
				items[i].EoL = models.EoLInfo{
					Status:  models.EoLSupported,
					Message: "Rolling / active upstream track",
				}
			}
			continue
		}

		releases, cached := cache[prod]
		if !cached {
			releases = e.fetchProductReleases(ctx, prod)
			cache[prod] = releases
		}
		eolDateStr, found := releases[cycle]
		if !found || eolDateStr == "" {
			items[i].EoL = models.EoLInfo{
				Product: prod,
				Cycle:   cycle,
				Status:  models.EoLSupported,
				Message: fmt.Sprintf("Active %s %s track", prod, cycle),
			}
			continue
		}

		eolTime, err := time.Parse("2006-01-02", eolDateStr)
		if err != nil {
			continue
		}
		todayUTC := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC)
		daysRem := int(eolTime.Sub(todayUTC).Hours() / 24)
		status := models.EoLSupported
		if daysRem < 0 {
			status = models.EoLExpired
		} else if daysRem <= warningDays {
			status = models.EoLExpiringSoon
		}
		items[i].EoL = models.EoLInfo{
			Product:       prod,
			Cycle:         cycle,
			Status:        status,
			EoLDate:       eolDateStr,
			DaysRemaining: daysRem,
		}
	}
	return nil
}

func (e *EoLChecker) fetchProductReleases(ctx context.Context, product string) map[string]string {
	out := make(map[string]string)
	if e.httpClient == nil {
		return out
	}
	url := fmt.Sprintf("%s/%s", e.baseURL, product)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return out
	}
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return out
	}
	defer resp.Body.Close()

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
	if json.NewDecoder(resp.Body).Decode(&payload) == nil {
		for _, rel := range payload.Releases {
			out[rel.Name] = rel.EoLFrom
		}
		for _, rel := range payload.Result.Releases {
			out[rel.Name] = rel.EoLFrom
		}
	}
	return out
}
