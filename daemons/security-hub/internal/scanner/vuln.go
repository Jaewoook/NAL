package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jaewoook/security-hub/internal/models"
)

type VulnScanner struct {
	osvURL     string
	httpClient *http.Client
	runner     CommandRunner
}

func NewVulnScanner(osvURL string, httpClient *http.Client, runner CommandRunner) *VulnScanner {
	if osvURL == "" {
		osvURL = "https://api.osv.dev/v1/querybatch"
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &VulnScanner{
		osvURL:     osvURL,
		httpClient: httpClient,
		runner:     runner,
	}
}

type osvQuery struct {
	Version string `json:"version"`
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
}

type osvVulnRecord struct {
	ID               string `json:"id"`
	Summary          string `json:"summary"`
	Details          string `json:"details"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Ranges []struct {
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

type osvBatchResult struct {
	Vulns []osvVulnRecord `json:"vulns"`
}

func cleanUpstreamVersion(raw string) string {
	cleanVer := strings.TrimSpace(raw)
	if idx := strings.IndexByte(cleanVer, ':'); idx >= 0 {
		cleanVer = cleanVer[idx+1:]
	}
	cleanVer = strings.TrimPrefix(cleanVer, "v")
	for _, sep := range []byte{'-', '_', '+', '~'} {
		if idx := strings.IndexByte(cleanVer, sep); idx > 0 {
			cleanVer = cleanVer[:idx]
		}
	}
	return cleanVer
}

func mapItemToOSVPackage(item models.ManagedItem) (eco, pkgName, cleanVer string, ok bool) {
	cleanVer = cleanUpstreamVersion(item.CurrentVersion)
	if cleanVer == "" || IsFloatingTag(cleanVer) {
		return "", "", "", false
	}

	baseName := stripAptArch(item.Name)
	ref := strings.ToLower(item.ImageRef + " " + baseName)
	switch {
	case strings.Contains(ref, "cloudflared") || strings.Contains(ref, "cloudflare-tunnel"):
		return "Go", "github.com/cloudflare/cloudflared", cleanVer, true
	case strings.Contains(ref, "authentik") || baseName == "auth":
		return "PyPI", "authentik", cleanVer, true
	case strings.Contains(ref, "home-assistant") || strings.Contains(ref, "homeassistant"):
		return "PyPI", "homeassistant", cleanVer, true
	case strings.Contains(ref, "matter-hub"):
		return "npm", "home-assistant-matter-hub", cleanVer, true
	case strings.Contains(ref, "open-webui"):
		return "PyPI", "open-webui", cleanVer, true
	case strings.Contains(ref, "portainer"):
		return "Go", "github.com/portainer/portainer", cleanVer, true
	default:
		return "", "", "", false
	}
}

func normalizeSeverity(s string) models.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return models.SeverityCritical
	case "HIGH":
		return models.SeverityHigh
	case "MODERATE", "MEDIUM":
		return models.SeverityMedium
	default:
		return models.SeverityLow
	}
}

func osvVulnsBaseURL(queryBatchURL string) string {
	trimmed := strings.TrimRight(queryBatchURL, "/")
	if strings.HasSuffix(trimmed, "/querybatch") {
		return strings.TrimSuffix(trimmed, "/querybatch") + "/vulns"
	}
	return "https://api.osv.dev/v1/vulns"
}

func (v *VulnScanner) fetchOSVVulnDetail(ctx context.Context, id string) (osvVulnRecord, bool) {
	if v.httpClient == nil || id == "" {
		return osvVulnRecord{}, false
	}
	detailURL := osvVulnsBaseURL(v.osvURL) + "/" + url.PathEscape(id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, detailURL, nil)
	if err != nil {
		return osvVulnRecord{}, false
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return osvVulnRecord{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return osvVulnRecord{}, false
	}
	var rec osvVulnRecord
	if json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&rec) != nil {
		return osvVulnRecord{}, false
	}
	return rec, true
}

func extractOSVSeverity(vuln osvVulnRecord) models.Severity {
	if vuln.DatabaseSpecific.Severity != "" {
		return normalizeSeverity(vuln.DatabaseSpecific.Severity)
	}
	for _, s := range vuln.Severity {
		if score, err := strconv.ParseFloat(strings.TrimSpace(s.Score), 64); err == nil {
			switch {
			case score >= 9.0:
				return models.SeverityCritical
			case score >= 7.0:
				return models.SeverityHigh
			case score >= 4.0:
				return models.SeverityMedium
			default:
				return models.SeverityLow
			}
		}
	}
	return models.SeverityHigh
}

func extractOSVFixedVersion(vuln osvVulnRecord) string {
	fixedVer := ""
	for _, aff := range vuln.Affected {
		for _, rng := range aff.Ranges {
			for _, ev := range rng.Events {
				if ev.Fixed != "" {
					fixedVer = ev.Fixed
				}
			}
		}
	}
	return fixedVer
}

func buildOSVBatchQueries(items []models.ManagedItem) ([]osvQuery, []int) {
	var queries []osvQuery
	var queryIdxToItem []int
	for i := range items {
		eco, pkg, ver, ok := mapItemToOSVPackage(items[i])
		if !ok {
			continue
		}
		var q osvQuery
		q.Version = ver
		q.Package.Name = pkg
		q.Package.Ecosystem = eco
		queries = append(queries, q)
		queryIdxToItem = append(queryIdxToItem, i)
	}
	return queries, queryIdxToItem
}

func (v *VulnScanner) postOSVBatch(ctx context.Context, queries []osvQuery) ([]osvBatchResult, bool) {
	reqBody, err := json.Marshal(struct {
		Queries []osvQuery `json:"queries"`
	}{Queries: queries})
	if err != nil {
		return nil, false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.osvURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, false
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}

	var batchResp struct {
		Results []osvBatchResult `json:"results"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&batchResp) != nil {
		return nil, false
	}
	return batchResp.Results, true
}

func (v *VulnScanner) backfillOSVDetails(ctx context.Context, vuln osvVulnRecord, detailCache map[string]osvVulnRecord) osvVulnRecord {
	if vuln.ID == "" || (vuln.Summary != "" && vuln.DatabaseSpecific.Severity != "") {
		return vuln
	}
	det, cached := detailCache[vuln.ID]
	if !cached {
		if fetched, ok := v.fetchOSVVulnDetail(ctx, vuln.ID); ok {
			det = fetched
			detailCache[vuln.ID] = fetched
		}
	}
	if vuln.Summary == "" {
		vuln.Summary = det.Summary
		if vuln.Summary == "" {
			vuln.Summary = det.Details
		}
	}
	if vuln.DatabaseSpecific.Severity == "" {
		vuln.DatabaseSpecific.Severity = det.DatabaseSpecific.Severity
	}
	if len(vuln.Severity) == 0 {
		vuln.Severity = det.Severity
	}
	if len(vuln.Affected) == 0 {
		vuln.Affected = det.Affected
	}
	return vuln
}

func (v *VulnScanner) checkOSVBatch(ctx context.Context, items []models.ManagedItem) {
	if v.httpClient == nil {
		return
	}
	queries, queryIdxToItem := buildOSVBatchQueries(items)
	if len(queries) == 0 {
		return
	}
	results, ok := v.postOSVBatch(ctx, queries)
	if !ok {
		return
	}

	detailCache := make(map[string]osvVulnRecord)
	for qIdx, res := range results {
		if qIdx >= len(queryIdxToItem) {
			break
		}
		if len(res.Vulns) == 0 {
			continue
		}
		item := &items[queryIdxToItem[qIdx]]
		for _, vuln := range res.Vulns {
			vuln = v.backfillOSVDetails(ctx, vuln, detailCache)
			appendVuln(item, models.Vulnerability{
				ID:           vuln.ID,
				Summary:      vuln.Summary,
				Severity:     extractOSVSeverity(vuln),
				FixedVersion: extractOSVFixedVersion(vuln),
				URL:          "https://osv.dev/vulnerability/" + url.PathEscape(vuln.ID),
			})
		}
		recountSeverities(item)
	}
}

func (v *VulnScanner) scanTrivyImage(ctx context.Context, imageRef string) ([]models.Vulnerability, bool) {
	trivyCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	out, err := v.runner.Run(trivyCtx, "trivy", "image", "--format", "json", "--quiet", "--scanners", "vuln", "--", imageRef)
	cancel()
	if err != nil {
		return nil, false
	}

	var trivyRes struct {
		Results []struct {
			Vulnerabilities []struct {
				VulnerabilityID string `json:"VulnerabilityID"`
				Title           string `json:"Title"`
				Severity        string `json:"Severity"`
				FixedVersion    string `json:"FixedVersion"`
				PrimaryURL      string `json:"PrimaryURL"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	if json.Unmarshal(out, &trivyRes) != nil {
		return nil, false
	}

	var vulns []models.Vulnerability
	for _, r := range trivyRes.Results {
		for _, tv := range r.Vulnerabilities {
			vulns = append(vulns, models.Vulnerability{
				ID:           tv.VulnerabilityID,
				Summary:      tv.Title,
				Severity:     normalizeSeverity(tv.Severity),
				FixedVersion: tv.FixedVersion,
				URL:          tv.PrimaryURL,
			})
		}
	}
	return vulns, true
}

func (v *VulnScanner) checkTrivyImages(ctx context.Context, items []models.ManagedItem) {
	if v.runner == nil {
		return
	}
	if _, err := v.runner.Run(ctx, "trivy", "--version"); err != nil {
		return
	}
	for i := range items {
		if items[i].TargetType != models.TargetDocker || items[i].ImageRef == "" {
			continue
		}
		vulns, ok := v.scanTrivyImage(ctx, items[i].ImageRef)
		if !ok || len(vulns) == 0 {
			continue
		}
		for _, tv := range vulns {
			appendVuln(&items[i], tv)
		}
		recountSeverities(&items[i])
	}
}

func (v *VulnScanner) CheckVulnerabilities(ctx context.Context, items []models.ManagedItem) error {
	v.checkOSVBatch(ctx, items)
	v.checkTrivyImages(ctx, items)
	return nil
}

func appendVuln(item *models.ManagedItem, v models.Vulnerability) {
	for _, existing := range item.Vulnerabilities {
		if existing.ID == v.ID {
			return
		}
	}
	item.Vulnerabilities = append(item.Vulnerabilities, v)
}

func recountSeverities(item *models.ManagedItem) {
	item.CritCount = 0
	item.HighCount = 0
	item.MedCount = 0
	item.LowCount = 0
	for _, v := range item.Vulnerabilities {
		switch v.Severity {
		case models.SeverityCritical:
			item.CritCount++
		case models.SeverityHigh:
			item.HighCount++
		case models.SeverityMedium:
			item.MedCount++
		default:
			item.LowCount++
		}
	}
}
