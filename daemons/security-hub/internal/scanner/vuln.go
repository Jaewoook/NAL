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

func (v *VulnScanner) CheckVulnerabilities(ctx context.Context, items []models.ManagedItem) error {
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

	if len(queries) > 0 && v.httpClient != nil {
		reqBody, _ := json.Marshal(struct {
			Queries []osvQuery `json:"queries"`
		}{Queries: queries})

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.osvURL, bytes.NewReader(reqBody))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			resp, err := v.httpClient.Do(req)
			if err == nil {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					var batchResp struct {
						Results []struct {
							Vulns []osvVulnRecord `json:"vulns"`
						} `json:"results"`
					}
					if json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&batchResp) == nil {
						detailCache := make(map[string]osvVulnRecord)
						for qIdx, res := range batchResp.Results {
							if qIdx >= len(queryIdxToItem) {
								break
							}
							itemIdx := queryIdxToItem[qIdx]
							for _, vuln := range res.Vulns {
								if vuln.ID != "" && (vuln.Summary == "" || vuln.DatabaseSpecific.Severity == "") {
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
								}

								sev := extractOSVSeverity(vuln)
								fixedVer := extractOSVFixedVersion(vuln)
								appendVuln(&items[itemIdx], models.Vulnerability{
									ID:           vuln.ID,
									Summary:      vuln.Summary,
									Severity:     sev,
									FixedVersion: fixedVer,
									URL:          "https://osv.dev/vulnerability/" + url.PathEscape(vuln.ID),
								})
							}
						}
					}
				}
			}
		}
	}

	// Optional Trivy image scan if trivy is installed on the host
	if v.runner != nil {
		if _, err := v.runner.Run(ctx, "trivy", "--version"); err == nil {
			for i := range items {
				if items[i].TargetType != models.TargetDocker || items[i].ImageRef == "" {
					continue
				}
				trivyCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
				out, err := v.runner.Run(trivyCtx, "trivy", "image", "--format", "json", "--quiet", "--scanners", "vuln", "--", items[i].ImageRef)
				cancel()
				if err != nil {
					continue
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
				if json.Unmarshal(out, &trivyRes) == nil {
					for _, r := range trivyRes.Results {
						for _, tv := range r.Vulnerabilities {
							appendVuln(&items[i], models.Vulnerability{
								ID:           tv.VulnerabilityID,
								Summary:      tv.Title,
								Severity:     normalizeSeverity(tv.Severity),
								FixedVersion: tv.FixedVersion,
								URL:          tv.PrimaryURL,
							})
						}
					}
				}
			}
		}
	}

	return nil
}

func appendVuln(item *models.ManagedItem, v models.Vulnerability) {
	for _, existing := range item.Vulnerabilities {
		if existing.ID == v.ID {
			return
		}
	}
	item.Vulnerabilities = append(item.Vulnerabilities, v)
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
