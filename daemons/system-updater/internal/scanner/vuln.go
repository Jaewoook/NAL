package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/jaewoook/system-updater/internal/models"
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

func mapItemToOSVPackage(item models.ManagedItem) (eco, pkgName, cleanVer string, ok bool) {
	cleanVer = strings.TrimPrefix(item.CurrentVersion, "v")
	if idx := strings.IndexByte(cleanVer, '-'); idx > 0 {
		cleanVer = cleanVer[:idx]
	}
	if idx := strings.IndexByte(cleanVer, '_'); idx > 0 {
		cleanVer = cleanVer[:idx]
	}
	if cleanVer == "" || IsFloatingTag(cleanVer) {
		return "", "", "", false
	}

	ref := strings.ToLower(item.ImageRef + " " + item.Name)
	switch {
	case strings.Contains(ref, "cloudflared") || strings.Contains(ref, "cloudflare-tunnel"):
		return "Go", "github.com/cloudflare/cloudflared", cleanVer, true
	case strings.Contains(ref, "authentik") || item.Name == "auth":
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
				var batchResp struct {
					Results []struct {
						Vulns []struct {
							ID               string `json:"id"`
							Summary          string `json:"summary"`
							DatabaseSpecific struct {
								Severity string `json:"severity"`
							} `json:"database_specific"`
							Affected []struct {
								Ranges []struct {
									Events []struct {
										Fixed string `json:"fixed"`
									} `json:"events"`
								} `json:"ranges"`
							} `json:"affected"`
						} `json:"vulns"`
					} `json:"results"`
				}
				if json.NewDecoder(resp.Body).Decode(&batchResp) == nil {
					for qIdx, res := range batchResp.Results {
						if qIdx >= len(queryIdxToItem) {
							break
						}
						itemIdx := queryIdxToItem[qIdx]
						for _, vuln := range res.Vulns {
							sev := normalizeSeverity(vuln.DatabaseSpecific.Severity)
							if vuln.DatabaseSpecific.Severity == "" {
								sev = models.SeverityHigh
							}
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
							appendVuln(&items[itemIdx], models.Vulnerability{
								ID:           vuln.ID,
								Summary:      vuln.Summary,
								Severity:     sev,
								FixedVersion: fixedVer,
								URL:          "https://osv.dev/vulnerability/" + vuln.ID,
							})
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
				out, err := v.runner.Run(ctx, "trivy", "image", "--format", "json", "--quiet", "--scanners", "vuln", items[i].ImageRef)
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
