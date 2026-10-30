package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type RegistryClient struct {
	httpClient *http.Client
}

func NewRegistryClient(client *http.Client) *RegistryClient {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &RegistryClient{httpClient: client}
}

var semverTagRe = regexp.MustCompile(`^v?(\d+)\.(\d+)(?:\.(\d+))?(?:-([A-Za-z0-9._-]+))?$`)

type parsedVer struct {
	raw    string
	major  int
	minor  int
	patch  int
	suffix string
}

func parseVersionTag(tag string) (parsedVer, bool) {
	m := semverTagRe.FindStringSubmatch(tag)
	if len(m) == 0 {
		return parsedVer{}, false
	}
	maj, _ := strconv.Atoi(m[1])
	min, _ := strconv.Atoi(m[2])
	pat := 0
	if m[3] != "" {
		pat, _ = strconv.Atoi(m[3])
	}
	return parsedVer{
		raw:    tag,
		major:  maj,
		minor:  min,
		patch:  pat,
		suffix: m[4],
	}, true
}

func compareParsedVer(a, b parsedVer) int {
	if a.major != b.major {
		return a.major - b.major
	}
	if a.minor != b.minor {
		return a.minor - b.minor
	}
	return a.patch - b.patch
}

func parseRegistryHostAndRepo(imageRepo string) (host, repo, tokenURL string) {
	switch {
	case strings.HasPrefix(imageRepo, "ghcr.io/"):
		repo = strings.TrimPrefix(imageRepo, "ghcr.io/")
		return "https://ghcr.io", repo, fmt.Sprintf("https://ghcr.io/token?service=ghcr.io&scope=repository:%s:pull", repo)
	case strings.HasPrefix(imageRepo, "lscr.io/"):
		repo = strings.TrimPrefix(imageRepo, "lscr.io/")
		return "https://lscr.io", repo, fmt.Sprintf("https://lscr.io/token?scope=repository:%s:pull", repo)
	default:
		repo = strings.TrimPrefix(imageRepo, "docker.io/")
		if !strings.Contains(repo, "/") {
			repo = "library/" + repo
		}
		return "https://registry-1.docker.io", repo, fmt.Sprintf("https://auth.docker.io/token?service=registry.docker.io&scope=repository:%s:pull", repo)
	}
}

func (r *RegistryClient) fetchToken(ctx context.Context, tokenURL string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return ""
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body.Token != "" {
		return body.Token
	}
	return body.AccessToken
}

func (r *RegistryClient) fetchRemoteDigest(ctx context.Context, host, repo, tag, token string) string {
	url := fmt.Sprintf("%s/v2/%s/manifests/%s", host, repo, tag)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	return resp.Header.Get("Docker-Content-Digest")
}

func (r *RegistryClient) fetchTagsList(ctx context.Context, host, repo, token string) ([]string, error) {
	url := fmt.Sprintf("%s/v2/%s/tags/list?n=200", host, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var payload struct {
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	return payload.Tags, nil
}

func (r *RegistryClient) CheckImageUpdates(ctx context.Context, imageRef string, currentDigest string) (latestVersion string, availableTags []string, remoteDigest string, outdated bool, err error) {
	imageRepo, currentTag := SplitImageRepoAndTag(imageRef)
	host, repo, tokenURL := parseRegistryHostAndRepo(imageRepo)
	token := r.fetchToken(ctx, tokenURL)

	remoteDigest = r.fetchRemoteDigest(ctx, host, repo, currentTag, token)
	rawTags, _ := r.fetchTagsList(ctx, host, repo, token)

	curParsed, curIsSemver := parseVersionTag(currentTag)
	// Also handle major-only flavor tags like "16-alpine"
	if !curIsSemver && strings.Contains(currentTag, "-") {
		parts := strings.SplitN(currentTag, "-", 2)
		if maj, errConv := strconv.Atoi(parts[0]); errConv == nil {
			curParsed = parsedVer{raw: currentTag, major: maj, suffix: parts[1]}
			curIsSemver = true
		}
	}

	var candidates []parsedVer
	for _, t := range rawTags {
		pv, ok := parseVersionTag(t)
		if !ok {
			continue
		}
		if curIsSemver && curParsed.suffix != pv.suffix {
			continue
		}
		candidates = append(candidates, pv)
	}

	sort.Slice(candidates, func(i, j int) bool {
		return compareParsedVer(candidates[i], candidates[j]) > 0
	})

	for _, c := range candidates {
		availableTags = append(availableTags, c.raw)
		if len(availableTags) >= 12 {
			break
		}
	}

	if IsFloatingTag(currentTag) {
		availableTags = append([]string{currentTag}, availableTags...)
		if len(candidates) > 0 {
			latestVersion = candidates[0].raw
		} else {
			latestVersion = currentTag
		}
		if currentDigest != "" && remoteDigest != "" && currentDigest != remoteDigest {
			outdated = true
		}
		return latestVersion, availableTags, remoteDigest, outdated, nil
	}

	// Pinned tag: prefer highest tag within the same major version if available,
	// while still listing major upgrades in availableTags.
	latestVersion = currentTag
	if len(candidates) > 0 {
		latestVersion = candidates[0].raw
		if curIsSemver {
			for _, c := range candidates {
				if c.major == curParsed.major {
					latestVersion = c.raw
					break
				}
			}
			if latestParsed, ok := parseVersionTag(latestVersion); ok {
				if compareParsedVer(latestParsed, curParsed) > 0 {
					outdated = true
				}
			}
		} else if latestVersion != currentTag {
			outdated = true
		}
	}
	if len(availableTags) == 0 {
		availableTags = []string{currentTag}
	}
	return latestVersion, availableTags, remoteDigest, outdated, nil
}
