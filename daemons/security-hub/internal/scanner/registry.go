package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

func isPrereleaseSuffix(s string) bool {
	lower := strings.ToLower(strings.TrimSpace(s))
	if lower == "" {
		return false
	}
	for _, p := range []string{"rc", "alpha", "beta", "dev", "pre", "preview", "canary"} {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
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
	if a.patch != b.patch {
		return a.patch - b.patch
	}
	// Stable release (empty suffix) beats prerelease suffix at same major.minor.patch
	if a.suffix == "" && isPrereleaseSuffix(b.suffix) {
		return 1
	}
	if isPrereleaseSuffix(a.suffix) && b.suffix == "" {
		return -1
	}
	return 0
}

func dockerHubHostAndRepo(repo string) (host, normalizedRepo, tokenURL string) {
	if !strings.Contains(repo, "/") {
		repo = "library/" + repo
	}
	return "https://registry-1.docker.io", repo, fmt.Sprintf("https://auth.docker.io/token?service=registry.docker.io&scope=repository:%s:pull", repo)
}

func parseRegistryHostAndRepo(imageRepo string) (host, repo, tokenURL string) {
	switch {
	case strings.HasPrefix(imageRepo, "ghcr.io/"):
		repo = strings.TrimPrefix(imageRepo, "ghcr.io/")
		return "https://ghcr.io", repo, fmt.Sprintf("https://ghcr.io/token?service=ghcr.io&scope=repository:%s:pull", repo)
	case strings.HasPrefix(imageRepo, "lscr.io/"):
		repo = strings.TrimPrefix(imageRepo, "lscr.io/")
		return "https://lscr.io", repo, fmt.Sprintf("https://lscr.io/token?scope=repository:%s:pull", repo)
	case strings.HasPrefix(imageRepo, "docker.io/"):
		return dockerHubHostAndRepo(strings.TrimPrefix(imageRepo, "docker.io/"))
	default:
		if slash := strings.IndexByte(imageRepo, '/'); slash > 0 {
			first := imageRepo[:slash]
			if strings.ContainsAny(first, ".:") || first == "localhost" {
				return "https://" + first, imageRepo[slash+1:], ""
			}
		}
		return dockerHubHostAndRepo(imageRepo)
	}
}

func parseWWWAuthenticateBearer(hdr, fallbackRepo string) string {
	idx := strings.Index(strings.ToLower(hdr), "bearer ")
	if idx < 0 {
		return ""
	}
	rest := hdr[idx+len("bearer "):]
	params := make(map[string]string)
	for _, part := range strings.Split(rest, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(kv[0]))
		v := strings.Trim(strings.TrimSpace(kv[1]), `"`)
		params[k] = v
	}
	realm := params["realm"]
	u, err := url.Parse(realm)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" {
		return ""
	}
	q := u.Query()
	if params["service"] != "" {
		q.Set("service", params["service"])
	}
	if params["scope"] != "" {
		q.Set("scope", params["scope"])
	} else if fallbackRepo != "" {
		q.Set("scope", "repository:"+fallbackRepo+":pull")
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func parseNextLinkURL(baseURL, linkHdr string) string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	for _, seg := range strings.Split(linkHdr, ",") {
		if !strings.Contains(strings.ToLower(seg), `rel="next"`) && !strings.Contains(strings.ToLower(seg), "rel=next") {
			continue
		}
		start := strings.IndexByte(seg, '<')
		end := strings.IndexByte(seg, '>')
		if start < 0 || end <= start+1 {
			continue
		}
		rel, err := url.Parse(strings.TrimSpace(seg[start+1 : end]))
		if err != nil {
			continue
		}
		next := base.ResolveReference(rel)
		if !strings.EqualFold(next.Scheme, base.Scheme) || !strings.EqualFold(next.Host, base.Host) {
			return ""
		}
		return next.String()
	}
	return ""
}

func (r *RegistryClient) fetchToken(ctx context.Context, tokenURL string) string {
	if tokenURL == "" || r.httpClient == nil {
		return ""
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return ""
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	var body struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body)
	if body.Token != "" {
		return body.Token
	}
	return body.AccessToken
}

func (r *RegistryClient) fetchRemoteDigest(ctx context.Context, host, repo, tag, token string) (string, string) {
	reqURL := fmt.Sprintf("%s/v2/%s/manifests/%s", host, repo, url.PathEscape(tag))
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, reqURL, nil)
	if err != nil {
		return "", ""
	}
	req.Header.Set("Accept", "application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := r.httpClient.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	return resp.Header.Get("Docker-Content-Digest"), resp.Header.Get("WWW-Authenticate")
}

func (r *RegistryClient) fetchTagsList(ctx context.Context, host, repo, token string) ([]string, error) {
	nextURL := fmt.Sprintf("%s/v2/%s/tags/list?n=200", host, repo)
	var allTags []string
	seenURLs := make(map[string]bool)
	discoveredChallenge := false

	const maxPages = 5
	for page := 0; page < maxPages && nextURL != ""; page++ {
		if seenURLs[nextURL] {
			break
		}
		seenURLs[nextURL] = true

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, nextURL, nil)
		if err != nil {
			return nil, err
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := r.httpClient.Do(req)
		if err != nil {
			if len(allTags) > 0 {
				return allTags, nil
			}
			return nil, err
		}
		if resp.StatusCode == http.StatusUnauthorized && token == "" && !discoveredChallenge {
			discoveredChallenge = true
			wwwAuth := resp.Header.Get("WWW-Authenticate")
			resp.Body.Close()
			if bearerURL := parseWWWAuthenticateBearer(wwwAuth, repo); bearerURL != "" {
				if newTok := r.fetchToken(ctx, bearerURL); newTok != "" {
					token = newTok
					delete(seenURLs, nextURL)
					page--
					continue
				}
			}
			return nil, fmt.Errorf("registry returned HTTP 401")
		}
		if resp.StatusCode != http.StatusOK {
			status := resp.StatusCode
			resp.Body.Close()
			if len(allTags) > 0 {
				return allTags, nil
			}
			return nil, fmt.Errorf("registry returned HTTP %d", status)
		}
		var payload struct {
			Tags []string `json:"tags"`
		}
		decErr := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&payload)
		linkHdr := resp.Header.Get("Link")
		resp.Body.Close()
		if decErr != nil {
			if len(allTags) > 0 {
				return allTags, nil
			}
			return nil, decErr
		}
		allTags = append(allTags, payload.Tags...)
		nextURL = parseNextLinkURL(nextURL, linkHdr)
	}
	return allTags, nil
}

func (r *RegistryClient) resolveDigestAndToken(ctx context.Context, host, repo, currentTag, tokenURL string) (string, string) {
	token := r.fetchToken(ctx, tokenURL)
	remoteDigest, wwwAuth := r.fetchRemoteDigest(ctx, host, repo, currentTag, token)
	if remoteDigest == "" && token == "" && wwwAuth != "" {
		if bearerURL := parseWWWAuthenticateBearer(wwwAuth, repo); bearerURL != "" {
			if tok := r.fetchToken(ctx, bearerURL); tok != "" {
				token = tok
				remoteDigest, _ = r.fetchRemoteDigest(ctx, host, repo, currentTag, token)
			}
		}
	}
	return remoteDigest, token
}

func parseCurrentTagSemver(currentTag string) (parsedVer, bool) {
	if curParsed, ok := parseVersionTag(currentTag); ok {
		return curParsed, true
	}
	if strings.Contains(currentTag, "-") {
		parts := strings.SplitN(currentTag, "-", 2)
		if maj, err := strconv.Atoi(parts[0]); err == nil {
			return parsedVer{raw: currentTag, major: maj, suffix: parts[1]}, true
		}
	}
	return parsedVer{}, false
}

func filterAndSortCandidateTags(rawTags []string, curParsed parsedVer, curIsSemver bool) []parsedVer {
	curPrerelease := curIsSemver && isPrereleaseSuffix(curParsed.suffix)
	var candidates []parsedVer
	for _, t := range rawTags {
		pv, ok := parseVersionTag(t)
		if !ok {
			continue
		}
		if curIsSemver && curParsed.suffix != pv.suffix {
			if !curPrerelease || pv.suffix != "" {
				continue
			}
		}
		candidates = append(candidates, pv)
	}
	sort.Slice(candidates, func(i, j int) bool {
		return compareParsedVer(candidates[i], candidates[j]) > 0
	})
	return candidates
}

func topCandidateTags(candidates []parsedVer, limit int) []string {
	var tags []string
	for _, c := range candidates {
		tags = append(tags, c.raw)
		if len(tags) >= limit {
			break
		}
	}
	return tags
}

func ensureLatestTagIncluded(availableTags []string, currentTag, latestVersion string) []string {
	if len(availableTags) == 0 {
		return []string{currentTag}
	}
	for _, t := range availableTags {
		if t == latestVersion {
			return availableTags
		}
	}
	return append(availableTags, latestVersion)
}

func selectImageUpdateTarget(currentTag, currentDigest, remoteDigest string, curParsed parsedVer, curIsSemver bool, candidates []parsedVer) (latestVersion string, availableTags []string, outdated bool) {
	availableTags = topCandidateTags(candidates, 12)

	if IsFloatingTag(currentTag) {
		availableTags = append([]string{currentTag}, availableTags...)
		latestVersion = currentTag
		if len(candidates) > 0 {
			latestVersion = candidates[0].raw
		}
		outdated = currentDigest != "" && remoteDigest != "" && currentDigest != remoteDigest
		return latestVersion, availableTags, outdated
	}

	latestVersion = currentTag
	if curIsSemver && len(candidates) > 0 {
		bestCandidate := candidates[0].raw
		for _, c := range candidates {
			if c.major == curParsed.major {
				bestCandidate = c.raw
				break
			}
		}
		if latestParsed, ok := parseVersionTag(bestCandidate); ok && compareParsedVer(latestParsed, curParsed) > 0 {
			latestVersion = bestCandidate
			outdated = true
		}
	}
	availableTags = ensureLatestTagIncluded(availableTags, currentTag, latestVersion)
	return latestVersion, availableTags, outdated
}

func (r *RegistryClient) CheckImageUpdates(ctx context.Context, imageRef string, currentDigest string) (latestVersion string, availableTags []string, remoteDigest string, outdated bool, err error) {
	imageRepo, currentTag := SplitImageRepoAndTag(imageRef)
	host, repo, tokenURL := parseRegistryHostAndRepo(imageRepo)
	remoteDigest, token := r.resolveDigestAndToken(ctx, host, repo, currentTag, tokenURL)

	rawTags, tagsErr := r.fetchTagsList(ctx, host, repo, token)
	if tagsErr != nil && remoteDigest == "" {
		return currentTag, []string{currentTag}, "", false, tagsErr
	}

	curParsed, curIsSemver := parseCurrentTagSemver(currentTag)
	candidates := filterAndSortCandidateTags(rawTags, curParsed, curIsSemver)
	latestVersion, availableTags, outdated = selectImageUpdateTarget(currentTag, currentDigest, remoteDigest, curParsed, curIsSemver, candidates)
	return latestVersion, availableTags, remoteDigest, outdated, nil
}
