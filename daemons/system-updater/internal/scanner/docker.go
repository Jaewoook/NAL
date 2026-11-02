package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jaewoook/system-updater/internal/models"
	"gopkg.in/yaml.v3"
)

type ComposeImageRef struct {
	ServiceName   string
	ServiceKey    string
	ContainerName string
	ComposePath   string
	EnvPath       string
	RawImage      string
	ImageRepo     string
	Tag           string
	Floating      bool
}

var envDefaultRe = regexp.MustCompile(`\$\{([A-Za-z0-9_]+)(?::-|-)?([^}]*)\}`)

func FindComposeFile(dir string) string {
	for _, name := range []string{"compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"} {
		p := filepath.Join(dir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func LoadEnvMap(envPath string) map[string]string {
	m := make(map[string]string)
	f, err := os.Open(envPath)
	if err != nil {
		return m
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.IndexByte(line, '='); idx > 0 {
			k := strings.TrimSpace(line[:idx])
			v := strings.Trim(strings.TrimSpace(line[idx+1:]), `"'`)
			m[k] = v
		}
	}
	return m
}

func ExpandEnvWithMap(raw string, env map[string]string) string {
	return envDefaultRe.ReplaceAllStringFunc(raw, func(match string) string {
		sub := envDefaultRe.FindStringSubmatch(match)
		if len(sub) < 3 {
			return match
		}
		varName := sub[1]
		defVal := sub[2]
		if v, ok := env[varName]; ok && v != "" {
			return v
		}
		return defVal
	})
}

func SplitImageRepoAndTag(expanded string) (string, string) {
	expanded = strings.Trim(strings.TrimSpace(expanded), `"'`)
	if idx := strings.Index(expanded, "@sha256:"); idx > 0 {
		expanded = expanded[:idx]
	}
	lastSlash := strings.LastIndexByte(expanded, '/')
	lastColon := strings.LastIndexByte(expanded, ':')
	if lastColon > lastSlash {
		return expanded[:lastColon], expanded[lastColon+1:]
	}
	return expanded, "latest"
}

func IsFloatingTag(tag string) bool {
	switch strings.ToLower(tag) {
	case "latest", "main", "master", "edge", "stable", "nightly":
		return true
	}
	return false
}

func ParseComposeImageRefs(composeDir string) ([]ComposeImageRef, error) {
	cPath := FindComposeFile(composeDir)
	if cPath == "" {
		return nil, fmt.Errorf("no compose file found in %s", composeDir)
	}
	envPath := filepath.Join(composeDir, ".env")
	envMap := LoadEnvMap(envPath)

	raw, err := os.ReadFile(cPath)
	if err != nil {
		return nil, err
	}

	var parsed struct {
		Services map[string]struct {
			Image         string `yaml:"image"`
			ContainerName string `yaml:"container_name"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}

	serviceName := filepath.Base(composeDir)
	seenRepo := make(map[string]bool)
	var keys []string
	for k := range parsed.Services {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []ComposeImageRef
	for _, k := range keys {
		svc := parsed.Services[k]
		if svc.Image == "" {
			continue
		}
		expanded := ExpandEnvWithMap(svc.Image, envMap)
		repo, tag := SplitImageRepoAndTag(expanded)
		dedupKey := repo + ":" + tag
		if seenRepo[dedupKey] {
			continue
		}
		seenRepo[dedupKey] = true

		cName := svc.ContainerName
		if cName == "" {
			cName = k
		}
		out = append(out, ComposeImageRef{
			ServiceName:   serviceName,
			ServiceKey:    k,
			ContainerName: cName,
			ComposePath:   cPath,
			EnvPath:       envPath,
			RawImage:      svc.Image,
			ImageRepo:     repo,
			Tag:           tag,
			Floating:      IsFloatingTag(tag),
		})
	}
	return out, nil
}

type DockerScanner struct {
	servicesDir      string
	criticalServices map[string]bool
	statefulVolumes  map[string]string
	runner           CommandRunner
	registry         *RegistryClient
}

func NewDockerScanner(servicesDir string, critical []string, stateful map[string]string, runner CommandRunner, reg *RegistryClient) *DockerScanner {
	critMap := make(map[string]bool, len(critical))
	for _, c := range critical {
		critMap[c] = true
	}
	return &DockerScanner{
		servicesDir:      servicesDir,
		criticalServices: critMap,
		statefulVolumes:  stateful,
		runner:           runner,
		registry:         reg,
	}
}

func (d *DockerScanner) InspectContainerDigest(ctx context.Context, containerName, imageRef string) string {
	if d.runner == nil {
		return ""
	}
	out, err := d.runner.Run(ctx, "docker", "inspect", "--format", "{{json .Image}}", containerName)
	if err == nil {
		imgID := strings.Trim(strings.TrimSpace(string(out)), `"`)
		if imgID != "" {
			if dOut, err := d.runner.Run(ctx, "docker", "image", "inspect", "--format", "{{json .RepoDigests}}", imgID); err == nil {
				var digests []string
				if json.Unmarshal(dOut, &digests) == nil && len(digests) > 0 {
					if idx := strings.Index(digests[0], "sha256:"); idx >= 0 {
						return digests[0][idx:]
					}
				}
			}
		}
	}
	if dOut, err := d.runner.Run(ctx, "docker", "image", "inspect", "--format", "{{json .RepoDigests}}", imageRef); err == nil {
		var digests []string
		if json.Unmarshal(dOut, &digests) == nil && len(digests) > 0 {
			if idx := strings.Index(digests[0], "sha256:"); idx >= 0 {
				return digests[0][idx:]
			}
		}
	}
	return ""
}

func ReleaseNotesURLForImage(repo string) string {
	repo = strings.TrimPrefix(repo, "docker.io/")
	repo = strings.TrimPrefix(repo, "ghcr.io/")
	repo = strings.TrimPrefix(repo, "lscr.io/")
	switch {
	case strings.Contains(repo, "cloudflare/cloudflared"):
		return "https://github.com/cloudflare/cloudflared/releases"
	case strings.Contains(repo, "goauthentik/server"):
		return "https://github.com/goauthentik/authentik/releases"
	case strings.Contains(repo, "home-assistant"):
		return "https://github.com/home-assistant/core/releases"
	case strings.Contains(repo, "postgres"):
		return "https://www.postgresql.org/docs/release/"
	case strings.Contains(repo, "portainer"):
		return "https://github.com/portainer/portainer/releases"
	case strings.Contains(repo, "nginx-proxy-manager"):
		return "https://github.com/NginxProxyManager/nginx-proxy-manager/releases"
	case strings.Contains(repo, "open-webui"):
		return "https://github.com/open-webui/open-webui/releases"
	case strings.Count(repo, "/") == 1 && !strings.HasPrefix(repo, "library/"):
		return "https://github.com/" + repo + "/releases"
	default:
		return "https://hub.docker.com/r/" + repo
	}
}

func (d *DockerScanner) ScanDockerServices(ctx context.Context) ([]models.ManagedItem, error) {
	if d.runner != nil {
		if _, err := d.runner.Run(ctx, "docker", "info"); err != nil {
			// Gracefully ignore Docker when daemon is stopped or not installed on this host (e.g., Atlas)
			return nil, nil
		}
	}
	entries, err := os.ReadDir(d.servicesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var items []models.ManagedItem
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		dir := filepath.Join(d.servicesDir, ent.Name())
		refs, err := ParseComposeImageRefs(dir)
		if err != nil || len(refs) == 0 {
			continue
		}
		for _, ref := range refs {
			fullImage := ref.ImageRepo + ":" + ref.Tag
			curDigest := d.InspectContainerDigest(ctx, ref.ContainerName, fullImage)
			latestVer := ref.Tag
			var availTags []string
			var remDigest string
			var outdated bool
			if d.registry != nil {
				if lv, tags, rd, outd, err := d.registry.CheckImageUpdates(ctx, fullImage, curDigest); err == nil {
					latestVer = lv
					availTags = tags
					remDigest = rd
					outdated = outd
				}
			}
			displayName := ref.ServiceName
			if len(refs) > 1 {
				displayName = fmt.Sprintf("%s/%s", ref.ServiceName, ref.ServiceKey)
			}
			_, stateful := d.statefulVolumes[ref.ServiceName]
			items = append(items, models.ManagedItem{
				TargetType:      models.TargetDocker,
				Name:            displayName,
				ServiceKey:      ref.ServiceKey,
				ImageRef:        fullImage,
				CurrentVersion:  ref.Tag,
				CurrentDigest:   curDigest,
				LatestVersion:   latestVer,
				RemoteDigest:    remDigest,
				AvailableTags:   availTags,
				Outdated:        outdated,
				CriticalPath:    d.criticalServices[ref.ServiceName],
				Stateful:        stateful,
				ReleaseNotesURL: ReleaseNotesURLForImage(ref.ImageRepo),
				EoL:             models.EoLInfo{Status: models.EoLUnknown},
				LastCheckedAt:   time.Now().UTC(),
			})
		}
	}
	return items, nil
}
