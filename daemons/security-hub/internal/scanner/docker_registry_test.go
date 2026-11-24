package scanner

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseComposeImageRefs_EnvExpansionAndFloatingTags(t *testing.T) {
	root := t.TempDir()

	// 1. services/auth with ${VAR:-default} and .env override
	authDir := filepath.Join(root, "auth")
	_ = os.MkdirAll(authDir, 0755)
	_ = os.WriteFile(filepath.Join(authDir, "compose.yml"), []byte(`services:
  server:
    image: ${AUTHENTIK_IMAGE:-ghcr.io/goauthentik/server}:${AUTHENTIK_TAG:-2026.5.3}
    container_name: authentik-server
  worker:
    image: ${AUTHENTIK_IMAGE:-ghcr.io/goauthentik/server}:${AUTHENTIK_TAG:-2026.5.3}
    container_name: authentik-worker
`), 0644)
	_ = os.WriteFile(filepath.Join(authDir, ".env"), []byte("AUTHENTIK_TAG=2026.5.4\n"), 0644)

	refs, err := ParseComposeImageRefs(authDir)
	if err != nil {
		t.Fatalf("ParseComposeImageRefs(auth) failed: %v", err)
	}
	if len(refs) != 1 {
		t.Fatalf("expected deduplicated 1 image ref for auth stack, got %d", len(refs))
	}
	if refs[0].ImageRepo != "ghcr.io/goauthentik/server" || refs[0].Tag != "2026.5.4" {
		t.Fatalf("unexpected auth ref: %+v", refs[0])
	}

	// 2. services/llm with ${WEBUI_DOCKER_TAG-main}
	llmDir := filepath.Join(root, "llm")
	_ = os.MkdirAll(llmDir, 0755)
	_ = os.WriteFile(filepath.Join(llmDir, "docker-compose.yml"), []byte(`services:
  open-webui:
    image: ghcr.io/open-webui/open-webui:${WEBUI_DOCKER_TAG-main}
    container_name: open-webui
`), 0644)
	llmRefs, err := ParseComposeImageRefs(llmDir)
	if err != nil || len(llmRefs) != 1 {
		t.Fatalf("ParseComposeImageRefs(llm) failed: %v", err)
	}
	if llmRefs[0].Tag != "main" || !llmRefs[0].Floating {
		t.Fatalf("expected floating tag 'main', got %+v", llmRefs[0])
	}
}

func TestParseComposeImageRefs_ContainerNameEnvExpansion(t *testing.T) {
	dir := t.TempDir()
	compose := "services:\n  web:\n    image: nginx:1.25.0\n    container_name: ${APP_PREFIX:-nal}_web_1\n  worker:\n    image: alpine:3.19\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yml"), []byte(compose), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("APP_PREFIX=prod\n"), 0600); err != nil {
		t.Fatal(err)
	}
	refs, err := ParseComposeImageRefs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 {
		t.Fatalf("expected 2 compose refs, got %d", len(refs))
	}
	if refs[0].ServiceKey != "web" || refs[0].ContainerName != "prod_web_1" {
		t.Fatalf("expected expanded container_name 'prod_web_1', got %+v", refs[0])
	}
	if refs[1].ServiceKey != "worker" || refs[1].ContainerName != "worker" {
		t.Fatalf("expected omitted container_name to default to service key 'worker', got %+v", refs[1])
	}
}

func TestDockerScanner_GracefullyIgnoresStoppedOrMissingDocker(t *testing.T) {
	runner := &fakeRunner{
		handler: func(name string, args ...string) ([]byte, error) {
			if name == "docker" && len(args) > 0 && args[0] == "info" {
				return []byte("Cannot connect to the Docker daemon"), errors.New("exit status 1")
			}
			return nil, nil
		},
	}
	ds := NewDockerScanner(t.TempDir(), nil, nil, runner, nil)
	items, err := ds.ScanDockerServices(context.Background())
	if err != nil || len(items) != 0 {
		t.Fatalf("expected graceful empty slice and nil error when Docker is stopped/uninstalled, got items=%v err=%v", items, err)
	}
}

func TestDockerScanner_InspectContainerDigest_ContainerAndImageFallback(t *testing.T) {
	ctx := context.Background()

	runner := &fakeRunner{
		handler: func(name string, args ...string) ([]byte, error) {
			cmdLine := name + " " + strings.Join(args, " ")
			switch {
			case strings.Contains(cmdLine, "docker inspect --format {{json .Image}} running-ctr"):
				return []byte("\"sha256:imgid123\"\n"), nil
			case strings.Contains(cmdLine, "docker image inspect --format {{json .RepoDigests}} sha256:imgid123"):
				return []byte(`["ghcr.io/org/app@sha256:aaaa1111"]`), nil
			case strings.Contains(cmdLine, "docker inspect --format {{json .Image}} missing-ctr"):
				return nil, errors.New("no such container")
			case strings.Contains(cmdLine, "docker image inspect --format {{json .RepoDigests}} ghcr.io/org/app:1.0.0"):
				return []byte(`["ghcr.io/org/app@sha256:bbbb2222"]`), nil
			default:
				return nil, errors.New("not found")
			}
		},
	}

	ds := NewDockerScanner(t.TempDir(), nil, nil, runner, nil)
	if got := ds.InspectContainerDigest(ctx, "running-ctr", "ghcr.io/org/app:1.0.0"); got != "sha256:aaaa1111" {
		t.Fatalf("expected container image digest 'sha256:aaaa1111', got %q", got)
	}
	if got := ds.InspectContainerDigest(ctx, "missing-ctr", "ghcr.io/org/app:1.0.0"); got != "sha256:bbbb2222" {
		t.Fatalf("expected fallback imageRef digest 'sha256:bbbb2222', got %q", got)
	}
}

func TestRegistryClient_CheckImageUpdates_PinnedAndLatest(t *testing.T) {
	client := NewRegistryClient(&http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			u := req.URL.String()
			switch {
			case strings.Contains(u, "token"):
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader(`{"token":"tok"}`)),
					Header:     make(http.Header),
				}, nil
			case strings.HasSuffix(u, "/manifests/latest"):
				h := make(http.Header)
				h.Set("Docker-Content-Digest", "sha256:999999")
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader(`{}`)),
					Header:     h,
				}, nil
			case strings.Contains(u, "cloudflare/cloudflared/tags/list"):
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader(`{"tags":["latest","2026.8.0","2026.10.2","2026.10.1"]}`)),
					Header:     make(http.Header),
				}, nil
			case strings.Contains(u, "library/postgres/tags/list"):
				return &http.Response{
					StatusCode: 200,
					Body:       io.NopCloser(strings.NewReader(`{"tags":["16-alpine","16.4-alpine","16.6-alpine","17.2-alpine","16.6"]}`)),
					Header:     make(http.Header),
				}, nil
			default:
				return &http.Response{
					StatusCode: 404,
					Body:       io.NopCloser(bytes.NewReader(nil)),
					Header:     make(http.Header),
				}, nil
			}
		}),
	})

	// 1. Floating latest with differing digest
	latestVer, tags, remDigest, outdated, err := client.CheckImageUpdates(context.Background(), "cloudflare/cloudflared:latest", "sha256:111111")
	if err != nil {
		t.Fatalf("CheckImageUpdates(cloudflared) error: %v", err)
	}
	if !outdated || remDigest != "sha256:999999" || latestVer != "2026.10.2" || len(tags) < 3 {
		t.Fatalf("unexpected cloudflared update result: latest=%s outdated=%v digest=%s tags=%v", latestVer, outdated, remDigest, tags)
	}

	// 2. Flavor-pinned postgres:16.4-alpine -> preserves -alpine suffix
	pgLatest, pgTags, _, pgOutdated, err := client.CheckImageUpdates(context.Background(), "docker.io/library/postgres:16.4-alpine", "sha256:222")
	if err != nil {
		t.Fatalf("CheckImageUpdates(postgres) error: %v", err)
	}
	if !pgOutdated || pgLatest != "16.6-alpine" {
		t.Fatalf("expected 16.6-alpine as same-major latest, got latest=%s outdated=%v tags=%v", pgLatest, pgOutdated, pgTags)
	}
}
