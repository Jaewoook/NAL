package updater

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateFileTag_PreservesCommentsAndEnvVars(t *testing.T) {
	dir := t.TempDir()
	composePath := filepath.Join(dir, "compose.yml")
	envPath := filepath.Join(dir, ".env")

	composeOriginal := `services:
  server:
    image: ${AUTHENTIK_IMAGE:-ghcr.io/goauthentik/server}:${AUTHENTIK_TAG:-2026.5.3}
    volumes:
      # Git-managed branding assets.
      - data:/data
  worker:
    image: ${AUTHENTIK_IMAGE:-ghcr.io/goauthentik/server}:${AUTHENTIK_TAG:-2026.5.3}
`
	envOriginal := `# Authentik Env
AUTHENTIK_SECRET_KEY=supersecret
AUTHENTIK_TAG=2026.5.3
`
	_ = os.WriteFile(composePath, []byte(composeOriginal), 0644)
	_ = os.WriteFile(envPath, []byte(envOriginal), 0644)

	newC, newE, err := UpdateFileTag(composePath, envPath, "server", "2026.10.1")
	if err != nil {
		t.Fatalf("UpdateFileTag failed: %v", err)
	}
	if !strings.Contains(string(newC), "# Git-managed branding assets.") {
		t.Fatalf("expected comments preserved in compose.yml: %s", string(newC))
	}
	if !strings.Contains(string(newC), "${AUTHENTIK_TAG:-2026.10.1}") {
		t.Fatalf("expected default tag updated in compose.yml: %s", string(newC))
	}
	if !strings.Contains(string(newE), "AUTHENTIK_TAG=2026.10.1") || !strings.Contains(string(newE), "# Authentik Env") {
		t.Fatalf("expected AUTHENTIK_TAG updated in .env with comments preserved: %s", string(newE))
	}

	// Test direct quoted image tag like 'jc21/nginx-proxy-manager:latest'
	npmCompose := filepath.Join(dir, "docker-compose.yml")
	_ = os.WriteFile(npmCompose, []byte("services:\n  proxy:\n    image: 'jc21/nginx-proxy-manager:latest'\n"), 0644)
	npmOut, _, err := UpdateFileTag(npmCompose, "", "proxy", "2.11.3")
	if err != nil {
		t.Fatalf("UpdateFileTag(npm) failed: %v", err)
	}
	if !strings.Contains(string(npmOut), "'jc21/nginx-proxy-manager:2.11.3'") {
		t.Fatalf("expected quoted tag updated to 2.11.3, got: %s", string(npmOut))
	}

	// Test multi-service compose file (like services/iot/compose.yml) updates ONLY the targeted serviceKey
	iotCompose := filepath.Join(dir, "iot-compose.yml")
	iotOriginal := `services:
  homeassistant:
    image: homeassistant/home-assistant:2026.9.4
    container_name: homeassistant
  matter-hub:
    image: ghcr.io/riddix/home-assistant-matter-hub:2.0.57
    container_name: matter-hub
`
	_ = os.WriteFile(iotCompose, []byte(iotOriginal), 0644)
	iotOut, _, err := UpdateFileTag(iotCompose, "", "matter-hub", "2.0.60")
	if err != nil {
		t.Fatalf("UpdateFileTag(iot) failed: %v", err)
	}
	if !strings.Contains(string(iotOut), "homeassistant/home-assistant:2026.9.4") {
		t.Fatalf("expected homeassistant tag to remain 2026.9.4 when updating matter-hub, got:\n%s", string(iotOut))
	}
	if !strings.Contains(string(iotOut), "ghcr.io/riddix/home-assistant-matter-hub:2.0.60") {
		t.Fatalf("expected matter-hub tag updated to 2.0.60, got:\n%s", string(iotOut))
	}

	// Test 4-space indentation and digest-pinned images: 'image: repo/app:v1.0@sha256:abcd...'
	pinnedCompose := filepath.Join(dir, "pinned-compose.yml")
	pinnedOriginal := "services:\n    app:\n        image: \"cloudflare/cloudflared:2024.1.0@sha256:4a91f8c0e123456789\"\n"
	_ = os.WriteFile(pinnedCompose, []byte(pinnedOriginal), 0644)
	pinnedOut, _, err := UpdateFileTag(pinnedCompose, "", "app", "2026.10.2")
	if err != nil {
		t.Fatalf("UpdateFileTag(pinned) failed: %v", err)
	}
	if !strings.Contains(string(pinnedOut), "\"cloudflare/cloudflared:2026.10.2\"") {
		t.Fatalf("expected digest stripped and tag replaced cleanly, got:\n%s", string(pinnedOut))
	}

	// Test nested keys (environment/volumes) defined before image line
	nestedCompose := filepath.Join(dir, "nested-compose.yml")
	nestedOriginal := `services:
  myapp:
    container_name: myapp
    environment:
      - NODE_ENV=production
      - PORT=8080
    volumes:
      - /data:/data
    image: myrepo/myapp:1.0.0
    restart: unless-stopped
`
	_ = os.WriteFile(nestedCompose, []byte(nestedOriginal), 0644)
	nestedOut, _, err := UpdateFileTag(nestedCompose, "", "myapp", "1.1.0")
	if err != nil {
		t.Fatalf("UpdateFileTag(nested) failed: %v", err)
	}
	if !strings.Contains(string(nestedOut), "myrepo/myapp:1.1.0") {
		t.Fatalf("expected myapp image updated to 1.1.0 even with nested keys preceding image line, got:\n%s", string(nestedOut))
	}
}

func TestUpdateFileTag_FullEnvVarAndNestedLabelsSafety(t *testing.T) {
	dir := t.TempDir()
	composePath := filepath.Join(dir, "compose.yml")
	envPath := filepath.Join(dir, ".env")

	composeContent := `x-template:
  image: should/not-touch:0.1
services:
  app:
    labels:
      meta:
        image: nested/fake:0.1
    image: ${APP_IMAGE:-ghcr.io/acme/app:1.0.0}
`
	envContent := "APP_IMAGE=ghcr.io/acme/app:1.0.0\n"
	_ = os.WriteFile(composePath, []byte(composeContent), 0640)
	_ = os.WriteFile(envPath, []byte(envContent), 0600)

	newC, newE, err := UpdateFileTag(composePath, envPath, "app", "2.0.0")
	if err != nil {
		t.Fatalf("UpdateFileTag failed: %v", err)
	}
	if !strings.Contains(string(newC), "${APP_IMAGE:-ghcr.io/acme/app:2.0.0}") {
		t.Fatalf("expected full-image env default updated preserving brace, got:\n%s", string(newC))
	}
	if !strings.Contains(string(newC), "should/not-touch:0.1") || !strings.Contains(string(newC), "nested/fake:0.1") {
		t.Fatalf("expected x-template and nested labels untouched, got:\n%s", string(newC))
	}
	if !strings.Contains(string(newE), "APP_IMAGE=ghcr.io/acme/app:2.0.0") {
		t.Fatalf("expected full-image .env value updated preserving repo, got:\n%s", string(newE))
	}
	if _, _, err := UpdateFileTag(composePath, envPath, "app", "bad\ntag"); err == nil {
		t.Fatal("expected newline tag injection in UpdateFileTag to fail")
	}
}
