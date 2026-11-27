VERSION ?= $(shell date +%Y-%m-%d.%H.%M)
LDFLAGS := -ldflags "-X github.com/jaewoook/security-hub/internal/version.BuildVersion=$(VERSION)"

.PHONY: all build frontend daemon test

all: build

build: frontend daemon

frontend:
	cd frontend && ([ -d node_modules ] || yarn install --frozen-lockfile) && yarn build

daemon:
	@mkdir -p internal/web/static
	@if [ -z "$$(ls -A internal/web/static 2>/dev/null)" ]; then touch internal/web/static/.placeholder; fi
	go build $(LDFLAGS) -o security-hub ./cmd/security-hub

test: frontend
	go test -race -count=1 ./...
