VERSION ?= $(shell date +%Y-%m-%d.%H.%M)
LDFLAGS := -ldflags "-X github.com/jaewoook/security-hub/internal/version.BuildVersion=$(VERSION)"

.PHONY: all build frontend daemon agent test

all: build

build: frontend daemon

frontend:
	cd frontend && ([ -d node_modules ] || yarn install --frozen-lockfile) && yarn build

daemon:
	go build $(LDFLAGS) -o security-hub ./cmd/security-hub

agent:
	go build -tags agent $(LDFLAGS) -o security-hub ./cmd/security-hub

test: frontend
	go test -race -count=1 ./...
