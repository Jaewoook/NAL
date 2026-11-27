VERSION ?= $(shell date +%Y-%m-%d.%H.%M)
LDFLAGS := -ldflags "-X github.com/jaewoook/security-hub/internal/version.BuildVersion=$(VERSION)"

.PHONY: all frontend build test

all: frontend build

frontend:
	cd frontend && npm run build

build:
	go build $(LDFLAGS) -o security-hub ./cmd/security-hub

test:
	go test -race -count=1 ./...
