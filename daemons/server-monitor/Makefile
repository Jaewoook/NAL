VERSION ?= $(shell date +%Y-%m-%d.%H.%M)
LDFLAGS := -ldflags "-X github.com/jaewoook/server-monitor/internal/version.BuildVersion=$(VERSION)"

.PHONY: build test

build:
	go build $(LDFLAGS) -o server-monitor ./cmd/server-monitor

test:
	go test -race -count=1 ./...
