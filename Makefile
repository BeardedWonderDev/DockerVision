SHELL := /bin/sh

APP := dockervision-agent
PKG := github.com/beardedwonder/dockervision-agent
GOFILES := $(shell find . -name '*.go' -not -path "./vendor/*")

.PHONY: all tidy lint test race run install clean

all: lint test

tidy:
	go mod tidy

lint:
	go vet ./...

test:
	go test ./...

race:
	go test -race ./...

run:
	go run ./cmd/$(APP)

# Placeholder: install will later drop launchd plist
install:
	@echo "Install target will be implemented after launchd plist is added."

clean:
	rm -rf bin
