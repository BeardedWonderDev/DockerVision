SHELL := /bin/sh

APP := dockervision-agent
PKG := github.com/beardedwonder/dockervision-agent
BIN_DIR := $(HOME)/Library/Application\ Support/DockerVision
BIN_DST := $(BIN_DIR)/$(APP)
PLIST_DST := $(HOME)/Library/LaunchAgents/com.dockervision.agent.plist
GOFILES := $(shell find . -name '*.go' -not -path "./vendor/*")

.PHONY: all tidy lint test race run install uninstall clean build

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

build:
	go build -o bin/$(APP) ./cmd/$(APP)

install: build
	@mkdir -p $(BIN_DIR)
	@cp bin/$(APP) $(BIN_DST)
	@sed "s#__BIN_PATH__#$(BIN_DST)#g" packaging/com.dockervision.agent.plist > $(PLIST_DST)
	launchctl unload $(PLIST_DST) 2>/dev/null || true
	launchctl load $(PLIST_DST)
	@echo "Installed and loaded launchd agent at $(PLIST_DST)"

uninstall:
	launchctl unload $(PLIST_DST) 2>/dev/null || true
	rm -f $(PLIST_DST) $(BIN_DST)
	@echo "Uninstalled launchd agent"

clean:
	rm -rf bin
