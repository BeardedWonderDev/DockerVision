package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/beardedwonder/dockervision-agent/internal/config"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/system"
	"github.com/docker/docker/errdefs"
)

type fakeDocker struct {
	pingErr    error
	info       system.Info
	infoErr    error
	list       []types.Container
	listErr    error
	inspect    types.ContainerJSON
	inspectErr error
	startErr   error
	stopErr    error
	restartErr error
	logReader  io.ReadCloser
	logErr     error
}

func (f *fakeDocker) Ping(ctx context.Context) error {
	return f.pingErr
}

func (f *fakeDocker) Info(ctx context.Context) (system.Info, error) {
	if f.infoErr != nil {
		return system.Info{}, f.infoErr
	}
	return f.info, nil
}

func (f *fakeDocker) Close() error { return nil }

func (f *fakeDocker) ListContainers(ctx context.Context, all bool) ([]types.Container, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.list, nil
}

func (f *fakeDocker) InspectContainer(ctx context.Context, id string) (types.ContainerJSON, error) {
	if f.inspectErr != nil {
		return types.ContainerJSON{}, f.inspectErr
	}
	return f.inspect, nil
}

func (f *fakeDocker) StartContainer(ctx context.Context, id string) error {
	return f.startErr
}

func (f *fakeDocker) StopContainer(ctx context.Context, id string, timeout *time.Duration) error {
	return f.stopErr
}

func (f *fakeDocker) RestartContainer(ctx context.Context, id string, timeout *time.Duration) error {
	return f.restartErr
}

func (f *fakeDocker) ContainerLogs(ctx context.Context, id string, opts container.LogsOptions) (io.ReadCloser, error) {
	if f.logErr != nil {
		return nil, f.logErr
	}
	if f.logReader == nil {
		return io.NopCloser(strings.NewReader("")), nil
	}
	return f.logReader, nil
}

func TestHealthOK(t *testing.T) {
	s := NewServer(config.Config{ListenAddr: "127.0.0.1:0"}, &fakeDocker{}, nil)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["status"] != "ok" {
		t.Fatalf("unexpected body: %v", body)
	}
}

func TestHealthDegraded(t *testing.T) {
	s := NewServer(config.Config{ListenAddr: "127.0.0.1:0"}, &fakeDocker{pingErr: errors.New("no socket")}, nil)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}

func TestSystemInfoOK(t *testing.T) {
	fd := &fakeDocker{
		info: system.Info{
			ServerVersion:   "25.0.1",
			OperatingSystem: "Docker Desktop",
			OSType:          "linux",
			Architecture:    "aarch64",
			KernelVersion:   "6.5",
			NCPU:            6,
			MemTotal:        8 * 1024 * 1024 * 1024,
		},
	}
	s := NewServer(config.Config{ListenAddr: "127.0.0.1:0"}, fd, nil)

	req := httptest.NewRequest(http.MethodGet, "/system/info", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if body["serverVersion"] != "25.0.1" {
		t.Fatalf("unexpected response: %v", body)
	}
}

func TestSystemInfoError(t *testing.T) {
	s := NewServer(config.Config{ListenAddr: "127.0.0.1:0"}, &fakeDocker{infoErr: errors.New("boom")}, nil)

	req := httptest.NewRequest(http.MethodGet, "/system/info", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec.Code)
	}
}

func TestListContainersFilters(t *testing.T) {
	fd := &fakeDocker{
		list: []types.Container{
			{ID: "1", Names: []string{"/web"}, Image: "nginx", State: "running", Status: "Up", Created: time.Now().Add(-time.Hour).Unix()},
			{ID: "2", Names: []string{"/db"}, Image: "postgres", State: "exited", Status: "Exited", Created: time.Now().Add(-2 * time.Hour).Unix()},
		},
	}
	s := NewServer(config.Config{ListenAddr: "127.0.0.1:0"}, fd, nil)

	req := httptest.NewRequest(http.MethodGet, "/containers?state=running", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var body map[string][]map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if len(body["containers"]) != 1 || body["containers"][0]["name"] != "web" {
		t.Fatalf("unexpected filter result: %v", body)
	}
}

func TestInspectNotFound(t *testing.T) {
	s := NewServer(config.Config{ListenAddr: "127.0.0.1:0"}, &fakeDocker{inspectErr: errdefs.NotFound(errors.New("nope"))}, nil)
	req := httptest.NewRequest(http.MethodGet, "/containers/abc", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
}

func TestStartContainer(t *testing.T) {
	s := NewServer(config.Config{ListenAddr: "127.0.0.1:0"}, &fakeDocker{}, nil)
	req := httptest.NewRequest(http.MethodPost, "/containers/abc/start", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", rec.Code)
	}
}

func TestContainerLogs(t *testing.T) {
	fd := &fakeDocker{
		logReader: io.NopCloser(strings.NewReader("line1\nline2\n")),
	}
	s := NewServer(config.Config{ListenAddr: "127.0.0.1:0"}, fd, nil)
	req := httptest.NewRequest(http.MethodGet, "/containers/abc/logs?lines=2", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "line2") {
		t.Fatalf("unexpected logs body: %q", rec.Body.String())
	}
}
