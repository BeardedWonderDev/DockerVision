package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/beardedwonder/dockervision-agent/internal/config"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/system"
	"github.com/docker/docker/errdefs"
	"github.com/gorilla/websocket"
)

type nopWriteCloser struct {
	w io.Writer
}

func (n nopWriteCloser) Write(p []byte) (int, error) { return n.w.Write(p) }
func (n nopWriteCloser) Close() error                { return nil }

type fakeDocker struct {
	pingErr     error
	info        system.Info
	infoErr     error
	list        []types.Container
	listErr     error
	inspect     types.ContainerJSON
	inspectErr  error
	startErr    error
	stopErr     error
	restartErr  error
	logReader   io.ReadCloser
	logErr      error
	eventsCh    <-chan events.Message
	eventsErr   <-chan error
	startCalled bool
	execAttach  types.HijackedResponse
	execCreate  types.IDResponse
	execErr     error
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
	f.startCalled = true
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

func (f *fakeDocker) Events(ctx context.Context, opts types.EventsOptions) (<-chan events.Message, <-chan error) {
	if f.eventsCh == nil {
		ch := make(chan events.Message)
		close(ch)
		f.eventsCh = ch
	}
	if f.eventsErr == nil {
		errCh := make(chan error)
		close(errCh)
		f.eventsErr = errCh
	}
	return f.eventsCh, f.eventsErr
}

func (f *fakeDocker) ContainerExecCreate(ctx context.Context, id string, opts types.ExecConfig) (types.IDResponse, error) {
	if f.execErr != nil {
		return types.IDResponse{}, f.execErr
	}
	if f.execCreate.ID == "" {
		return types.IDResponse{ID: "exec123"}, nil
	}
	return f.execCreate, nil
}

func (f *fakeDocker) ContainerExecAttach(ctx context.Context, execID string, opts types.ExecStartCheck) (types.HijackedResponse, error) {
	if f.execErr != nil {
		return types.HijackedResponse{}, f.execErr
	}
	if f.execAttach.Reader == nil {
		c1, _ := net.Pipe()
		return types.HijackedResponse{
			Conn:   c1,
			Reader: bufio.NewReader(strings.NewReader("output\n")),
		}, nil
	}
	return f.execAttach, nil
}

func (f *fakeDocker) ContainerExecResize(ctx context.Context, execID string, height, width uint) error {
	return f.execErr
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

func TestMetricsEndpoint(t *testing.T) {
	s := NewServer(config.Config{ListenAddr: "127.0.0.1:0"}, &fakeDocker{}, nil)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestAuthRequired(t *testing.T) {
	cfg := config.Config{ListenAddr: "127.0.0.1:0", AuthToken: "secret"}
	s := NewServer(cfg, &fakeDocker{}, nil)
	req := httptest.NewRequest(http.MethodGet, "/containers", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/containers", nil)
	req2.Header.Set("Authorization", "Bearer secret")
	rec2 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec2.Code)
	}
}

func TestEventsStream(t *testing.T) {
	evCh := make(chan events.Message, 1)
	errCh := make(chan error)
	evCh <- events.Message{Type: events.ContainerEventType, Action: "start", ID: "abc123"}
	close(evCh)

	s := NewServer(config.Config{ListenAddr: "127.0.0.1:0"}, &fakeDocker{eventsCh: evCh, eventsErr: errCh}, nil)
	req := httptest.NewRequest(http.MethodGet, "/events", nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(strings.ToLower(rec.Body.String()), `"action":"start"`) {
		t.Fatalf("expected event payload, got %q", rec.Body.String())
	}
}

func TestWebsocketLifecycleStart(t *testing.T) {
	fd := &fakeDocker{}
	s := NewServer(config.Config{ListenAddr: "127.0.0.1:0"}, fd, nil)
	server := httptest.NewServer(s.Handler())
	defer server.Close()

	u := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
	conn, _, err := websocket.DefaultDialer.Dial(u, nil)
	if err != nil {
		t.Fatalf("dial ws: %v", err)
	}
	defer conn.Close()

	cmd := `{"type":"cmd","action":"start","containerId":"abc"}`
	if err := conn.WriteMessage(websocket.TextMessage, []byte(cmd)); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(msg), `"ack"`) {
		t.Fatalf("expected ack, got %s", string(msg))
	}
	if !fd.startCalled {
		t.Fatalf("expected start to be called")
	}
}

func TestWebsocketLogs(t *testing.T) {
	fd := &fakeDocker{
		logReader: io.NopCloser(strings.NewReader("hello\nworld\n")),
	}
	s := NewServer(config.Config{ListenAddr: "127.0.0.1:0"}, fd, nil)
	server := httptest.NewServer(s.Handler())
	defer server.Close()

	u := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
	conn, _, err := websocket.DefaultDialer.Dial(u, nil)
	if err != nil {
		t.Fatalf("dial ws: %v", err)
	}
	defer conn.Close()

	cmd := `{"type":"cmd","action":"logs","containerId":"abc","streamId":"s1","params":{"follow":false,"stdout":true,"lines":"10"}}`
	if err := conn.WriteMessage(websocket.TextMessage, []byte(cmd)); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Expect ack then log chunk
	_, msg1, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read ack: %v", err)
	}
	if !strings.Contains(string(msg1), `"ack"`) {
		t.Fatalf("expected ack, got %s", string(msg1))
	}
	_, msg2, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if !strings.Contains(string(msg2), "hello") {
		t.Fatalf("expected log chunk, got %s", string(msg2))
	}
}
