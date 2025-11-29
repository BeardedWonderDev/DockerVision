package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/beardedwonder/dockervision-agent/internal/config"
	"github.com/beardedwonder/dockervision-agent/internal/docker"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server hosts the HTTP API for DockerVision.
type Server struct {
	cfg        config.Config
	docker     docker.Client
	logger     *slog.Logger
	mux        *http.ServeMux
	streams    map[string]context.CancelFunc
	streamData map[string]*execStream
	streamMu   sync.Mutex
	wsLimit    int
	metrics    Metrics
}

// NewServer wires routes with dependencies.
func NewServer(cfg config.Config, d docker.Client, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s := &Server{
		cfg:        cfg,
		docker:     d,
		logger:     logger,
		mux:        http.NewServeMux(),
		streams:    make(map[string]context.CancelFunc),
		streamData: make(map[string]*execStream),
		wsLimit:    8,
		metrics:    defaultMetrics(),
	}
	s.routes()
	return s
}

// Handler returns the http.Handler for the server.
func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /health", s.handleHealth)
	s.mux.HandleFunc("GET /system/info", s.requireTokenIfSet(s.handleSystemInfo))
	s.mux.HandleFunc("GET /containers", s.requireTokenIfSet(s.handleListContainers))
	s.mux.HandleFunc("GET /containers/{id}", s.requireTokenIfSet(s.handleInspectContainer))
	s.mux.HandleFunc("POST /containers/{id}/start", s.requireTokenIfSet(s.handleStartContainer))
	s.mux.HandleFunc("POST /containers/{id}/stop", s.requireTokenIfSet(s.handleStopContainer))
	s.mux.HandleFunc("POST /containers/{id}/restart", s.requireTokenIfSet(s.handleRestartContainer))
	s.mux.HandleFunc("GET /containers/{id}/logs", s.requireTokenIfSet(s.handleContainerLogs))
	s.mux.HandleFunc("GET /events", s.requireTokenIfSet(s.handleEvents))
	s.mux.HandleFunc("GET /ws", s.requireTokenIfSet(s.handleWebsocket))
	if strings.TrimSpace(s.cfg.AuthToken) != "" {
		s.mux.Handle("/metrics", s.requireTokenIfSetHandler(promhttp.HandlerFor(s.metrics.Registry, promhttp.HandlerOpts{})))
	} else {
		s.mux.Handle("/metrics", promhttp.HandlerFor(s.metrics.Registry, promhttp.HandlerOpts{}))
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), time.Second)
	defer cancel()

	if err := s.docker.Ping(ctx); err != nil {
		s.logger.Warn("docker ping failed", slog.String("error", err.Error()))
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status": "degraded",
			"error":  "docker unreachable",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok",
	})
}

func (s *Server) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	info, err := s.docker.Info(ctx)
	if err != nil {
		s.logger.Error("docker info failed", slog.String("error", err.Error()))
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "docker info unavailable",
		})
		return
	}

	resp := map[string]any{
		"serverVersion":   info.ServerVersion,
		"operatingSystem": info.OperatingSystem,
		"osType":          info.OSType,
		"architecture":    info.Architecture,
		"kernelVersion":   info.KernelVersion,
		"nCPU":            info.NCPU,
		"memTotal":        info.MemTotal,
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleListContainers(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()

	all := parseBoolDefault(r.URL.Query().Get("all"), false)
	stateFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("state")))

	containers, err := s.docker.ListContainers(ctx, all)
	if err != nil {
		s.logger.Error("list containers failed", slog.String("error", err.Error()))
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "docker unavailable"})
		return
	}

	items := make([]map[string]any, 0, len(containers))
	for _, c := range containers {
		if stateFilter != "" && strings.ToLower(c.State) != stateFilter {
			continue
		}
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		items = append(items, map[string]any{
			"id":        c.ID,
			"name":      name,
			"image":     c.Image,
			"state":     c.State,
			"status":    c.Status,
			"createdAt": time.Unix(c.Created, 0),
			"ports":     c.Ports,
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{"containers": items})
}

func (s *Server) handleInspectContainer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "container id required"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
	defer cancel()

	info, err := s.docker.InspectContainer(ctx, id)
	if err != nil {
		if client.IsErrNotFound(err) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "container not found"})
			return
		}
		s.logger.Error("inspect container failed", slog.String("error", err.Error()))
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "docker unavailable"})
		return
	}

	writeJSON(w, http.StatusOK, info)
}

func (s *Server) handleStartContainer(w http.ResponseWriter, r *http.Request) {
	s.controlContainer(w, r, "start")
}

func (s *Server) handleStopContainer(w http.ResponseWriter, r *http.Request) {
	s.controlContainer(w, r, "stop")
}

func (s *Server) handleRestartContainer(w http.ResponseWriter, r *http.Request) {
	s.controlContainer(w, r, "restart")
}

func (s *Server) controlContainer(w http.ResponseWriter, r *http.Request, action string) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "container id required"})
		return
	}

	timeout := parseTimeout(r.URL.Query().Get("timeoutSeconds"))

	ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
	defer cancel()

	var err error
	switch action {
	case "start":
		err = s.docker.StartContainer(ctx, id)
	case "stop":
		err = s.docker.StopContainer(ctx, id, timeout)
	case "restart":
		err = s.docker.RestartContainer(ctx, id, timeout)
	default:
		err = errors.New("unsupported action")
	}

	if err != nil {
		if client.IsErrNotFound(err) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "container not found"})
			return
		}
		s.logger.Error("container control failed", slog.String("action", action), slog.String("error", err.Error()))
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "docker unavailable"})
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{"status": action + "ed"})
}

func (s *Server) handleContainerLogs(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "container id required"})
		return
	}

	q := r.URL.Query()
	lines := q.Get("lines")
	if lines == "" {
		lines = "100"
	}
	stdout := parseBoolDefault(q.Get("stdout"), true)
	stderr := parseBoolDefault(q.Get("stderr"), false)
	follow := parseBoolDefault(q.Get("follow"), false)
	timestamps := parseBoolDefault(q.Get("timestamps"), false)
	since := q.Get("since")

	opts := container.LogsOptions{
		ShowStdout: stdout,
		ShowStderr: stderr,
		Follow:     follow,
		Timestamps: timestamps,
		Tail:       lines,
		Since:      since,
	}

	ctx := r.Context()
	// For non-follow requests, bound time to avoid hanging.
	if !follow {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}

	reader, err := s.docker.ContainerLogs(ctx, id, opts)
	if err != nil {
		if client.IsErrNotFound(err) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "container not found"})
			return
		}
		s.logger.Error("container logs failed", slog.String("error", err.Error()))
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "docker unavailable"})
		return
	}
	defer reader.Close()

	w.Header().Set("Content-Type", "text/plain")
	if follow {
		if f, ok := w.(http.Flusher); ok {
			_, _ = io.Copy(w, reader)
			f.Flush()
		} else {
			_, _ = io.Copy(w, reader)
		}
	} else {
		_, _ = io.Copy(w, reader)
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (s *Server) requireTokenIfSet(next http.HandlerFunc) http.HandlerFunc {
	if strings.TrimSpace(s.cfg.AuthToken) == "" {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func (s *Server) requireTokenIfSetHandler(next http.Handler) http.Handler {
	if strings.TrimSpace(s.cfg.AuthToken) == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.authorized(r) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authorized(r *http.Request) bool {
	header := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	token := strings.TrimSpace(strings.TrimPrefix(header, prefix))
	if len(token) != len(s.cfg.AuthToken) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.AuthToken)) == 1
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	args := filters.NewArgs()
	q := r.URL.Query()
	if v := strings.TrimSpace(q.Get("type")); v != "" {
		args.Add("type", v)
	}
	if v := strings.TrimSpace(q.Get("action")); v != "" {
		args.Add("event", v)
	}
	if v := strings.TrimSpace(q.Get("container")); v != "" {
		args.Add("container", v)
	}
	if v := strings.TrimSpace(q.Get("image")); v != "" {
		args.Add("image", v)
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	msgCh, errCh := s.docker.Events(ctx, types.EventsOptions{
		Filters: args,
		Since:   q.Get("since"),
	})

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case err := <-errCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				sendSSE(w, flusher, "error", map[string]string{"error": err.Error()})
			}
			return
		case ev := <-msgCh:
			if ev.Type == "" && ev.Action == "" && ev.ID == "" {
				return
			}
			sendSSE(w, flusher, "event", ev)
		case <-heartbeat.C:
			sendSSE(w, flusher, "heartbeat", "ok")
		}
	}
}

func sendSSE(w http.ResponseWriter, flusher http.Flusher, event string, data any) {
	var sb strings.Builder
	if event != "" {
		sb.WriteString("event: ")
		sb.WriteString(event)
		sb.WriteString("\n")
	}
	if data != nil {
		bytes, _ := json.Marshal(data)
		sb.WriteString("data: ")
		sb.Write(bytes)
		sb.WriteString("\n")
	}
	sb.WriteString("\n")
	_, _ = io.WriteString(w, sb.String())
	flusher.Flush()
}

// --- WebSocket bidirectional control ---

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		// Agent is local-first; allow same-machine connections.
		return true
	},
}

type wsMessage struct {
	Type        string         `json:"type"` // cmd | close | ack | error | log | event | pong
	Action      string         `json:"action,omitempty"`
	ContainerID string         `json:"containerId,omitempty"`
	StreamID    string         `json:"streamId,omitempty"`
	Data        map[string]any `json:"data,omitempty"`
	Params      map[string]any `json:"params,omitempty"`
}

type execStream struct {
	stdin   io.Writer
	resize  func(h, w uint)
	writeMu sync.Mutex
}

func (s *Server) handleWebsocket(w http.ResponseWriter, r *http.Request) {
	// basic connection limit
	s.streamMu.Lock()
	active := len(s.streams)
	s.streamMu.Unlock()
	if active >= s.wsLimit {
		http.Error(w, "too many streams", http.StatusServiceUnavailable)
		return
	}
	s.metrics.WSActive.Inc()

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.metrics.WSErrors.Inc()
		return
	}
	defer conn.Close()
	defer s.metrics.WSActive.Dec()

	// serialize writes to avoid concurrent write panics
	writeMu := &sync.Mutex{}
	send := func(msg wsMessage) {
		writeMu.Lock()
		defer writeMu.Unlock()
		_ = conn.WriteJSON(msg)
	}

	// close all active streams on disconnect
	defer s.cancelAllStreams()

	conn.SetReadLimit(1 << 20) // 1MB
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		var msg wsMessage
		if err := conn.ReadJSON(&msg); err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				return
			}
			s.logger.Warn("ws read error", slog.String("error", err.Error()))
			return
		}

		switch msg.Type {
		case "ping":
			send(wsMessage{Type: "pong"})
		case "close":
			s.cancelStream(msg.StreamID)
		case "cmd":
			s.handleWSCommand(r.Context(), msg, send)
		default:
			send(wsMessage{Type: "error", StreamID: msg.StreamID, Data: map[string]any{"error": "unknown message type"}})
		}
	}
}

func (s *Server) handleWSCommand(ctx context.Context, msg wsMessage, send func(wsMessage)) {
	streamID := msg.StreamID
	if streamID == "" {
		streamID = strconv.FormatInt(time.Now().UnixNano(), 36)
	}

	switch msg.Action {
	case "start", "stop", "restart":
		s.handleWSLifecycle(ctx, msg, streamID, send)
	case "logs":
		s.handleWSLogs(ctx, msg, streamID, send)
	case "events":
		s.handleWSEvents(ctx, msg, streamID, send)
	case "exec":
		s.handleWSExec(ctx, msg, streamID, send)
	default:
		send(wsMessage{Type: "error", StreamID: streamID, Data: map[string]any{"error": "unknown action"}})
	}
	s.metrics.WSCreated.Inc()
}

func (s *Server) handleWSLifecycle(ctx context.Context, msg wsMessage, streamID string, send func(wsMessage)) {
	id := msg.ContainerID
	if id == "" {
		send(wsMessage{Type: "error", StreamID: streamID, Data: map[string]any{"error": "containerId required"}})
		return
	}
	cctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()

	var err error
	switch msg.Action {
	case "start":
		err = s.docker.StartContainer(cctx, id)
	case "stop":
		err = s.docker.StopContainer(cctx, id, nil)
	case "restart":
		err = s.docker.RestartContainer(cctx, id, nil)
	}

	if err != nil {
		status := map[string]any{"error": err.Error()}
		if client.IsErrNotFound(err) {
			status["code"] = http.StatusNotFound
		}
		s.metrics.DockerFail.WithLabelValues("lifecycle").Inc()
		send(wsMessage{Type: "error", StreamID: streamID, Data: status})
		return
	}
	send(wsMessage{Type: "ack", StreamID: streamID, Action: msg.Action})
}

func (s *Server) handleWSLogs(ctx context.Context, msg wsMessage, streamID string, send func(wsMessage)) {
	id := msg.ContainerID
	if id == "" {
		send(wsMessage{Type: "error", StreamID: streamID, Data: map[string]any{"error": "containerId required"}})
		return
	}
	params := msg.Params
	lines := "100"
	if v, ok := params["lines"].(string); ok && v != "" {
		lines = v
	}
	stdout := parseBoolDefault(asString(params["stdout"]), true)
	stderr := parseBoolDefault(asString(params["stderr"]), false)
	follow := parseBoolDefault(asString(params["follow"]), true)
	timestamps := parseBoolDefault(asString(params["timestamps"]), false)

	opts := container.LogsOptions{
		ShowStdout: stdout,
		ShowStderr: stderr,
		Follow:     follow,
		Timestamps: timestamps,
		Tail:       lines,
	}

	lctx, cancel := context.WithCancel(ctx)
	s.setStream(streamID, cancel)

	reader, err := s.docker.ContainerLogs(lctx, id, opts)
	if err != nil {
		s.cancelStream(streamID)
		status := map[string]any{"error": err.Error()}
		if client.IsErrNotFound(err) {
			status["code"] = http.StatusNotFound
		}
		s.metrics.DockerFail.WithLabelValues("logs").Inc()
		send(wsMessage{Type: "error", StreamID: streamID, Data: status})
		return
	}

	send(wsMessage{Type: "ack", StreamID: streamID, Action: "logs"})

	go func() {
		defer reader.Close()
		buf := make([]byte, 2048)
		for {
			n, readErr := reader.Read(buf)
			if n > 0 {
				send(wsMessage{Type: "log", StreamID: streamID, Data: map[string]any{"chunk": string(buf[:n])}})
			}
			if readErr != nil {
				if !errors.Is(readErr, io.EOF) {
					send(wsMessage{Type: "error", StreamID: streamID, Data: map[string]any{"error": readErr.Error()}})
				}
				s.cancelStream(streamID)
				return
			}
		}
	}()
}

func (s *Server) handleWSEvents(ctx context.Context, msg wsMessage, streamID string, send func(wsMessage)) {
	args := filters.NewArgs()
	if v, ok := msg.Params["type"].(string); ok && v != "" {
		args.Add("type", v)
	}
	if v, ok := msg.Params["action"].(string); ok && v != "" {
		args.Add("event", v)
	}
	if v, ok := msg.Params["container"].(string); ok && v != "" {
		args.Add("container", v)
	}
	if v, ok := msg.Params["image"].(string); ok && v != "" {
		args.Add("image", v)
	}

	evCtx, cancel := context.WithCancel(ctx)
	s.setStream(streamID, cancel)

	msgCh, errCh := s.docker.Events(evCtx, types.EventsOptions{
		Filters: args,
	})

	send(wsMessage{Type: "ack", StreamID: streamID, Action: "events"})

	go func() {
		for {
			select {
			case ev := <-msgCh:
				if ev.Type == "" && ev.Action == "" {
					s.cancelStream(streamID)
					return
				}
				send(wsMessage{Type: "event", StreamID: streamID, Data: map[string]any{
					"type":   ev.Type,
					"action": ev.Action,
					"id":     ev.ID,
				}})
			case err := <-errCh:
				if err != nil && !errors.Is(err, context.Canceled) {
					send(wsMessage{Type: "error", StreamID: streamID, Data: map[string]any{"error": err.Error()}})
				}
				s.cancelStream(streamID)
				return
			case <-evCtx.Done():
				s.cancelStream(streamID)
				return
			}
		}
	}()
}

func (s *Server) handleWSExec(ctx context.Context, msg wsMessage, streamID string, send func(wsMessage)) {
	id := msg.ContainerID
	if id == "" {
		send(wsMessage{Type: "error", StreamID: streamID, Data: map[string]any{"error": "containerId required"}})
		return
	}

	env := []string{}
	if envAny, ok := msg.Params["env"].([]any); ok {
		for _, e := range envAny {
			if str, ok := e.(string); ok {
				env = append(env, str)
			}
		}
	}

	cmd := []string{}
	if cAny, ok := msg.Params["cmd"].([]any); ok {
		for _, e := range cAny {
			if str, ok := e.(string); ok {
				cmd = append(cmd, str)
			}
		}
	}
	if len(cmd) == 0 {
		send(wsMessage{Type: "error", StreamID: streamID, Data: map[string]any{"error": "cmd required"}})
		return
	}

	tty := parseBoolDefault(asString(msg.Params["tty"]), true)

	execCtx, cancel := context.WithCancel(ctx)
	s.setStream(streamID, cancel)

	resp, err := s.docker.ContainerExecCreate(execCtx, id, types.ExecConfig{
		AttachStdout: true,
		AttachStderr: true,
		AttachStdin:  true,
		Tty:          tty,
		Env:          env,
		Cmd:          cmd,
	})
	if err != nil {
		s.cancelStream(streamID)
		send(wsMessage{Type: "error", StreamID: streamID, Data: map[string]any{"error": err.Error()}})
		s.metrics.DockerFail.WithLabelValues("exec").Inc()
		return
	}

	attach, err := s.docker.ContainerExecAttach(execCtx, resp.ID, types.ExecStartCheck{Tty: tty})
	if err != nil {
		s.cancelStream(streamID)
		send(wsMessage{Type: "error", StreamID: streamID, Data: map[string]any{"error": err.Error()}})
		return
	}

	s.setStreamData(streamID, &execStream{
		stdin: attach.Conn,
		resize: func(h, w uint) {
			_ = s.docker.ContainerExecResize(execCtx, resp.ID, h, w)
		},
	})

	send(wsMessage{Type: "ack", StreamID: streamID, Action: "exec"})

	// read pump
	go func() {
		defer attach.Close()
		buf := make([]byte, 2048)
		for {
			n, readErr := attach.Reader.Read(buf)
			if n > 0 {
				send(wsMessage{Type: "exec", StreamID: streamID, Data: map[string]any{"stdout": string(buf[:n])}})
			}
			if readErr != nil {
				if !errors.Is(readErr, io.EOF) {
					send(wsMessage{Type: "error", StreamID: streamID, Data: map[string]any{"error": readErr.Error()}})
				}
				s.cancelStream(streamID)
				s.clearStreamData(streamID)
				return
			}
		}
	}()
}

func (s *Server) handleWSInput(msg wsMessage) {
	s.streamMu.Lock()
	data, ok := s.streamData[msg.StreamID]
	s.streamMu.Unlock()
	if !ok || data == nil {
		return
	}
	if chunk, ok := msg.Data["chunk"].(string); ok {
		data.writeMu.Lock()
		_, _ = data.stdin.Write([]byte(chunk))
		data.writeMu.Unlock()
	}
}

func (s *Server) handleWSResize(msg wsMessage) {
	s.streamMu.Lock()
	data, ok := s.streamData[msg.StreamID]
	s.streamMu.Unlock()
	if !ok || data == nil {
		return
	}
	h := uint(0)
	w := uint(0)
	if v, ok := msg.Data["height"].(float64); ok {
		h = uint(v)
	}
	if v, ok := msg.Data["width"].(float64); ok {
		w = uint(v)
	}
	if h > 0 && w > 0 && data.resize != nil {
		data.resize(h, w)
	}
}

func (s *Server) setStream(id string, cancel context.CancelFunc) {
	s.streamMu.Lock()
	defer s.streamMu.Unlock()
	if old, ok := s.streams[id]; ok {
		old()
	}
	s.streams[id] = cancel
}

func (s *Server) cancelStream(id string) {
	s.streamMu.Lock()
	defer s.streamMu.Unlock()
	if cancel, ok := s.streams[id]; ok {
		cancel()
		delete(s.streams, id)
	}
	delete(s.streamData, id)
}

func (s *Server) cancelAllStreams() {
	s.streamMu.Lock()
	defer s.streamMu.Unlock()
	for id, cancel := range s.streams {
		cancel()
		delete(s.streams, id)
	}
	for id := range s.streamData {
		delete(s.streamData, id)
	}
}

func (s *Server) setStreamData(id string, data *execStream) {
	s.streamMu.Lock()
	defer s.streamMu.Unlock()
	s.streamData[id] = data
}

func (s *Server) clearStreamData(id string) {
	s.streamMu.Lock()
	defer s.streamMu.Unlock()
	delete(s.streamData, id)
}

func parseBoolDefault(val string, def bool) bool {
	if val == "" {
		return def
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		return def
	}
	return b
}

func parseTimeout(val string) *time.Duration {
	if val == "" {
		return nil
	}
	secs, err := strconv.Atoi(val)
	if err != nil || secs < 0 {
		return nil
	}
	d := time.Duration(secs) * time.Second
	return &d
}

func asString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return ""
	}
}
