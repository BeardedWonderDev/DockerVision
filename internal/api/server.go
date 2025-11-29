package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/beardedwonder/dockervision-agent/internal/config"
	"github.com/beardedwonder/dockervision-agent/internal/docker"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

// Server hosts the HTTP API for DockerVision.
type Server struct {
	cfg    config.Config
	docker docker.Client
	logger *slog.Logger
	mux    *http.ServeMux
}

// NewServer wires routes with dependencies.
func NewServer(cfg config.Config, d docker.Client, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	s := &Server{
		cfg:    cfg,
		docker: d,
		logger: logger,
		mux:    http.NewServeMux(),
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
	s.mux.HandleFunc("GET /system/info", s.handleSystemInfo)
	s.mux.HandleFunc("GET /containers", s.handleListContainers)
	s.mux.HandleFunc("GET /containers/{id}", s.handleInspectContainer)
	s.mux.HandleFunc("POST /containers/{id}/start", s.handleStartContainer)
	s.mux.HandleFunc("POST /containers/{id}/stop", s.handleStopContainer)
	s.mux.HandleFunc("POST /containers/{id}/restart", s.handleRestartContainer)
	s.mux.HandleFunc("GET /containers/{id}/logs", s.handleContainerLogs)
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
