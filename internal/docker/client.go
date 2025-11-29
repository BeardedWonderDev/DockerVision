package docker

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/system"
	"github.com/docker/docker/client"
)

// Client defines the subset of Docker Engine operations the agent needs.
type Client interface {
	Ping(ctx context.Context) error
	Info(ctx context.Context) (system.Info, error)
	ListContainers(ctx context.Context, all bool) ([]types.Container, error)
	InspectContainer(ctx context.Context, id string) (types.ContainerJSON, error)
	StartContainer(ctx context.Context, id string) error
	StopContainer(ctx context.Context, id string, timeout *time.Duration) error
	RestartContainer(ctx context.Context, id string, timeout *time.Duration) error
	ContainerLogs(ctx context.Context, id string, opts container.LogsOptions) (io.ReadCloser, error)
	Events(ctx context.Context, opts types.EventsOptions) (<-chan events.Message, <-chan error)
	Close() error
}

// Engine wraps the official Docker SDK client.
type Engine struct {
	cli *client.Client
}

// New creates a Docker Engine client using the provided host override (optional).
// If host is empty, environment variables and defaults are used.
func New(ctx context.Context, host string) (*Engine, error) {
	opts := []client.Opt{
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	}
	if host != "" {
		opts = append(opts, client.WithHost(host))
	}
	cli, err := client.NewClientWithOpts(opts...)
	if err != nil {
		return nil, fmt.Errorf("create docker client: %w", err)
	}
	// Quick ping to fail fast on bad sockets.
	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if _, err := cli.Ping(pingCtx); err != nil {
		_ = cli.Close()
		return nil, fmt.Errorf("ping docker: %w", err)
	}
	return &Engine{cli: cli}, nil
}

func (e *Engine) Ping(ctx context.Context) error {
	_, err := e.cli.Ping(ctx)
	return err
}

func (e *Engine) Info(ctx context.Context) (system.Info, error) {
	return e.cli.Info(ctx)
}

func (e *Engine) ListContainers(ctx context.Context, all bool) ([]types.Container, error) {
	return e.cli.ContainerList(ctx, container.ListOptions{All: all})
}

func (e *Engine) InspectContainer(ctx context.Context, id string) (types.ContainerJSON, error) {
	return e.cli.ContainerInspect(ctx, id)
}

func (e *Engine) StartContainer(ctx context.Context, id string) error {
	return e.cli.ContainerStart(ctx, id, container.StartOptions{})
}

func (e *Engine) StopContainer(ctx context.Context, id string, timeout *time.Duration) error {
	var secs *int
	if timeout != nil {
		v := int(timeout.Seconds())
		secs = &v
	}
	return e.cli.ContainerStop(ctx, id, container.StopOptions{Timeout: secs})
}

func (e *Engine) RestartContainer(ctx context.Context, id string, timeout *time.Duration) error {
	var secs *int
	if timeout != nil {
		v := int(timeout.Seconds())
		secs = &v
	}
	return e.cli.ContainerRestart(ctx, id, container.StopOptions{Timeout: secs})
}

func (e *Engine) ContainerLogs(ctx context.Context, id string, opts container.LogsOptions) (io.ReadCloser, error) {
	return e.cli.ContainerLogs(ctx, id, opts)
}

func (e *Engine) Events(ctx context.Context, opts types.EventsOptions) (<-chan events.Message, <-chan error) {
	return e.cli.Events(ctx, opts)
}

func (e *Engine) Close() error {
	return e.cli.Close()
}
