package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/beardedwonder/dockervision-agent/internal/api"
	"github.com/beardedwonder/dockervision-agent/internal/config"
	"github.com/beardedwonder/dockervision-agent/internal/docker"
	ilog "github.com/beardedwonder/dockervision-agent/internal/log"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg := config.FromEnv()
	flag.StringVar(&cfg.ListenAddr, "listen", cfg.ListenAddr, "listen address (host:port)")
	flag.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "log level: debug|info|warn|error")
	flag.StringVar(&cfg.DockerHost, "docker-host", cfg.DockerHost, "docker host override (unix:///var/run/docker.sock, tcp://host:2375, etc)")
	flag.Parse()

	if err := cfg.Validate(); err != nil {
		log.Fatalf("invalid config: %v", err)
	}

	logger := ilog.NewLogger(cfg.LogLevel)

	dockerClient, err := docker.New(ctx, cfg.DockerHost)
	if err != nil {
		logger.Error("failed to create docker client", slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer dockerClient.Close()

	srv := api.NewServer(cfg, dockerClient, logger)

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		logger.Info("starting server", slog.String("addr", cfg.ListenAddr))
		var err error
		if cfg.TLSCertPath != "" && cfg.TLSKeyPath != "" {
			err = server.ListenAndServeTLS(cfg.TLSCertPath, cfg.TLSKeyPath)
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			logger.Error("server error", slog.String("error", err.Error()))
			stop()
		}
	}()

	<-ctx.Done()
	logger.Info("shutdown signal received")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", slog.String("error", err.Error()))
	}
	logger.Info("server stopped")
}
