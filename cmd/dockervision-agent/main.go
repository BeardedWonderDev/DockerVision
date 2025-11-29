package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
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
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg := config.FromEnv()
	flag.StringVar(&cfg.ListenAddr, "listen", cfg.ListenAddr, "listen address (host:port)")
	flag.StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "log level: debug|info|warn|error")
	flag.StringVar(&cfg.DockerHost, "docker-host", cfg.DockerHost, "docker host override (unix:///var/run/docker.sock, tcp://host:2375, etc)")
	flag.StringVar(&cfg.TLSClientCA, "tls-client-ca", cfg.TLSClientCA, "optional client CA PEM to require mTLS")
	flag.StringVar(&cfg.OTLPEndpoint, "otel-endpoint", cfg.OTLPEndpoint, "OTLP/HTTP endpoint for tracing (optional)")
	flag.BoolVar(&cfg.OTLPInsecure, "otel-insecure", cfg.OTLPInsecure, "use insecure OTLP connection")
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

	tlsConfig, err := setupTLS(cfg)
	if err != nil {
		logger.Error("failed to init tls", slog.String("error", err.Error()))
		os.Exit(1)
	}

	handler := srv.Handler()
	handler = instrumentHTTP(handler)
	if cfg.OTLPEndpoint != "" {
		shutdown, terr := setupTracing(ctx, cfg, logger)
		if terr != nil {
			logger.Warn("tracing init failed", slog.String("error", terr.Error()))
		} else {
			defer shutdown()
			handler = otelhttp.NewHandler(handler, "http.server")
		}
	}

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		TLSConfig:         tlsConfig,
	}

	go func() {
		logger.Info("starting server", slog.String("addr", cfg.ListenAddr))
		var err error
		if server.TLSConfig != nil {
			err = server.ListenAndServeTLS("", "")
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

func setupTLS(cfg config.Config) (*tls.Config, error) {
	if cfg.TLSCertPath == "" || cfg.TLSKeyPath == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(cfg.TLSCertPath, cfg.TLSKeyPath)
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if cfg.TLSClientCA != "" {
		caPEM, err := os.ReadFile(cfg.TLSClientCA)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to parse client CA")
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return tlsCfg, nil
}

var (
	httpRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Total HTTP requests",
	}, []string{"method", "path", "code"})
	httpLatency = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "http_request_duration_seconds",
		Help:    "HTTP request latency",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path"})
)

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func instrumentHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(ww, r)
		path := r.URL.Path
		if len(path) > 64 {
			path = path[:64]
		}
		httpRequests.WithLabelValues(r.Method, path, fmt.Sprintf("%d", ww.status)).Inc()
		httpLatency.WithLabelValues(r.Method, path).Observe(time.Since(start).Seconds())
	})
}

func setupTracing(ctx context.Context, cfg config.Config, logger *slog.Logger) (func(), error) {
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(cfg.OTLPEndpoint),
		otlptracehttp.WithCompression(otlptracehttp.GzipCompression),
	}
	if cfg.OTLPInsecure {
		opts = append(opts, otlptracehttp.WithInsecure())
	}
	exp, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName("dockervision-agent"),
		))
	if err != nil {
		return nil, err
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tp.Shutdown(ctx)
	}, nil
}
