package config

import "testing"

func TestFromEnvDefaults(t *testing.T) {
	t.Setenv("DV_LISTEN_ADDR", "")
	t.Setenv("DV_LOG_LEVEL", "")
	t.Setenv("DOCKER_HOST", "")

	cfg := FromEnv()
	if cfg.ListenAddr == "" || cfg.ListenAddr == "0.0.0.0:0" {
		t.Fatalf("expected default listen address, got %q", cfg.ListenAddr)
	}
	if cfg.LogLevel != defaultLevel {
		t.Fatalf("expected default log level %q, got %q", defaultLevel, cfg.LogLevel)
	}
}

func TestFromEnvOverrides(t *testing.T) {
	t.Setenv("DV_LISTEN_ADDR", "127.0.0.1:9999")
	t.Setenv("DV_LOG_LEVEL", "debug")
	t.Setenv("DOCKER_HOST", "unix:///tmp/docker.sock")
	cfg := FromEnv()

	if cfg.ListenAddr != "127.0.0.1:9999" {
		t.Fatalf("expected listen override, got %q", cfg.ListenAddr)
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("expected log level debug, got %q", cfg.LogLevel)
	}
	if cfg.DockerHost != "unix:///tmp/docker.sock" {
		t.Fatalf("expected docker host override, got %q", cfg.DockerHost)
	}
}

func TestValidateTLSMismatch(t *testing.T) {
	cfg := Config{
		ListenAddr:  "127.0.0.1:1111",
		TLSCertPath: "/tmp/cert",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected error when cert provided without key")
	}
}

func TestValidatePublicNoAuth(t *testing.T) {
	cfg := Config{
		ListenAddr: "0.0.0.0:8080",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatalf("expected error when binding public without auth or TLS")
	}
}

func TestValidateOK(t *testing.T) {
	cfg := Config{
		ListenAddr: "127.0.0.1:8080",
		LogLevel:   "info",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected config to validate, got %v", err)
	}
}
