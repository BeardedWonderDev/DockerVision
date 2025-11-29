package config

import (
	"errors"
	"net"
	"os"
	"strings"
)

const (
	defaultListen = "127.0.0.1:8364"
	defaultLevel  = "info"
)

// Config holds runtime configuration for the agent.
// Input is treated as untrusted; validate before use.
type Config struct {
	ListenAddr  string
	AuthToken   string
	TLSCertPath string
	TLSKeyPath  string
	DockerHost  string
	LogLevel    string
}

// FromEnv builds a Config using environment variables and defaults.
// Flag parsing can override these values.
func FromEnv() Config {
	return Config{
		ListenAddr:  getenvOrDefault("DV_LISTEN_ADDR", defaultListen),
		AuthToken:   os.Getenv("DV_AUTH_TOKEN"),
		TLSCertPath: os.Getenv("DV_TLS_CERT"),
		TLSKeyPath:  os.Getenv("DV_TLS_KEY"),
		DockerHost:  os.Getenv("DOCKER_HOST"),
		LogLevel:    strings.ToLower(getenvOrDefault("DV_LOG_LEVEL", defaultLevel)),
	}
}

// Validate checks for basic configuration errors and unsafe defaults.
func (c Config) Validate() error {
	if c.ListenAddr == "" {
		return errors.New("listen address must not be empty")
	}
	if c.TLSCertPath == "" && c.TLSKeyPath != "" {
		return errors.New("tls key provided without cert path")
	}
	if c.TLSKeyPath == "" && c.TLSCertPath != "" {
		return errors.New("tls cert provided without key path")
	}
	if !isLoopback(c.ListenAddr) && c.AuthToken == "" && c.TLSCertPath == "" {
		return errors.New("refusing to bind publicly without auth or TLS")
	}
	return nil
}

func getenvOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
