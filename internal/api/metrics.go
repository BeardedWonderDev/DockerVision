package api

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics groups Prometheus collectors used by the API/WS.
type Metrics struct {
	WSActive   prometheus.Gauge
	WSCreated  prometheus.Counter
	WSErrors   prometheus.Counter
	DockerFail *prometheus.CounterVec
	Registry   *prometheus.Registry
}

func defaultMetrics() Metrics {
	reg := prometheus.NewRegistry()
	return newMetricsWithRegistry(reg)
}

func newMetricsWithRegistry(reg *prometheus.Registry) Metrics {
	return Metrics{
		Registry: reg,
		WSActive: promauto.With(reg).NewGauge(prometheus.GaugeOpts{
			Name: "ws_active_streams",
			Help: "Active websocket streams",
		}),
		WSCreated: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "ws_streams_created_total",
			Help: "Total websocket streams created",
		}),
		WSErrors: promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Name: "ws_stream_errors_total",
			Help: "Websocket stream errors",
		}),
		DockerFail: promauto.With(reg).NewCounterVec(prometheus.CounterOpts{
			Name: "docker_calls_failed_total",
			Help: "Count of Docker API failures",
		}, []string{"operation"}),
	}
}
