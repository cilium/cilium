// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"syscall"

	"github.com/cilium/hive/cell"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	sdpNamespace = "standalone_dns_proxy"

	// Error labels for CiliumAgentConnection metric.
	LabelErrorClientCreation   = "client_creation"    // gRPC client creation failed
	LabelErrorOpenPolicyStream = "open_policy_stream" // opening the policy stream failed

	// Error labels for RetrieveDNSRules metric.
	LabelErrorPolicyStreamSend = "policy_stream_send" // sending ACK on the policy stream failed
	LabelErrorPolicyStreamRecv = "policy_stream_recv" // receiving from the policy stream failed

	// Error labels for FQDNMappingSync metric.
	LabelErrorMappingSyncConnection = "mapping_sync_connection" // FQDN mapping sync failed due to connection error
	LabelErrorMappingSyncRequest    = "mapping_sync_request"    // FQDN mapping sync request failed
)

// goCustomCollectorsRX tracks enabled go runtime metrics.
var goCustomCollectorsRX = regexp.MustCompile(`^/sched/latencies:seconds`)

// Metrics contains all metrics for the standalone DNS proxy.
type Metrics struct {
	// CiliumAgentConnection tracks total errors while connecting to cilium-agent.
	CiliumAgentConnection metric.Vec[metric.Counter]

	// FQDNMappingSync tracks errors while syncing FQDN mappings.
	FQDNMappingSync metric.Vec[metric.Counter]

	// RetrieveDNSRules tracks errors while retrieving DNS rules.
	RetrieveDNSRules metric.Vec[metric.Counter]

	// ProxyBootstrapError tracks errors that occurred during proxy bootstrap.
	ProxyBootstrapError metric.Counter
}

// NewMetrics creates the SDP metrics.
func NewMetrics() *Metrics {
	return &Metrics{
		CiliumAgentConnection: metric.NewCounterVec(metric.CounterOpts{
			Namespace: sdpNamespace,
			Name:      "cilium_agent_connection_errors",
			Help:      "Total errors while connecting to cilium-agent",
		}, []string{metrics.LabelError}),
		FQDNMappingSync: metric.NewCounterVec(metric.CounterOpts{
			Namespace: sdpNamespace,
			Name:      "fqdn_mapping_sync_errors",
			Help:      "Total errors while syncing FQDN mappings",
		}, []string{metrics.LabelError}),
		RetrieveDNSRules: metric.NewCounterVec(metric.CounterOpts{
			Namespace: sdpNamespace,
			Name:      "retrieve_dns_rules_errors",
			Help:      "Total errors while retrieving DNS rules",
		}, []string{metrics.LabelError}),
		ProxyBootstrapError: metric.NewCounter(metric.CounterOpts{
			Namespace: sdpNamespace,
			Name:      "proxy_bootstrap_errors",
			Help:      "Number of errors occurred during proxy bootstrap",
		}),
	}
}

type initParams struct {
	cell.In

	Logger   *slog.Logger
	Registry *metrics.Registry

	Metrics []metric.WithMetadata `group:"hive-metrics"`
}

func initializeMetrics(p initParams) {
	p.Registry.MustRegister(collectors.NewGoCollector(
		collectors.WithGoCollectorRuntimeMetrics(
			collectors.GoRuntimeMetricsRule{Matcher: goCustomCollectorsRX},
		),
	))

	p.Registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{
		Namespace: sdpNamespace,
	}))

	for _, m := range p.Metrics {
		p.Registry.MustRegister(m.(prometheus.Collector))
	}

	p.Registry.AddServerRuntimeHooks("sdp-prometheus-server", nil, net.ListenConfig{
		Control: setsockoptReusePort,
	})
}

// setsockoptReusePort sets SO_REUSEPORT on the socket to allow the new SDP pod
// to bind the metrics port while the old pod is still terminating during a
// surge-based rolling update.
func setsockoptReusePort(network, address string, c syscall.RawConn) error {
	var soerr error
	if err := c.Control(func(su uintptr) {
		s := int(su)
		if err := unix.SetsockoptInt(s, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
			soerr = fmt.Errorf("failed to setsockopt(SO_REUSEPORT): %w", err)
		}
	}); err != nil {
		return err
	}
	return soerr
}
