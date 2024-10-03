// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package hubblecell

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/spf13/pflag"

	ciliumDefaults "github.com/cilium/cilium/pkg/defaults"
	hubbleDefaults "github.com/cilium/cilium/pkg/hubble/defaults"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
)

type config struct {
	// EnableHubble specifies whether to enable the hubble server.
	EnableHubble bool `mapstructure:"enable-hubble"`

	// EventBufferCapacity specifies the capacity of Hubble events buffer.
	EventBufferCapacity int `mapstructure:"hubble-event-buffer-capacity"`
	// EventQueueSize specifies the buffer size of the channel to receive
	// monitor events.
	EventQueueSize int `mapstructure:"hubble-event-queue-size"`
	// SkipUnknownCGroupIDs specifies if events with unknown cgroup ids should
	// be skipped.
	SkipUnknownCGroupIDs bool `mapstructure:"hubble-skip-unknown-cgroup-ids"`
	// MonitorEvents specifies Cilium monitor events for Hubble to observe. By
	// default, Hubble observes all monitor events.
	MonitorEvents []string `mapstructure:"hubble-monitor-events"`

	// SocketPath specifies the UNIX domain socket for Hubble server to listen
	// to.
	SocketPath string `mapstructure:"hubble-socket-path"`

	// ListenAddress specifies address for Hubble to listen to.
	ListenAddress string `mapstructure:"hubble-listen-address"`
	// PreferIpv6 controls whether IPv6 or IPv4 addresses should be preferred
	// for communication to agents, if both are available.
	PreferIpv6 bool `mapstructure:"hubble-prefer-ipv6"`
	// DisableServerTLS allows the Hubble server to run on the given listen
	// address without TLS.
	DisableServerTLS bool `mapstructure:"hubble-disable-tls"`
	// ServerTLSCertFile specifies the path to the public key file for the
	// Hubble server. The file must contain PEM encoded data.
	ServerTLSCertFile string `mapstructure:"hubble-tls-cert-file"`
	// ServerTLSKeyFile specifies the path to the private key file for the
	// Hubble server. The file must contain PEM encoded data.
	ServerTLSKeyFile string `mapstructure:"hubble-tls-key-file"`
	// ServerTLSClientCAFiles specifies the path to one or more client CA
	// certificates to use for TLS with mutual authentication (mTLS). The files
	// must contain PEM encoded data.
	ServerTLSClientCAFiles []string `mapstructure:"hubble-tls-client-ca-files"`

	// Metrics specifies enabled metrics and their configuration options.
	Metrics []string `mapstructure:"hubble-metrics"`
	// EnableOpenMetrics enables exporting hubble metrics in OpenMetrics
	// format.
	EnableOpenMetrics bool `mapstructure:"enable-hubble-open-metrics"`

	// MetricsServer specifies the addresses to serve Hubble metrics on.
	MetricsServer string `mapstructure:"hubble-metrics-server"`
	// EnableMetricsServerTLS run the Hubble metrics server on the given listen
	// address with TLS.
	EnableMetricsServerTLS bool `mapstructure:"hubble-metrics-server-enable-tls"`
	// MetricsServerTLSCertFile specifies the path to the public key file for
	// the Hubble metrics server. The file must contain PEM encoded data.
	MetricsServerTLSCertFile string `mapstructure:"hubble-metrics-server-tls-cert-file"`
	// MetricsServerTLSKeyFile specifies the path to the private key file for
	// the Hubble metrics server. The file must contain PEM encoded data.
	MetricsServerTLSKeyFile string `mapstructure:"hubble-metrics-server-tls-key-file"`
	// MetricsServerTLSClientCAFiles specifies the path to one or more client
	// CA certificates to use for TLS with mutual authentication (mTLS) on the
	// Hubble metrics server. The files must contain PEM encoded data.
	MetricsServerTLSClientCAFiles []string `mapstructure:"hubble-metrics-server-tls-client-ca-files"`
}

var defaultConfig = config{
	EnableHubble: true,
	// Hubble internals (parser, ringbuffer) configuration
	EventBufferCapacity:  observeroption.Default.MaxFlows.AsInt(),
	EventQueueSize:       0, // see getDefaultMonitorQueueSize()
	SkipUnknownCGroupIDs: true,
	MonitorEvents:        []string{},
	// Hubble local server configuration
	SocketPath: hubbleDefaults.SocketPath,
	// Hubble TCP server configuration
	ListenAddress:          "",
	PreferIpv6:             false,
	DisableServerTLS:       false,
	ServerTLSCertFile:      "",
	ServerTLSKeyFile:       "",
	ServerTLSClientCAFiles: []string{},
	// Hubble metrics configuration
	Metrics:           []string{},
	EnableOpenMetrics: false,
	// Hubble metrics server configuration
	MetricsServer:                 "",
	EnableMetricsServerTLS:        false,
	MetricsServerTLSCertFile:      "",
	MetricsServerTLSKeyFile:       "",
	MetricsServerTLSClientCAFiles: []string{},
}

func (def config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-hubble", def.EnableHubble, "Enable hubble server")
	// Hubble internals (parser, ringbuffer) configuration
	flags.Int("hubble-event-buffer-capacity", def.EventBufferCapacity, "Capacity of Hubble events buffer. The provided value must be one less than an integer power of two and no larger than 65535 (ie: 1, 3, ..., 2047, 4095, ..., 65535)")
	flags.Int("hubble-event-queue-size", def.EventQueueSize, "Buffer size of the channel to receive monitor events.")
	flags.Bool("hubble-skip-unknown-cgroup-ids", def.SkipUnknownCGroupIDs, "Skip Hubble events with unknown cgroup ids")
	flags.StringSlice("hubble-monitor-events", def.MonitorEvents,
		fmt.Sprintf(
			"Cilium monitor events for Hubble to observe: [%s]. By default, Hubble observes all monitor events.",
			strings.Join(monitorAPI.AllMessageTypeNames(), " "),
		),
	)
	// Hubble local server configuration
	flags.String("hubble-socket-path", def.SocketPath, "Set hubble's socket path to listen for connections")
	// Hubble TCP server configuration
	flags.String("hubble-listen-address", def.ListenAddress, `An additional address for Hubble server to listen to, e.g. ":4244"`)
	flags.Bool("hubble-prefer-ipv6", def.PreferIpv6, "Prefer IPv6 addresses for announcing nodes when both address types are available.")
	flags.Bool("hubble-disable-tls", def.DisableServerTLS, "Allow Hubble server to run on the given listen address without TLS.")
	flags.String("hubble-tls-cert-file", def.ServerTLSCertFile, "Path to the public key file for the Hubble server. The file must contain PEM encoded data.")
	flags.String("hubble-tls-key-file", def.ServerTLSKeyFile, "Path to the private key file for the Hubble server. The file must contain PEM encoded data.")
	flags.StringSlice("hubble-tls-client-ca-files", def.ServerTLSClientCAFiles, "Paths to one or more public key files of client CA certificates to use for TLS with mutual authentication (mTLS). The files must contain PEM encoded data. When provided, this option effectively enables mTLS.")
	flags.StringSlice("hubble-metrics", def.Metrics, "List of Hubble metrics to enable.")
	flags.Bool("enable-hubble-open-metrics", def.EnableOpenMetrics, "Enable exporting hubble metrics in OpenMetrics format")
	// Hubble metrics server configuration
	flags.String("hubble-metrics-server", def.MetricsServer, "Address to serve Hubble metrics on.")
	flags.Bool("hubble-metrics-server-enable-tls", def.EnableMetricsServerTLS, "Run the Hubble metrics server on the given listen address with TLS.")
	flags.String("hubble-metrics-server-tls-cert-file", def.MetricsServerTLSCertFile, "Path to the public key file for the Hubble metrics server. The file must contain PEM encoded data.")
	flags.String("hubble-metrics-server-tls-key-file", def.MetricsServerTLSKeyFile, "Path to the private key file for the Hubble metrics server. The file must contain PEM encoded data.")
	flags.StringSlice("hubble-metrics-server-tls-client-ca-files", def.MetricsServerTLSClientCAFiles, "Paths to one or more public key files of client CA certificates to use for TLS with mutual authentication (mTLS). The files must contain PEM encoded data. When provided, this option effectively enables mTLS.")
}

func (cfg *config) normalize() {
	// Dynamically set the event queue size.
	if cfg.EventQueueSize == 0 {
		cfg.EventQueueSize = getDefaultMonitorQueueSize(runtime.NumCPU())
	}
}

func (cfg config) validate() error {
	return nil
}

func getDefaultMonitorQueueSize(numCPU int) int {
	monitorQueueSize := numCPU * ciliumDefaults.MonitorQueueSizePerCPU
	if monitorQueueSize > ciliumDefaults.MonitorQueueSizePerCPUMaximum {
		monitorQueueSize = ciliumDefaults.MonitorQueueSizePerCPUMaximum
	}
	return monitorQueueSize
}
