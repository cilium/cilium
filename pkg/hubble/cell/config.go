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
	"github.com/cilium/cilium/pkg/time"
)

type config struct {
	// EnableHubble specifies whether to enable the hubble server.
	EnableHubble bool `mapstructure:"enable-hubble"`

	// EventBufferCapacity specifies the capacity of Hubble events buffer.
	EventBufferCapacity int `mapstructure:"hubble-event-buffer-capacity"`
	// EventQueueSize specifies the buffer size of the channel to receive
	// monitor events.
	EventQueueSize int `mapstructure:"hubble-event-queue-size"`
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

	// EnableRecorderAPI specifies if the Hubble Recorder API should be served.
	EnableRecorderAPI bool `mapstructure:"enable-hubble-recorder-api"`
	// RecorderStoragePath specifies the directory in which pcap files created
	// via the Hubble Recorder API are stored.
	RecorderStoragePath string `mapstructure:"hubble-recorder-storage-path"`
	// RecorderSinkQueueSize is the queue size for each recorder sink.
	RecorderSinkQueueSize int `mapstructure:"hubble-recorder-sink-queue-size"`

	// EnableK8sDropEvents controls whether Hubble should create v1.Events for
	// packet drops related to pods.
	EnableK8sDropEvents bool `mapstructure:"hubble-drop-events"`
	// K8sDropEventsInterval controls the minimum time between emitting events
	// with the same source and destination IP.
	K8sDropEventsInterval time.Duration `mapstructure:"hubble-drop-events-interval"`
	// K8sDropEventsReasons controls which drop reasons to emit events for.
	K8sDropEventsReasons []string `mapstructure:"hubble-drop-events-reasons"`
}

var defaultConfig = config{
	EnableHubble: false,
	// Hubble internals (parser, ringbuffer) configuration
	EventBufferCapacity: observeroption.Default.MaxFlows.AsInt(),
	EventQueueSize:      0, // see getDefaultMonitorQueueSize()
	MonitorEvents:       []string{},
	// Hubble local server configuration
	SocketPath: hubbleDefaults.SocketPath,
	// Hubble TCP server configuration
	ListenAddress:          "",
	PreferIpv6:             false,
	DisableServerTLS:       false,
	ServerTLSCertFile:      "",
	ServerTLSKeyFile:       "",
	ServerTLSClientCAFiles: []string{},
	// Hubble recorder configuration
	EnableRecorderAPI:     true,
	RecorderStoragePath:   hubbleDefaults.RecorderStoragePath,
	RecorderSinkQueueSize: 1024,
	// Hubble k8s v1.Events integration configuration.
	EnableK8sDropEvents:   false,
	K8sDropEventsInterval: 2 * time.Minute,
	K8sDropEventsReasons:  []string{"auth_required", "policy_denied"},
}

func (def config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-hubble", def.EnableHubble, "Enable hubble server")
	// Hubble internals (parser, ringbuffer) configuration
	flags.Int("hubble-event-buffer-capacity", def.EventBufferCapacity, "Capacity of Hubble events buffer. The provided value must be one less than an integer power of two and no larger than 65535 (ie: 1, 3, ..., 2047, 4095, ..., 65535)")
	flags.Int("hubble-event-queue-size", def.EventQueueSize, "Buffer size of the channel to receive monitor events.")
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
	// Hubble recorder configuration
	flags.Bool("enable-hubble-recorder-api", def.EnableRecorderAPI, "Enable the Hubble recorder API")
	flags.MarkDeprecated("enable-hubble-recorder-api", "The feature will be removed in v1.19")
	flags.String("hubble-recorder-storage-path", def.RecorderStoragePath, "Directory in which pcap files created via the Hubble Recorder API are stored")
	flags.MarkDeprecated("hubble-recorder-storage-path", "The feature will be removed in v1.19")
	flags.Int("hubble-recorder-sink-queue-size", def.RecorderSinkQueueSize, "Queue size of each Hubble recorder sink")
	flags.MarkDeprecated("hubble-recorder-sink-queue-size", "The feature will be removed in v1.19")
	// Hubble k8s v1.Events integration configuration.
	flags.Bool("hubble-drop-events", def.EnableK8sDropEvents, "Emit packet drop Events related to pods (alpha)")
	flags.Duration("hubble-drop-events-interval", def.K8sDropEventsInterval, "Minimum time between emitting same events")
	flags.StringSlice("hubble-drop-events-reasons", def.K8sDropEventsReasons, "Drop reasons to emit events for")
}

func (cfg *config) normalize() {
	// Dynamically set the event queue size.
	if cfg.EventQueueSize == 0 {
		cfg.EventQueueSize = getDefaultMonitorQueueSize(runtime.NumCPU())
	}
	// Before moving the --hubble-drop-events-reasons flag to Config, it was
	// registered as flags.String() and parsed through viper.GetStringSlice()
	// in Cilium's DaemonConfig. In that case, viper is handling the split of
	// the single string value into slice and it uses white spaces as
	// separators. See also https://github.com/cilium/cilium/pull/33699 for
	// more context.
	//
	// Since it moved to Config, the --hubble-drop-events-reasons flag is
	// registered as flags.StringSlice() allowing multiple flag invocations,
	// and splitting values using comma as separator (see
	// https://pkg.go.dev/github.com/spf13/pflag#StringSlice). Since the
	// reasons themselves have no commas nor white spaces, starting to split on
	// commas should not introduce issues but we still need to handle white
	// spaces splitting to maintain backward compatibility.
	if len(cfg.K8sDropEventsReasons) == 1 {
		cfg.K8sDropEventsReasons = strings.Fields(cfg.K8sDropEventsReasons[0])
	}
}

func getDefaultMonitorQueueSize(numCPU int) int {
	monitorQueueSize := min(numCPU*ciliumDefaults.MonitorQueueSizePerCPU, ciliumDefaults.MonitorQueueSizePerCPUMaximum)
	return monitorQueueSize
}
