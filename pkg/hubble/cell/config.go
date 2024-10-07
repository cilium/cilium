// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package hubblecell

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/spf13/pflag"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	ciliumDefaults "github.com/cilium/cilium/pkg/defaults"
	hubbleDefaults "github.com/cilium/cilium/pkg/hubble/defaults"
	"github.com/cilium/cilium/pkg/hubble/exporter/exporteroption"
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

	// FlowlogsConfigFilePath specifies the filepath with configuration of
	// hubble flowlogs. e.g. "/etc/cilium/flowlog.yaml".
	FlowlogsConfigFilePath string `mapstructure:"hubble-flowlogs-config-path"`
	// ExportFilePath specifies the filepath to write Hubble events to. e.g.
	// "/var/run/cilium/hubble/events.log".
	ExportFilePath string `mapstructure:"hubble-export-file-path"`
	// ExportFileMaxSizeMB specifies the file size in MB at which to rotate the
	// Hubble export file.
	ExportFileMaxSizeMB int `mapstructure:"hubble-export-file-max-size-mb"`
	// ExportFileMaxBackups specifies the number of rotated files to keep.
	ExportFileMaxBackups int `mapstructure:"hubble-export-file-max-backups"`
	// ExportFileCompress specifies whether rotated files are compressed.
	ExportFileCompress bool `mapstructure:"hubble-export-file-compress"`
	// ExportAllowlist specifies allow list filter use by exporter.
	ExportAllowlist []*flowpb.FlowFilter `mapstructure:"hubble-export-allowlist"`
	// ExportDenylist specifies deny list filter use by exporter.
	ExportDenylist []*flowpb.FlowFilter `mapstructure:"hubble-export-denylist"`
	// ExportFieldmask specifies list of fields to log in exporter.
	ExportFieldmask []string `mapstructure:"hubble-export-fieldmask"`

	// EnableRecorderAPI specifies if the Hubble Recorder API should be served.
	EnableRecorderAPI bool `mapstructure:"enable-hubble-recorder-api"`
	// RecorderStoragePath specifies the directory in which pcap files created
	// via the Hubble Recorder API are stored.
	RecorderStoragePath string `mapstructure:"hubble-recorder-storage-path"`
	// RecorderSinkQueueSize is the queue size for each recorder sink.
	RecorderSinkQueueSize int `mapstructure:"hubble-recorder-sink-queue-size"`

	// EnableRedact controls if sensitive information will be redacted from L7
	// flows.
	EnableRedact bool `mapstructure:"hubble-redact-enabled"`
	// RedactHttpURLQuery controls if the URL query will be redacted from flows.
	RedactHttpURLQuery bool `mapstructure:"hubble-redact-http-urlquery"`
	// RedactHttpUserInfo controls if the user info will be redacted from flows.
	RedactHttpUserInfo bool `mapstructure:"hubble-redact-http-userinfo"`
	// RedactHttpHeadersAllow controls which http headers will not be redacted
	// from flows.
	RedactHttpHeadersAllow []string `mapstructure:"hubble-redact-http-headers-allow"`
	// RedactHttpHeadersDeny controls which http headers will be redacted from
	// flows.
	RedactHttpHeadersDeny []string `mapstructure:"hubble-redact-http-headers-deny"`
	// RedactKafkaAPIKey controls if Kafka API key will be redacted from flows.
	RedactKafkaAPIKey bool `mapstructure:"hubble-redact-kafka-apikey"`

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
	// Hubble log export configuration
	FlowlogsConfigFilePath: "",
	ExportFilePath:         exporteroption.Default.Path,
	ExportFileMaxSizeMB:    exporteroption.Default.MaxSizeMB,
	ExportFileMaxBackups:   exporteroption.Default.MaxBackups,
	ExportFileCompress:     exporteroption.Default.Compress,
	ExportAllowlist:        []*flowpb.FlowFilter{},
	ExportDenylist:         []*flowpb.FlowFilter{},
	ExportFieldmask:        []string{},
	// Hubble recorder configuration
	EnableRecorderAPI:     true,
	RecorderStoragePath:   hubbleDefaults.RecorderStoragePath,
	RecorderSinkQueueSize: 1024,
	// Hubble field redaction configuration
	EnableRedact:           false,
	RedactHttpURLQuery:     false,
	RedactHttpUserInfo:     true,
	RedactHttpHeadersAllow: []string{},
	RedactHttpHeadersDeny:  []string{},
	RedactKafkaAPIKey:      false,
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
	// Hubble log export configuration
	flags.String("hubble-flowlogs-config-path", def.FlowlogsConfigFilePath, "Filepath with configuration of hubble flowlogs")
	flags.String("hubble-export-file-path", def.ExportFilePath, "Filepath to write Hubble events to. By specifying `stdout` the flows are logged instead of written to a rotated file.")
	flags.Int("hubble-export-file-max-size-mb", def.ExportFileMaxSizeMB, "Size in MB at which to rotate Hubble export file.")
	flags.Int("hubble-export-file-max-backups", def.ExportFileMaxBackups, "Number of rotated Hubble export files to keep.")
	flags.Bool("hubble-export-file-compress", def.ExportFileCompress, "Compress rotated Hubble export files.")
	flags.StringSlice("hubble-export-allowlist", []string{}, "Specify allowlist as JSON encoded FlowFilters to Hubble exporter.")
	flags.StringSlice("hubble-export-denylist", []string{}, "Specify denylist as JSON encoded FlowFilters to Hubble exporter.")
	flags.StringSlice("hubble-export-fieldmask", def.ExportFieldmask, "Specify list of fields to use for field mask in Hubble exporter.")
	// Hubble recorder configuration
	flags.Bool("enable-hubble-recorder-api", def.EnableRecorderAPI, "Enable the Hubble recorder API")
	flags.String("hubble-recorder-storage-path", def.RecorderStoragePath, "Directory in which pcap files created via the Hubble Recorder API are stored")
	flags.Int("hubble-recorder-sink-queue-size", def.RecorderSinkQueueSize, "Queue size of each Hubble recorder sink")
	// Hubble field redaction configuration
	flags.Bool("hubble-redact-enabled", def.EnableRedact, "Hubble redact sensitive information from flows")
	flags.Bool("hubble-redact-http-urlquery", def.RedactHttpURLQuery, "Hubble redact http URL query from flows")
	flags.Bool("hubble-redact-http-userinfo", def.RedactHttpUserInfo, "Hubble redact http user info from flows")
	flags.StringSlice("hubble-redact-http-headers-allow", def.RedactHttpHeadersAllow, "HTTP headers to keep visible in flows")
	flags.StringSlice("hubble-redact-http-headers-deny", def.RedactHttpHeadersDeny, "HTTP headers to redact from flows")
	flags.Bool("hubble-redact-kafka-apikey", def.RedactKafkaAPIKey, "Hubble redact Kafka API key from flows")
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

func (cfg config) validate() error {
	if fm := cfg.ExportFieldmask; len(fm) > 0 {
		_, err := fieldmaskpb.New(&flowpb.Flow{}, fm...)
		if err != nil {
			return fmt.Errorf("hubble-export-fieldmask contains invalid fieldmask '%v': %w", fm, err)
		}
	}
	if len(cfg.RedactHttpHeadersAllow) > 0 && len(cfg.RedactHttpHeadersDeny) > 0 {
		return fmt.Errorf("Only one of --hubble-redact-http-headers-allow and --hubble-redact-http-headers-deny can be specified, not both")
	}
	return nil
}

func getDefaultMonitorQueueSize(numCPU int) int {
	monitorQueueSize := numCPU * ciliumDefaults.MonitorQueueSizePerCPU
	if monitorQueueSize > ciliumDefaults.MonitorQueueSizePerCPUMaximum {
		monitorQueueSize = ciliumDefaults.MonitorQueueSizePerCPUMaximum
	}
	return monitorQueueSize
}
