// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package hubblecell

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	ciliumDefaults "github.com/cilium/cilium/pkg/defaults"
	hubbleDefaults "github.com/cilium/cilium/pkg/hubble/defaults"
	"github.com/cilium/cilium/pkg/hubble/observer/observeroption"
	peercell "github.com/cilium/cilium/pkg/hubble/peer/cell"
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
	// LostEventSendInterval specifies the interval at which lost events are
	// sent from the Observer server, if any.
	LostEventSendInterval time.Duration `mapstructure:"hubble-lost-event-send-interval"`

	// SocketPath specifies the UNIX domain socket for Hubble server to listen
	// to.
	SocketPath string `mapstructure:"hubble-socket-path"`

	// ListenAddress specifies address for Hubble to listen to.
	ListenAddress string `mapstructure:"hubble-listen-address"`
	// PreferIpv6 controls whether IPv6 or IPv4 addresses should be preferred
	// for communication to agents, if both are available.
	PreferIpv6 bool `mapstructure:"hubble-prefer-ipv6"`
}

var defaultConfig = config{
	EnableHubble: false,
	// Hubble internals (parser, ringbuffer) configuration
	EventBufferCapacity:   observeroption.Default.MaxFlows.AsInt(),
	EventQueueSize:        0, // see getDefaultMonitorQueueSize()
	MonitorEvents:         []string{},
	LostEventSendInterval: hubbleDefaults.LostEventSendInterval,
	// Hubble local server configuration
	SocketPath: hubbleDefaults.SocketPath,
	// Hubble TCP server configuration
	ListenAddress: "",
	PreferIpv6:    false,
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
	flags.Duration("hubble-lost-event-send-interval", def.LostEventSendInterval, "Interval at which lost events are sent from the Observer server, if any.")
	// Hubble local server configuration
	flags.String("hubble-socket-path", def.SocketPath, "Set hubble's socket path to listen for connections")
	// Hubble TCP server configuration
	flags.String("hubble-listen-address", def.ListenAddress, `An additional address for Hubble server to listen to, e.g. ":4244"`)
	flags.Bool("hubble-prefer-ipv6", def.PreferIpv6, "Prefer IPv6 addresses for announcing nodes when both address types are available.")
}

func (cfg *config) normalize() {
	// Dynamically set the event queue size.
	if cfg.EventQueueSize == 0 {
		cfg.EventQueueSize = getDefaultMonitorQueueSize(runtime.NumCPU())
	}
}

func getDefaultMonitorQueueSize(numCPU int) int {
	monitorQueueSize := min(numCPU*ciliumDefaults.MonitorQueueSizePerCPU, ciliumDefaults.MonitorQueueSizePerCPUMaximum)
	return monitorQueueSize
}

// ConfigProviders provides configuration objects for Hubble components.
// This group creates and provides configuration structs by combining
// different configuration sources (hubble config, TLS config, etc.).
var ConfigProviders = cell.Group(
	// Provide HubbleConfig struct for peer service and other components
	cell.ProvidePrivate(func(cfg config, tlsCfg certloaderConfig) *peercell.HubbleConfig {
		return &peercell.HubbleConfig{
			ListenAddress:   cfg.ListenAddress,
			PreferIpv6:      cfg.PreferIpv6,
			EnableServerTLS: !tlsCfg.DisableServerTLS,
		}
	}),
)
