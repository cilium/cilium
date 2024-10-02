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
