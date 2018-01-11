// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"net"
	"os"
	"runtime"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
)

const (
	// AllowLocalhostAuto defaults to policy except when running in
	// Kubernetes where it then defaults to "always"
	AllowLocalhostAuto = "auto"

	// AllowLocalhostAlways always allows the local stack to reach local
	// endpoints
	AllowLocalhostAlways = "always"

	// AllowLocalhostPolicy requires a policy rule to allow the local stack
	// to reach particular endpoints or policy enforcement must be
	// disabled.
	AllowLocalhostPolicy = "policy"

	// ModePreFilterNative for loading progs with xdpdrv
	ModePreFilterNative = "native"

	// ModePreFilterGeneric for loading progs with xdpgeneric
	ModePreFilterGeneric = "generic"
)

// AgentConfiguration contains all configuration with agent wide scope
type AgentConfiguration struct {
	BpfDir          string     // BPF template files directory
	LibDir          string     // Cilium library files directory
	RunDir          string     // Cilium runtime directory
	NAT46Prefix     *net.IPNet // NAT46 IPv6 Prefix
	Device          string     // Receive device
	DevicePreFilter string     // XDP device
	ModePreFilter   string     // XDP mode, values: { native | generic }
	HostV4Addr      net.IP     // Host v4 address of the snooping device
	HostV6Addr      net.IP     // Host v6 address of the snooping device
	IPv4Disabled    bool       // Disable IPv4 allocation
	LBInterface     string     // Set with name of the interface to loadbalance packets from

	Tunnel string // Tunnel mode

	DryMode       bool // Do not create BPF maps, devices, ..
	RestoreState  bool // RestoreState restores the state from previous running daemons.
	KeepConfig    bool // Keep configuration of existing endpoints when starting up.
	KeepTemplates bool // Do not overwrite the template files

	// AllowLocalhost defines when to allows the local stack to local endpoints
	// values: { auto | always | policy }
	AllowLocalhost string

	// AlwaysAllowLocalhost is set based on the value of AllowLocalhost and
	// is either set to true when localhost can always reach local
	// endpoints or false when policy should be evaluated
	AlwaysAllowLocalhost bool

	// StateDir is the directory where runtime state of endpoints is stored
	StateDir string

	// Options changeable at runtime
	Opts *option.BoolOptions

	// Mutex for serializing configuration updates to the daemon.
	ConfigPatchMutex lock.RWMutex

	// Monitor contains the configuration for the node monitor.
	Monitor *models.MonitorStatus
}

func newAgentConfiguration() *AgentConfiguration {
	return &AgentConfiguration{
		Opts:    option.NewBoolOptions(&AgentOptions),
		Monitor: &models.MonitorStatus{Cpus: int64(runtime.NumCPU()), Npages: 64, Pagesize: int64(os.Getpagesize()), Lost: 0, Unknown: 0},
	}
}

// IsLBEnabled returns true if the standalone load-balancer has been enabled
func (a *AgentConfiguration) IsLBEnabled() bool {
	return a.LBInterface != ""
}

// ParseAgentOption parses a string as agent option
func ParseAgentOption(opt string) (string, bool, error) {
	return option.ParseOption(opt, &AgentOptions)
}

var (
	agentConfig = newAgentConfiguration()

	// AgentOptions is the list of all available agent options
	AgentOptions = option.OptionLibrary{
		OptionPolicyTracing: &OptionSpecPolicyTracing,
	}

	agentMutableOptionLibrary = option.OptionLibrary{
		OptionConntrackAccounting: &OptionSpecConntrackAccounting,
		OptionConntrackLocal:      &OptionSpecConntrackLocal,
		OptionConntrack:           &OptionSpecConntrack,
		OptionDebug:               &OptionSpecDebug,
		OptionDropNotify:          &OptionSpecDropNotify,
		OptionTraceNotify:         &OptionSpecTraceNotify,
		OptionNAT46:               &OptionSpecNAT46,
	}
)

func init() {
	for k, v := range agentMutableOptionLibrary {
		AgentOptions[k] = v
	}
}

// AgentConfig returns the global agent configuration
func AgentConfig() *AgentConfiguration {
	return agentConfig
}

// List of accessor functions for global mutable options

// PolicyTracingEnabled returns true if policy tracing is enabled
func PolicyTracingEnabled() bool {
	return agentConfig.Opts.IsEnabled(OptionPolicyTracing)
}

// AlwaysAllowLocalhost returns true if the agent has the option set that
// localhost can always reach local endpoints
func AlwaysAllowLocalhost() bool {
	return agentConfig.AlwaysAllowLocalhost
}

// DebugEnabled returns true if debug mode is enabled
func DebugEnabled() bool {
	return agentConfig.Opts.IsEnabled(OptionDebug)
}

// List of accessor functions for non-mutable options, hence no locking is required

// GetStateDir returns the path to the directory where all state is stored
func GetStateDir() string {
	return agentConfig.StateDir
}

// GetBpfDir returns the path to the BPF template directory
func GetBpfDir() string {
	return agentConfig.BpfDir
}

// DryModeEnabled returns true if dry mode is enabled (mock kernel interactions)
func DryModeEnabled() bool {
	return agentConfig.DryMode
}
