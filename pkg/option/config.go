// Copyright 2016-2018 Authors of Cilium
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

package option

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/lock"

	"github.com/spf13/viper"
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

// CLI flags
const (
	AutoIPv6NodeRoutes    = "auto-ipv6-node-routes" // obsoleted (GH-4082)
	AutoRouting           = "auto-routing"
	AnnounceAutoRouting   = "announce-auto-routing"
	K8sUseNodeAnnotations = "k8s-use-node-annotations"
)

// daemonConfig is the configuration used by Daemon.
type daemonConfig struct {
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

	// StateDir is the directory where runtime state of endpoints is stored
	StateDir string

	// Options changeable at runtime
	Opts *BoolOptions

	// Mutex for serializing configuration updates to the daemon.
	ConfigPatchMutex lock.RWMutex

	// Monitor contains the configuration for the node monitor.
	Monitor *models.MonitorStatus

	// AccessLog is the path to the access log of supported L7 requests observed.
	AccessLog string

	// AgentLabels contains additional labels to identify this agent in monitor events.
	AgentLabels []string

	routingConfig *models.RoutingConfiguration
}

func (c *daemonConfig) deriveNodeRoutingConfiguration() (*models.RoutingConfiguration, error) {
	routingConfiguration := models.NewRoutingConfiguration()
	switch strings.ToLower(c.Tunnel) {
	case "vxlan":
		routingConfiguration.Encapsulation = models.RoutingConfigurationEncapsulationVxlan
	case "geneve":
		routingConfiguration.Encapsulation = models.RoutingConfigurationEncapsulationGeneve
	case "disabled", "false":
		routingConfiguration.Encapsulation = models.RoutingConfigurationEncapsulationDisabled
	default:
		return nil, fmt.Errorf("Unknown encapsulation type '%s'. Supported values are vxlan, geneve, and disabled", c.Tunnel)
	}

	if viper.GetBool(AutoRouting) {
		routingConfiguration.DirectRouting.InstallRoutes = true
	}

	if viper.GetBool(AnnounceAutoRouting) {
		routingConfiguration.DirectRouting.Announce = true
	}

	return routingConfiguration, nil
}

var (
	routingConfig *models.RoutingConfiguration
)

// Initialize is called early on in bootstrapping and initializes and validates
// the configuration
func Initialize() error {
	conf, err := Config.deriveNodeRoutingConfiguration()
	if err != nil {
		return err
	}

	routingConfig = conf
	return nil
}

// GetRoutingConfiguration() returns the routing configuration of the node
func GetRoutingConfiguration() *models.RoutingConfiguration {
	return routingConfig
}

var (
	Config = &daemonConfig{
		Opts:    NewBoolOptions(&daemonLibrary),
		Monitor: &models.MonitorStatus{Cpus: int64(runtime.NumCPU()), Npages: 64, Pagesize: int64(os.Getpagesize()), Lost: 0, Unknown: 0},
	}
)

func (c *daemonConfig) IsLBEnabled() bool {
	return c.LBInterface != ""
}

// GetNodeConfigPath returns the full path of the NodeConfigFile.
func (c *daemonConfig) GetNodeConfigPath() string {
	return filepath.Join(c.GetGlobalsDir(), common.NodeConfigFile)
}

// GetGlobalsDir returns the path for the globals directory.
func (c *daemonConfig) GetGlobalsDir() string {
	return filepath.Join(c.StateDir, "globals")
}

// AlwaysAllowLocalhost returns true if the daemon has the option set that
// localhost can always reach local endpoints
func (c *daemonConfig) AlwaysAllowLocalhost() bool {
	switch c.AllowLocalhost {
	case AllowLocalhostAlways:
		return true
	case AllowLocalhostAuto, AllowLocalhostPolicy:
		return false
	default:
		return false
	}
}

// TracingEnabled returns if tracing policy (outlining which rules apply to a
// specific set of labels) is enabled.
func (c *daemonConfig) TracingEnabled() bool {
	return c.Opts.IsEnabled(PolicyTracing)
}
