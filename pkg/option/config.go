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

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/lock"
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

	// IPv6ClusterAllocCIDRName is the name of the IPv6ClusterAllocCIDR option
	IPv6ClusterAllocCIDRName = "ipv6-cluster-alloc-cidr"

	// K8sRequireIPv4PodCIDRName is the name of the K8sRequireIPv4PodCIDR option
	K8sRequireIPv4PodCIDRName = "k8s-require-ipv4-pod-cidr"

	// K8sRequireIPv6PodCIDRName is the name of the K8sRequireIPv6PodCIDR option
	K8sRequireIPv6PodCIDRName = "k8s-require-ipv6-pod-cidr"

	// AutoIPv6NodeRoutesName is the name of the AutoIPv6NodeRoutes option
	AutoIPv6NodeRoutesName = "auto-ipv6-node-routes"
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
	Workloads       []string   // List of Workloads set by the user to used by cilium.

	Tunnel string // Tunnel mode

	DryMode bool // Do not create BPF maps, devices, ..

	// RestoreState enables restoring the state from previous running daemons.
	RestoreState bool

	// EnableHostIPRestore enables restoring the host IPs based on state
	// left behind by previous Cilium runs.
	EnableHostIPRestore bool

	KeepConfig    bool // Keep configuration of existing endpoints when starting up.
	KeepTemplates bool // Do not overwrite the template files

	// AllowLocalhost defines when to allows the local stack to local endpoints
	// values: { auto | always | policy }
	AllowLocalhost string

	// HostAllowsWorld applies the same policy to world-sourced traffic as
	// host-sourced traffic, to provide compatibility with Cilium 1.0.
	HostAllowsWorld bool

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

	// IPv6ClusterAllocCIDR is the base CIDR used to allocate IPv6 node
	// CIDRs if allocation is not performed by an orchestration system
	IPv6ClusterAllocCIDR string

	// IPv6ClusterAllocCIDRBase is derived from IPv6ClusterAllocCIDR and
	// contains the CIDR without the mask, e.g. "fdfd::1/64" -> "fdfd::"
	//
	// This variable should never be written to, it is initialized via
	// daemonConfig.Validate()
	IPv6ClusterAllocCIDRBase string

	// K8sRequireIPv4PodCIDR requires the k8s node resource to specify the
	// IPv4 PodCIDR. Cilium will block bootstrapping until the information
	// is available.
	K8sRequireIPv4PodCIDR bool

	// K8sRequireIPv6PodCIDR requires the k8s node resource to specify the
	// IPv6 PodCIDR. Cilium will block bootstrapping until the information
	// is available.
	K8sRequireIPv6PodCIDR bool

	// AutoIPv6NodeRoutes enables automatic route injection of IPv6
	// endpoint routes based on node discovery information
	AutoIPv6NodeRoutes bool
}

var (
	Config = &daemonConfig{
		Opts:                     NewBoolOptions(&daemonLibrary),
		Monitor:                  &models.MonitorStatus{Cpus: int64(runtime.NumCPU()), Npages: 64, Pagesize: int64(os.Getpagesize()), Lost: 0, Unknown: 0},
		IPv6ClusterAllocCIDR:     defaults.IPv6ClusterAllocCIDR,
		IPv6ClusterAllocCIDRBase: defaults.IPv6ClusterAllocCIDRBase,
		EnableHostIPRestore:      defaults.EnableHostIPRestore,
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

func (c *daemonConfig) validateIPv6ClusterAllocCIDR() error {
	ip, cidr, err := net.ParseCIDR(c.IPv6ClusterAllocCIDR)
	if err != nil {
		return err
	}

	if cidr == nil {
		return fmt.Errorf("ParseCIDR returned nil")
	}

	if ones, _ := cidr.Mask.Size(); ones != 64 {
		return fmt.Errorf("CIDR length must be /64")
	}

	c.IPv6ClusterAllocCIDRBase = ip.Mask(cidr.Mask).String()

	return nil
}

// Validate validates the daemon configuration
func (c *daemonConfig) Validate() error {
	if err := c.validateIPv6ClusterAllocCIDR(); err != nil {
		return fmt.Errorf("unable to parse CIDR value '%s' of option --%s: %s",
			c.IPv6ClusterAllocCIDR, IPv6ClusterAllocCIDRName, err)
	}

	return nil
}
