// Copyright 2016-2017 Authors of Cilium
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

package defaults

import (
	"time"
)

const (
	// IPv6ClusterAllocCIDR is the default value for option.IPv6ClusterAllocCIDR
	IPv6ClusterAllocCIDR = IPv6ClusterAllocCIDRBase + "/64"

	// IPv6ClusterAllocCIDRBase is the default base for IPv6ClusterAllocCIDR
	IPv6ClusterAllocCIDRBase = "f00d::"

	// RuntimePath is the default path to the runtime directory
	RuntimePath = "/var/run/cilium"

	// RuntimePathRights are the default access rights of the RuntimePath directory
	RuntimePathRights = 0775

	// StateDirRights are the default access rights of the state directory
	StateDirRights = 0770

	//StateDir is the default path for the state directory relative to RuntimePath
	StateDir = "state"

	// BpfDir is the default path for template files relative to LibDir
	BpfDir = "bpf"

	// LibraryPath is the default path to the cilium libraries directory
	LibraryPath = "/var/lib/cilium"

	// SockPath is the path to the UNIX domain socket exposing the API to clients locally
	SockPath = RuntimePath + "/cilium.sock"

	// SockPathEnv is the environment variable to overwrite SockPath
	SockPathEnv = "CILIUM_SOCK"

	// MonitorSockPath1_0 is the path to the UNIX domain socket used to
	// distribute BPF and agent events to listeners.
	// This is the 1.0 protocol version.
	MonitorSockPath1_0 = RuntimePath + "/monitor.sock"

	// MonitorSockPath1_2 is the path to the UNIX domain socket used to
	// distribute BPF and agent events to listeners.
	// This is the 1.2 protocol version.
	MonitorSockPath1_2 = RuntimePath + "/monitor1_2.sock"

	// PidFilePath is the path to the pid file for the agent.
	PidFilePath = RuntimePath + "/cilium.pid"

	// EventsPipe is the name of the named pipe for agent <=> monitor events
	EventsPipe = "events.sock"

	// EnableHostIPRestore controls whether the host IP should be restored
	// from previous state automatically
	EnableHostIPRestore = true

	// DefaultMapRoot is the default path where BPFFS should be mounted
	DefaultMapRoot = "/sys/fs/bpf"

	// DefaultCgroupRoot is the default path where cilium cgroup2 should be mounted
	DefaultCgroupRoot = "/var/run/cilium/cgroupv2"

	// SockopsEnable controsl whether sockmap should be used
	SockopsEnable = false

	// DefaultMapRootFallback is the path which is used when /sys/fs/bpf has
	// a mount, but with the other filesystem than BPFFS.
	DefaultMapRootFallback = "/run/cilium/bpffs"

	// DefaultMapPrefix is the default prefix for all BPF maps.
	DefaultMapPrefix = "tc/globals"

	// ToFQDNsMinTTL is the default lower bound for TTLs used with ToFQDNs rules.
	ToFQDNsMinTTL = 3600 // 1 hour in seconds

	// IdentityChangeGracePeriod is the grace period that needs to pass
	// before an endpoint that has changed its identity will start using
	// that new identity. During the grace period, the new identity has
	// already been allocated and other nodes in the cluster have a chance
	// to whitelist the new upcoming identity of the endpoint.
	IdentityChangeGracePeriod = 25 * time.Second

	// ExecTimeout is a timeout for executing commands.
	ExecTimeout = 300 * time.Second

	// StatusCollectorInterval is the interval between a probe invocations
	StatusCollectorInterval = 5 * time.Second

	// StatusCollectorWarningThreshold is the duration after which a probe
	// is declared as stale
	StatusCollectorWarningThreshold = 15 * time.Second

	// StatusCollectorFailureThreshold is the duration after which a probe
	// is considered failed
	StatusCollectorFailureThreshold = 1 * time.Minute

	// EnableIPv4 is the default value for IPv4 enablement
	EnableIPv4 = true

	// EnableIPv6 is the default value for IPv6 enablement
	EnableIPv6 = true
)
