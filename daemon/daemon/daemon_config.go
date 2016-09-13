//
// Copyright 2016 Authors of Cilium
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
//
package daemon

import (
	"net"
	"sync"

	"github.com/cilium/cilium/bpf/lxcmap"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/common/types"

	consulAPI "github.com/hashicorp/consul/api"
)

const (
	OptionPolicyTracing = "PolicyTracing"
)

var (
	OptionSpecPolicyTracing = types.Option{
		Description: "Enable tracing when resolving policy (Debug)",
	}

	DaemonOptionLibrary = types.OptionLibrary{
		types.OptionNAT46:               &types.OptionSpecNAT46,
		types.OptionDropNotify:          &types.OptionSpecDropNotify,
		types.OptionDebug:               &types.OptionSpecDebug,
		types.OptionPolicy:              &types.OptionSpecPolicy,
		types.OptionConntrack:           &types.OptionSpecConntrack,
		types.OptionConntrackAccounting: &types.OptionSpecConntrackAccounting,
		OptionPolicyTracing:             &OptionSpecPolicyTracing,
	}
)

// Config is the configuration used by Daemon.
type Config struct {
	LibDir               string                  // Cilium library directory
	RunDir               string                  // Cilium runtime directory
	LXCMap               *lxcmap.LXCMap          // LXCMap where all LXCs are stored
	NodeAddress          *addressing.NodeAddress // Node IPv6 Address
	NAT46Prefix          *net.IPNet              // NAT46 IPv6 Prefix
	Device               string                  // Receive device
	ConsulConfig         *consulAPI.Config       // Consul configuration
	DockerEndpoint       string                  // Docker endpoint
	IPv4Enabled          bool                    // Gives IPv4 addresses to containers
	K8sEndpoint          string                  // Kubernetes endpoint
	ValidLabelPrefixes   *types.LabelPrefixCfg   // Label prefixes used to filter from all labels
	ValidLabelPrefixesMU sync.RWMutex
	UIServerAddr         string // TCP address for UI server
	UIEnabled            bool
	LBMode               bool   // Set to true on load balancer node
	Tunnel               string // Tunnel mode

	DryMode      bool // Do not create BPF maps, devices, ..
	RestoreState bool // RestoreState restores the state from previous running daemons.

	// Options changeable at runtime
	Opts   *types.BoolOptions
	OptsMU sync.RWMutex
}

func NewConfig() *Config {
	return &Config{
		Opts: types.NewBoolOptions(&DaemonOptionLibrary),
	}
}

func (c *Config) IsUIEnabled() bool {
	return c.UIEnabled
}

func (c *Config) IsK8sEnabled() bool {
	return len(c.K8sEndpoint) != 0
}
