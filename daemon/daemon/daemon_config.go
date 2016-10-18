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
	"fmt"
	"net"
	"sync"

	"github.com/cilium/cilium/bpf/lxcmap"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/common/types"

	etcdAPI "github.com/coreos/etcd/clientv3"
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
		OptionPolicyTracing: &OptionSpecPolicyTracing,
	}
	kvBackend = ""
)

func init() {
	for k, v := range types.EndpointMutableOptionLibrary {
		DaemonOptionLibrary[k] = v
	}
}

// Config is the configuration used by Daemon.
type Config struct {
	LibDir               string                  // Cilium library directory
	RunDir               string                  // Cilium runtime directory
	LXCMap               *lxcmap.LXCMap          // LXCMap where all LXCs are stored
	NodeAddress          *addressing.NodeAddress // Node IPv6 Address
	NAT46Prefix          *net.IPNet              // NAT46 IPv6 Prefix
	Device               string                  // Receive device
	ConsulConfig         *consulAPI.Config       // Consul configuration
	EtcdConfig           *etcdAPI.Config         // Etcd Configuration
	EtcdCfgPath          string                  // Etcd Configuration path
	DockerEndpoint       string                  // Docker endpoint
	IPv4Enabled          bool                    // Gives IPv4 addresses to containers
	K8sEndpoint          string                  // Kubernetes endpoint
	K8sCfgPath           string                  // Kubeconfig path
	ValidLabelPrefixes   *types.LabelPrefixCfg   // Label prefixes used to filter from all labels
	ValidLabelPrefixesMU sync.RWMutex
	UIServerAddr         string // TCP address for UI server
	UIEnabled            bool
	LBMode               bool   // Set to true on load balancer node
	Tunnel               string // Tunnel mode

	DryMode      bool // Do not create BPF maps, devices, ..
	RestoreState bool // RestoreState restores the state from previous running daemons.
	KeepConfig   bool // Keep configuration of existing endpoints when starting up.

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
	return c.K8sEndpoint != "" || c.K8sCfgPath != ""
}

// SetKVBackend is only used for test purposes
func (c *Config) SetKVBackend() error {
	switch kvBackend {
	case "consul":
		consulConfig := consulAPI.DefaultConfig()
		consulConfig.Address = "127.0.0.1:8501"
		c.ConsulConfig = consulConfig
		return nil
	case "etcd":
		c.EtcdConfig = &etcdAPI.Config{}
		c.EtcdConfig.Endpoints = []string{"http://127.0.0.1:4002"}
		return nil
	default:
		return fmt.Errorf("invalid backend %s", kvBackend)
	}
}
