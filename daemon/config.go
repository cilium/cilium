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

package main

import (
	"fmt"
	"net"
	"sync"

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/daemon/options"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/option"

	etcdAPI "github.com/coreos/etcd/clientv3"
	consulAPI "github.com/hashicorp/consul/api"
)

var (
	kvBackend = ""
)

// Config is the configuration used by Daemon.
type Config struct {
	BpfDir                string                  // BPF template files directory
	LibDir                string                  // Cilium library files directory
	RunDir                string                  // Cilium runtime directory
	LXCMap                *lxcmap.LXCMap          // LXCMap where all LXCs are stored
	NodeAddress           *addressing.NodeAddress // Node IPv6 Address
	NAT46Prefix           *net.IPNet              // NAT46 IPv6 Prefix
	Device                string                  // Receive device
	HostV4Addr            net.IP                  // Host v4 address of the snooping device
	HostV6Addr            net.IP                  // Host v6 address of the snooping device
	ConsulConfig          *consulAPI.Config       // Consul configuration
	EtcdConfig            *etcdAPI.Config         // Etcd Configuration
	EtcdCfgPath           string                  // Etcd Configuration path
	DockerEndpoint        string                  // Docker endpoint
	IPv4Disabled          bool                    // Disable IPv4 allocation
	K8sEndpoint           string                  // Kubernetes endpoint
	K8sCfgPath            string                  // Kubeconfig path
	ValidLabelPrefixes    *labels.LabelPrefixCfg  // Label prefixes used to filter from all labels
	ValidK8sLabelPrefixes *labels.LabelPrefixCfg  // Label prefixes used to filter from all labels
	ValidLabelPrefixesMU  sync.RWMutex
	LBInterface           string // Set with name of the interface to loadbalance packets from
	Tunnel                string // Tunnel mode

	DryMode       bool // Do not create BPF maps, devices, ..
	RestoreState  bool // RestoreState restores the state from previous running daemons.
	KeepConfig    bool // Keep configuration of existing endpoints when starting up.
	KeepTemplates bool // Do not overwrite the template files

	// StateDir is the directory where runtime state of endpoints is stored
	StateDir string

	// Options changeable at runtime
	Opts   *option.BoolOptions
	OptsMU sync.RWMutex
}

func NewConfig() *Config {
	return &Config{
		Opts: option.NewBoolOptions(&options.Library),
	}
}

func (c *Config) IsK8sEnabled() bool {
	return c.K8sEndpoint != "" || c.K8sCfgPath != ""
}

func (c *Config) IsLBEnabled() bool {
	return c.LBInterface != ""
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
