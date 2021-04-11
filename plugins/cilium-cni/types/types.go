// Copyright 2016-2019 Authors of Cilium
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

package types

import (
	"encoding/json"
	"fmt"
	"net"
	"os"

	alibabaCloudTypes "github.com/cilium/cilium/pkg/alibabacloud/eni/types"
	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	azureTypes "github.com/cilium/cilium/pkg/azure/types"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"

	cniTypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
)

// NetConf is the Cilium specific CNI network configuration
type NetConf struct {
	cniTypes.NetConf
	MTU          int                    `json:"mtu"`
	Args         Args                   `json:"args"`
	ENI          eniTypes.ENISpec       `json:"eni,omitempty"`
	Azure        azureTypes.AzureSpec   `json:"azure,omitempty"`
	IPAM         ipamTypes.IPAMSpec     `json:"ipam,omitempty"`
	AlibabaCloud alibabaCloudTypes.Spec `json:"alibaba-cloud,omitempty"`
	EnableDebug  bool                   `json:"enable-debug"`
	LogFormat    string                 `json:"log-format"`
}

// NetConfList is a CNI chaining configuration
type NetConfList struct {
	Plugins []*NetConf `json:"plugins,omitempty"`
}

func parsePrevResult(n *NetConf) (*NetConf, error) {
	if n.RawPrevResult != nil {
		resultBytes, err := json.Marshal(n.RawPrevResult)
		if err != nil {
			return nil, fmt.Errorf("could not serialize prevResult: %v", err)
		}
		res, err := version.NewResult(n.CNIVersion, resultBytes)
		if err != nil {
			return nil, fmt.Errorf("could not parse prevResult: %v", err)
		}
		n.PrevResult, err = current.NewResultFromResult(res)
		if err != nil {
			return nil, fmt.Errorf("could not convert result to current version: %v", err)
		}
	}

	return n, nil
}

// ReadNetConf reads a CNI configuration file and returns the corresponding
// NetConf structure
func ReadNetConf(path string) (*NetConf, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Unable to read CNI configuration '%s': %s", path, err)
	}

	netConfList := &NetConfList{}
	if err := json.Unmarshal(b, netConfList); err == nil {
		for _, plugin := range netConfList.Plugins {
			if plugin.Type == "cilium-cni" {
				return parsePrevResult(plugin)
			}
		}
	}

	return LoadNetConf(b)
}

// LoadNetConf unmarshals a Cilium network configuration from JSON and returns
// a NetConf together with the CNI version
func LoadNetConf(bytes []byte) (*NetConf, error) {
	n := &NetConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %s", err)
	}

	return parsePrevResult(n)
}

// ArgsSpec is the specification of additional arguments of the CNI ADD call
type ArgsSpec struct {
	cniTypes.CommonArgs
	IP                         net.IP
	K8S_POD_NAME               cniTypes.UnmarshallableString
	K8S_POD_NAMESPACE          cniTypes.UnmarshallableString
	K8S_POD_INFRA_CONTAINER_ID cniTypes.UnmarshallableString
}

// Args contains arbitrary information a scheduler
// can pass to the cni plugin
type Args struct {
	Mesos Mesos `json:"org.apache.mesos,omitempty"`
}

// Mesos contains network-specific information from the scheduler to the cni plugin
type Mesos struct {
	NetworkInfo NetworkInfo `json:"network_info"`
}

// NetworkInfo supports passing only labels from mesos
type NetworkInfo struct {
	Name   string `json:"name"`
	Labels struct {
		Labels []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"labels,omitempty"`
	} `json:"labels,omitempty"`
}
