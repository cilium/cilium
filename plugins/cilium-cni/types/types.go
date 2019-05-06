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

	cniTypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
)

// NetConf is the Cilium specific CNI network configuration
type NetConf struct {
	cniTypes.NetConf
	MTU  int  `json:"mtu"`
	Args Args `json:"args"`
}

// LoadNetConf unmarshals a Cilium network configuration from JSON and returns
// a NetConf together with the CNI version
func LoadNetConf(bytes []byte) (*NetConf, error) {
	n := &NetConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %s", err)
	}

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
