// Copyright 2020 Authors of Cilium
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

package ipmasq

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/maps/ipmasq"
)

// ipnet is a wrapper type for net.IPNet to enable de-serialization of CIDRs
type ipnet net.IPNet

func (c *ipnet) UnmarshalJSON(json []byte) error {
	_, n, err := net.ParseCIDR(string(json[1 : len(json)-1]))
	if err != nil {
		return fmt.Errorf("Invalid CIDR %s: %s", string(json), err)
	}
	*c = ipnet(*n)
	return nil

}

// config represents the ip-masq-agent configuration file encoded as JSON
type config struct {
	NonMasqCIDRs []ipnet `json:"nonMasqueradeCIDRs"`
}

// IPMasqAgent represents a state of the ip-masq-agent
type IPMasqAgent struct {
	configPath             string
	nonMasqCIDRsFromConfig map[string]net.IPNet
	nonMasqCIDRsInMap      map[string]net.IPNet
}

// Run starts the "ip-masq-agent" controller which is used to sync the ipmasq
// BPF maps.
func Run(configPath string, syncPeriod time.Duration) error {
	a := &IPMasqAgent{
		configPath:        configPath,
		nonMasqCIDRsInMap: map[string]net.IPNet{},
	}

	if err := a.restore(); err != nil {
		return err
	}

	controller.NewManager().UpdateController("ip-masq-agent",
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				return a.Update()
			},
			RunInterval: syncPeriod,
		},
	)

	return nil
}

// Update updates the ipmasq BPF map entries with ones from the config file.
func (a *IPMasqAgent) Update() error {
	if err := a.readConfig(); err != nil {
		return err
	}

	for cidrStr, cidr := range a.nonMasqCIDRsInMap {
		if _, ok := a.nonMasqCIDRsFromConfig[cidrStr]; !ok {
			ipmasq.Delete(cidr)
			delete(a.nonMasqCIDRsFromConfig, cidrStr)
		}
	}

	for cidrStr, cidr := range a.nonMasqCIDRsFromConfig {
		if _, ok := a.nonMasqCIDRsInMap[cidrStr]; !ok {
			ipmasq.Update(cidr)
			a.nonMasqCIDRsInMap[cidrStr] = cidr
		}
	}

	return nil
}

// readConfig reads the config file and populates IPMasqAgent.nonMasqCIDRsFromConfig
// with the CIDRs from the file.
func (a *IPMasqAgent) readConfig() error {
	var cfg config

	raw, err := ioutil.ReadFile(a.configPath)
	if err != nil {
		return fmt.Errorf("Failed to read %s: %s", a.configPath, err)
	}

	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("Failed to de-serialize JSON: %s", err)
	}

	nonMasqCIDRs := map[string]net.IPNet{}
	for _, cidr := range cfg.NonMasqCIDRs {
		n := net.IPNet(cidr)
		nonMasqCIDRs[n.String()] = n
	}
	a.nonMasqCIDRsFromConfig = nonMasqCIDRs

	return nil
}

// restore dumps the ipmasq BPF map and populates IPMasqAgent.nonMasqCIDRsInMap
// with the CIDRs from the map.
func (a *IPMasqAgent) restore() error {
	cidrsInMap, err := ipmasq.Dump()
	if err != nil {
		return fmt.Errorf("Failed to dump ip-masq-agent cidrs from map: %s", err)
	}

	cidrs := map[string]net.IPNet{}
	for _, cidr := range cidrsInMap {
		cidrs[cidr.String()] = cidr
	}
	a.nonMasqCIDRsInMap = cidrs

	return nil
}
