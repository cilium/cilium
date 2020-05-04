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
	"os"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/yaml"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ipmasq"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ipmasq")
)

// ipnet is a wrapper type for net.IPNet to enable de-serialization of CIDRs
type Ipnet net.IPNet

func (c *Ipnet) UnmarshalJSON(json []byte) error {
	str := string(json)

	if json[0] != '"' {
		return fmt.Errorf("Invalid CIDR: %s", str)
	}

	ip, n, err := net.ParseCIDR(strings.Trim(str, `"`))
	if err != nil {
		return fmt.Errorf("Invalid CIDR %s: %s", str, err)
	}
	if ip.To4() == nil {
		return fmt.Errorf("Invalid CIDR %s: only IPv4 is supported", str)
	}

	*c = Ipnet(*n)
	return nil
}

// config represents the ip-masq-agent configuration file encoded as YAML
type config struct {
	NonMasqCIDRs []Ipnet `json:"nonMasqueradeCIDRs"`
}

// IPMasqMap is an interface describing methods for manipulating an ipmasq map
type IPMasqMap interface {
	Update(cidr net.IPNet) error
	Delete(cidr net.IPNet) error
	Dump() ([]net.IPNet, error)
}

// IPMasqAgent represents a state of the ip-masq-agent
type IPMasqAgent struct {
	configPath             string
	nonMasqCIDRsFromConfig map[string]net.IPNet
	nonMasqCIDRsInMap      map[string]net.IPNet
	ipMasqMap              IPMasqMap
}

// Start starts the "ip-masq-agent" controller which is used to sync the ipmasq
// BPF maps.
func Start(configPath string, syncPeriod time.Duration) {
	start(configPath, syncPeriod, &ipmasq.IPMasqBPFMap{}, controller.NewManager())
}

func start(configPath string, syncPeriod time.Duration,
	ipMasqMap IPMasqMap, manager *controller.Manager) {

	a := &IPMasqAgent{
		configPath:        configPath,
		nonMasqCIDRsInMap: map[string]net.IPNet{},
		ipMasqMap:         ipMasqMap,
	}

	if err := a.restore(); err != nil {
		log.WithError(err).Warn("ip-masq-agent failed to restore")
	}

	manager.UpdateController("ip-masq-agent",
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				return a.Update()
			},
			RunInterval: syncPeriod,
		},
	)
}

// Update updates the ipmasq BPF map entries with ones from the config file.
func (a *IPMasqAgent) Update() error {
	if err := a.readConfig(); err != nil {
		return err
	}

	for cidrStr, cidr := range a.nonMasqCIDRsFromConfig {
		if _, ok := a.nonMasqCIDRsInMap[cidrStr]; !ok {
			log.WithField(logfields.CIDR, cidrStr).Info("Adding CIDR")
			a.ipMasqMap.Update(cidr)
			a.nonMasqCIDRsInMap[cidrStr] = cidr
		}
	}

	for cidrStr, cidr := range a.nonMasqCIDRsInMap {
		if _, ok := a.nonMasqCIDRsFromConfig[cidrStr]; !ok {
			log.WithField(logfields.CIDR, cidrStr).Info("Removing CIDR")
			a.ipMasqMap.Delete(cidr)
			delete(a.nonMasqCIDRsInMap, cidrStr)
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
		if os.IsNotExist(err) {
			log.WithField(logfields.Path, a.configPath).Info("Config file not found")
			a.nonMasqCIDRsFromConfig = map[string]net.IPNet{}
			return nil
		}
		return fmt.Errorf("Failed to read %s: %s", a.configPath, err)
	}

	jsonStr, err := yaml.ToJSON(raw)
	if err != nil {
		return fmt.Errorf("Failed to convert to json: %s", err)
	}

	if err := json.Unmarshal([]byte(jsonStr), &cfg); err != nil {
		return fmt.Errorf("Failed to de-serialize json: %s", err)
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
	cidrsInMap, err := a.ipMasqMap.Dump()
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
