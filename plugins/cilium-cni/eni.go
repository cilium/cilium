// Copyright 2019 Authors of Cilium
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

	"github.com/cilium/cilium/api/v1/models"
	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"

	"github.com/containernetworking/cni/pkg/types/current"
)

func eniAdd(ipConfig *current.IPConfig, ipam *models.IPAMAddressResponse, conf models.DaemonConfigurationStatus) error {
	cidrs := make([]net.IPNet, 0, len(ipam.Cidrs))
	for _, cidrString := range ipam.Cidrs {
		_, cidr, err := net.ParseCIDR(cidrString)
		if err != nil {
			return fmt.Errorf("invalid CIDR '%s': %s", cidrString, err)
		}

		cidrs = append(cidrs, *cidr)
	}

	routingInfo, err := linuxrouting.NewRoutingInfo(ipam.Gateway, ipam.Cidrs, ipam.MasterMac)
	if err != nil {
		return fmt.Errorf("unable to parse routing info: %v", err)
	}

	if err := routingInfo.Configure(ipConfig.Address.IP,
		int(conf.DeviceMTU),
		conf.Masquerade); err != nil {
		return fmt.Errorf("unable to install ip rules and routes: %s", err)
	}

	return nil
}
