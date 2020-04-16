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
	enirouting "github.com/cilium/cilium/pkg/aws/eni/routing"
	"github.com/cilium/cilium/pkg/mac"

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

	if ipam.MasterMac == "" {
		return fmt.Errorf("ENI master interface MAC address is not set")
	}

	mac, err := mac.ParseMAC(ipam.MasterMac)
	if err != nil {
		return fmt.Errorf("unable to parse master interface MAC address %s", ipam.MasterMac)
	}

	gatewayIP := net.ParseIP(ipam.Gateway)
	if gatewayIP == nil {
		return fmt.Errorf("unable to parse gateway IP %s", ipam.Gateway)
	}

	if err := enirouting.Install(ipConfig.Address.IP, &enirouting.RoutingInfo{
		IPv4Gateway: gatewayIP,
		IPv4CIDRs:   cidrs,
		MasterIfMAC: mac,
	}, int(conf.DeviceMTU), conf.Masquerade); err != nil {
		return fmt.Errorf("unable to install ip rules and routes: %s", err)
	}

	return nil
}
