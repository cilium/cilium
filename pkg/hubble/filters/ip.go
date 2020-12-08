// Copyright 2019-2020 Authors of Hubble
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

package filters

import (
	"context"
	"fmt"
	"net"
	"strings"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func sourceIP(ev *v1.Event) string {
	return ev.GetFlow().GetIP().GetSource()
}

func destinationIP(ev *v1.Event) string {
	return ev.GetFlow().GetIP().GetDestination()
}

func filterByIPs(ips []string, getIP func(*v1.Event) string) (FilterFunc, error) {
	// IP filter can either be an exact match (e.g. "1.1.1.1") or a CIDR range
	// (e.g. "1.1.1.0/24"). Put them into 2 separate lists here.
	var addresses []string
	var cidrs []*net.IPNet
	for _, ip := range ips {
		if strings.Contains(ip, "/") {
			_, ipnet, err := net.ParseCIDR(ip)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR in filter: %q", ip)
			}
			cidrs = append(cidrs, ipnet)
		} else {
			if net.ParseIP(ip) == nil {
				return nil, fmt.Errorf("invalid IP address in filter: %q", ip)
			}
			addresses = append(addresses, ip)
		}
	}

	return func(ev *v1.Event) bool {
		eventIP := getIP(ev)
		if eventIP == "" {
			return false
		}

		for _, ip := range addresses {
			if ip == eventIP {
				return true
			}
		}

		if len(cidrs) > 0 {
			parsedIP := net.ParseIP(eventIP)
			for _, cidr := range cidrs {
				if cidr.Contains(parsedIP) {
					return true
				}
			}
		}

		return false
	}, nil
}

// IPFilter implements IP addressing filtering for the source and destination
// address
type IPFilter struct{}

// OnBuildFilter builds an IP address filter
func (f *IPFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc

	if ff.GetSourceIp() != nil {
		ipf, err := filterByIPs(ff.GetSourceIp(), sourceIP)
		if err != nil {
			return nil, err
		}
		fs = append(fs, ipf)
	}

	if ff.GetDestinationIp() != nil {
		ipf, err := filterByIPs(ff.GetDestinationIp(), destinationIP)
		if err != nil {
			return nil, err
		}
		fs = append(fs, ipf)
	}

	return fs, nil
}
