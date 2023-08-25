// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

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

func filterByIPVersion(ipver []flowpb.IPVersion) (FilterFunc, error) {
	return func(ev *v1.Event) bool {
		flow := ev.GetFlow()
		if flow == nil {
			return false
		}
		ver := flow.GetIP().GetIpVersion()
		for _, v := range ipver {
			if v == ver {
				return true
			}
		}
		return false
	}, nil
}

// IPVersionFilter implements IP version based filtering
type IPVersionFilter struct{}

// OnBuildFilter builds an IP version filter
func (f *IPVersionFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc

	if ff.GetIpVersion() != nil {
		pf, err := filterByIPVersion(ff.GetIpVersion())
		if err != nil {
			return nil, err
		}
		fs = append(fs, pf)
	}

	return fs, nil
}
