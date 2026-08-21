// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"
	"fmt"
	"slices"
	"strconv"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func sourcePort(ev *v1.Event) (port uint16, ok bool) {
	if ev == nil {
		return 0, false
	}
	fl := ev.GetFlow()
	if fl == nil {
		return 0, false
	}
	switch {
	case !fl.L4.TCP.IsEmpty():
		return uint16(fl.L4.TCP.SourcePort), true
	case !fl.L4.UDP.IsEmpty():
		return uint16(fl.L4.UDP.SourcePort), true
	case !fl.L4.SCTP.IsEmpty():
		return uint16(fl.L4.SCTP.SourcePort), true
	default:
		return 0, false
	}
}

func destinationPort(ev *v1.Event) (port uint16, ok bool) {
	if ev == nil {
		return 0, false
	}
	fl := ev.GetFlow()
	if fl == nil {
		return 0, false
	}

	switch {
	case !fl.L4.TCP.IsEmpty():
		return uint16(fl.L4.TCP.DestinationPort), true
	case !fl.L4.UDP.IsEmpty():
		return uint16(fl.L4.UDP.DestinationPort), true
	case !fl.L4.SCTP.IsEmpty():
		return uint16(fl.L4.SCTP.DestinationPort), true
	default:
		return 0, false
	}
}

func filterByPort(portStrs []string, getPort func(*v1.Event) (port uint16, ok bool)) (FilterFunc, error) {
	ports := make([]uint16, 0, len(portStrs))
	for _, p := range portStrs {
		port, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", p, err)
		}
		ports = append(ports, uint16(port))
	}

	return func(ev *v1.Event) bool {
		if port, ok := getPort(ev); ok {
			return slices.Contains(ports, port)
		}
		return false
	}, nil
}

// PortFilter implements filtering based on L4 port numbers
type PortFilter struct{}

// OnBuildFilter builds a L4 port filter
func (p *PortFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc

	if ff.GetSourcePort() != nil {
		spf, err := filterByPort(ff.GetSourcePort(), sourcePort)
		if err != nil {
			return nil, fmt.Errorf("invalid source port filter: %w", err)
		}
		fs = append(fs, spf)
	}

	if ff.GetDestinationPort() != nil {
		dpf, err := filterByPort(ff.GetDestinationPort(), destinationPort)
		if err != nil {
			return nil, fmt.Errorf("invalid destination port filter: %w", err)
		}
		fs = append(fs, dpf)
	}

	return fs, nil
}
