// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"
	"fmt"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func filterByTCPFlags(flags []*flowpb.TCPFlags) (FilterFunc, error) {
	return func(ev *v1.Event) bool {
		flowFlags := ev.GetFlow().GetL4().GetTCP().GetFlags()
		if flowFlags == nil {
			return false
		}
		// check if the TCP event has any of the flags mentioned in flowfilter
		// example: if TCP event has flags SYN and ACK set and if the flowfilter
		// only has SYN, then this event should be accepted by the filter.
		for _, f := range flags {
			switch {
			case f.FIN && !flowFlags.FIN,
				f.SYN && !flowFlags.SYN,
				f.RST && !flowFlags.RST,
				f.PSH && !flowFlags.PSH,
				f.ACK && !flowFlags.ACK,
				f.URG && !flowFlags.URG,
				f.ECE && !flowFlags.ECE,
				f.CWR && !flowFlags.CWR,
				f.NS && !flowFlags.NS:
				continue
			}
			return true
		}
		return false
	}, nil
}

// TCPFilter implements filtering based on TCP protocol header
type TCPFilter struct{}

// OnBuildFilter builds a TCP protocol based filter
func (p *TCPFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc

	if ff.GetTcpFlags() != nil {
		pf, err := filterByTCPFlags(ff.GetTcpFlags())
		if err != nil {
			return nil, fmt.Errorf("invalid tcp flags filter: %w", err)
		}
		fs = append(fs, pf)
	}

	return fs, nil
}
