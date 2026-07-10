// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func filterByNetworkInterface(ifaces []*flowpb.NetworkInterface) FilterFunc {
	return func(ev *v1.Event) bool {
		iface := ev.GetFlow().GetInterface()
		if iface == nil {
			return false
		}
		for _, f := range ifaces {
			if idx := f.GetIndex(); idx > 0 && idx != iface.GetIndex() {
				continue
			}
			if name := f.GetName(); name != "" && name != iface.GetName() {
				continue
			}
			return true
		}
		return false
	}
}

// NetworkInterfaceFilter implements filtering based on flow network interface.
type NetworkInterfaceFilter struct{}

// OnBuildFilter builds a flow network interface filter.
func (e *NetworkInterfaceFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc

	if ifaces := ff.GetInterface(); len(ifaces) > 0 {
		fs = append(fs, filterByNetworkInterface(ifaces))
	}

	return fs, nil
}
