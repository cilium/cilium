// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func filterByUUID(uuids []string) FilterFunc {
	return func(ev *v1.Event) bool {
		flow := ev.GetFlow()
		if flow == nil {
			return false
		}
		eid := flow.GetUuid()
		for _, id := range uuids {
			if id == eid {
				return true
			}
		}
		return false
	}
}

// UUIDFilter implements filtering based on flow identifiers.
type UUIDFilter struct{}

// OnBuildFilter builds a a flow identifier filter.
func (e *UUIDFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc

	if ids := ff.GetUuid(); len(ids) > 0 {
		fs = append(fs, filterByUUID(ids))
	}

	return fs, nil
}
