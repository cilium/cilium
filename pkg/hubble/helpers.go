// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hubble

import (
	"encoding/json"
	"fmt"
	"strings"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

func ParseFlowFilters(args ...string) ([]*flowpb.FlowFilter, error) {
	filters := make([]*flowpb.FlowFilter, 0, len(args))
	for _, enc := range args {
		dec := json.NewDecoder(strings.NewReader(enc))
		var filter flowpb.FlowFilter
		if err := dec.Decode(&filter); err != nil {
			return nil, fmt.Errorf("failed to decode flow filter '%v': %w", enc, err)
		}
		filters = append(filters, &filter)
	}
	return filters, nil
}
