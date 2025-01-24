// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hubble

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

// ParseFlowFilters parses a whitespace-delimited list of JSON-encoded flow filters.
func ParseFlowFilters(arg string) ([]*flowpb.FlowFilter, error) {
	var filters []*flowpb.FlowFilter
	dec := json.NewDecoder(strings.NewReader(arg))
	for {
		var filter flowpb.FlowFilter
		err := dec.Decode(&filter)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to decode flow filters %q: %w", arg, err)
		}
		filters = append(filters, &filter)
	}
	return filters, nil
}
