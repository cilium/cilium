// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"strconv"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/labels"
)

// SearchContext defines the context while evaluating policy
type SearchContext struct {
	Depth  int
	From   labels.LabelArray
	To     labels.LabelArray
	DPorts []*models.Port
	// rulesSelect specifies whether or not to check whether a rule which is
	// being analyzed using this SearchContext matches either From or To.
	// This is used to avoid using EndpointSelector.Matches() if possible,
	// since it is costly in terms of performance.
	rulesSelect bool
}

func (s *SearchContext) String() string {
	from := make([]string, 0, len(s.From))
	to := make([]string, 0, len(s.To))
	dports := make([]string, 0, len(s.DPorts))
	for _, fromLabel := range s.From {
		from = append(from, fromLabel.String())
	}
	for _, toLabel := range s.To {
		to = append(to, toLabel.String())
	}
	// We should avoid to use `fmt.Sprintf()` since
	// it is well-known for not being opimal in terms of
	// CPU and memory allocations.
	// See https://github.com/cilium/cilium/issues/19571
	for _, dport := range s.DPorts {
		dportStr := dport.Name
		if dportStr == "" {
			dportStr = strconv.FormatUint(uint64(dport.Port), 10)
		}
		dports = append(dports, dportStr+"/"+dport.Protocol)
	}
	fromStr := strings.Join(from, ", ")
	toStr := strings.Join(to, ", ")
	if len(dports) != 0 {
		dportStr := strings.Join(dports, ", ")
		return "From: [" + fromStr + "] => To: [" + toStr + "] Ports: [" + dportStr + "]"
	}
	return "From: [" + fromStr + "] => To: [" + toStr + "]"
}

func (s *SearchContext) CallDepth() string {
	return strconv.Itoa(s.Depth * 2)
}
