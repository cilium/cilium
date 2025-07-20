// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package observe

import (
	"strings"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

// parseWorkload parse and returns workloads
func parseWorkload(s string) *flowpb.Workload {
	if s == "" {
		return &flowpb.Workload{}
	}
	var kind, name string
	elements := strings.SplitN(s, "/", 2)
	if len(elements) == 1 { // foo-deploy
		name = elements[0]
	} else { // Deployment/foo-deploy and Deployment/
		kind, name = elements[0], elements[1]
	}
	return &flowpb.Workload{Kind: kind, Name: name}
}
