// Copyright 2016-2017 Authors of Cilium
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

package policy

import (
	"fmt"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

type rule struct {
	api.Rule
}

func (r *rule) String() string {
	return fmt.Sprintf("%v", r.EndpointSelector)
}

func (r *rule) validate() error {
	if r == nil {
		return fmt.Errorf("nil rule")
	}

	if len(r.EndpointSelector) == 0 {
		return fmt.Errorf("empty EndpointSelector")
	}

	return nil
}

func mergeL4Port(ctx *SearchContext, r api.PortRule, p api.PortProtocol, proto string, resMap L4PolicyMap) int {
	fmt := p.Port + "/" + proto
	if _, ok := resMap[fmt]; !ok {
		resMap[fmt] = CreateL4Filter(r, p, proto)
		return 1
	}

	return 0
}

func mergeL4(ctx *SearchContext, dir string, portRules []api.PortRule, resMap L4PolicyMap) int {
	found := 0

	for _, r := range portRules {
		ctx.PolicyTrace("  Allows %s port %v\n", dir, r.Ports)

		if r.RedirectPort != 0 {
			ctx.PolicyTrace("    Redirect-To: %d\n", r.RedirectPort)
		}

		if r.Rules != nil {
			for _, l7 := range r.Rules.HTTP {
				ctx.PolicyTrace("      %+v\n", l7)
			}
		}

		for _, p := range r.Ports {
			if p.Protocol != "" {
				found += mergeL4Port(ctx, r, p, p.Protocol, resMap)
			} else {
				found += mergeL4Port(ctx, r, p, "tcp", resMap)
				found += mergeL4Port(ctx, r, p, "udp", resMap)
			}
		}
	}

	return found
}

func (r *rule) resolveL4Policy(ctx *SearchContext, state *traceState, result *L4Policy) *L4Policy {
	if !ctx.TargetCoveredBy(r.EndpointSelector) {
		ctx.PolicyTraceVerbose("  Rule %d %s: no match\n", state.ruleID, r)
		return nil
	}

	state.selectedRules++
	ctx.PolicyTrace("* Rule %d %s: match\n", state.ruleID, r)
	found := 0

	if !ctx.EgressL4Only {
		for _, r := range r.Ingress {
			found += mergeL4(ctx, "Ingress", r.ToPorts, result.Ingress)
		}
	}

	if !ctx.IngressL4Only {
		for _, r := range r.Egress {
			found += mergeL4(ctx, "Egress", r.ToPorts, result.Egress)
		}
	}

	if found > 0 {
		return result
	}

	ctx.PolicyTrace("    No L4 rules\n")
	return nil
}

func (r *rule) canReach(ctx *SearchContext, state *traceState) api.Decision {
	if !ctx.TargetCoveredBy(r.EndpointSelector) {
		ctx.PolicyTraceVerbose("  Rule %d %s: no match\n", state.ruleID, r)
		return api.Undecided
	}

	state.selectedRules++
	ctx.PolicyTrace("* Rule %d %s: match\n", state.ruleID, r)

	for _, r := range r.Ingress {
		for _, sel := range r.FromRequires {
			ctx.PolicyTrace("    Requires from labels %+v", sel)
			// TODO: get rid of this cast
			lacks := ctx.From.Lacks(labels.LabelArray(sel))
			if len(lacks) > 0 {
				ctx.PolicyTrace("-     Labels %v not found\n", lacks)
				return api.Denied
			}
			ctx.PolicyTrace("+     Found all required labels\n")
		}
	}

	// separate loop is needed as failure to meet FromRequires always takes
	// precedence over FromEndpoints
	for _, r := range r.Ingress {
		for _, sel := range r.FromEndpoints {
			// TODO: get rid of this cast
			ctx.PolicyTrace("    Allows from labels %+v", sel)
			lacks := ctx.From.Lacks(labels.LabelArray(sel))
			if len(lacks) == 0 {
				ctx.PolicyTrace("+     Found all required labels\n")
				return api.Allowed
			}

			ctx.PolicyTrace("      Labels %v not found\n", lacks)
		}
	}

	return api.Undecided
}
