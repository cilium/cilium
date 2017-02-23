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
	"strings"
	"sync"
)

// Overall policy tree
type Tree struct {
	Root  *Node
	Mutex sync.RWMutex
}

func canConsume(root *Node, ctx *SearchContext) ConsumableDecision {
	ctx.Depth++
	decision := UNDECIDED
	nmatch := 0
	defer func() {
		if nmatch != 0 {
			ctx.Depth--
		}
	}()

	for _, child := range root.Children {
		if child.Covers(ctx) {
			nmatch++
			policyTrace(ctx, "Coverage found in [%s], processing rules...\n", child.path)
			ctx.Depth++
			switch child.Allows(ctx) {
			case DENY:
				ctx.Depth--
				return DENY
			case ALWAYS_ACCEPT:
				ctx.Depth--
				return ALWAYS_ACCEPT
			case ACCEPT:
				decision = ACCEPT
			}
			ctx.Depth--
			policyTrace(ctx, "No conclusion in [%s] rules, current verdict: [%s]\n", child.path, decision)
		}
	}

	if nmatch == 0 {
		ctx.Depth--
		policyTrace(ctx, "No matching children in [%s]\n", root.path)
		return decision
	}

	for _, child := range root.Children {
		if child.Covers(ctx) {
			switch canConsume(child, ctx) {
			case DENY:
				return DENY
			case ALWAYS_ACCEPT:
				return ALWAYS_ACCEPT
			case ACCEPT:
				decision = ACCEPT
			}
		}
	}

	return decision
}

func (t *Tree) Allows(ctx *SearchContext) ConsumableDecision {
	policyTrace(ctx, "Resolving policy: %s\n", ctx.String())

	var decision, sub_decision ConsumableDecision
	// In absence of policy, deny
	if t.Root == nil {
		decision = DENY
		policyTrace(ctx, "No policy loaded: [%s]\n", decision.String())
		goto end
	}

	decision = t.Root.Allows(ctx)
	policyTrace(ctx, "Root's [%s] rules verdict: [%s]\n", t.Root.path, decision)
	switch decision {
	case ALWAYS_ACCEPT:
		decision = ACCEPT
		goto end
	case DENY:
		goto end
	}

	policyTrace(ctx, "Searching in [%s]'s children that have the coverage for: [%s]\n", t.Root.path, ctx.To)
	sub_decision = canConsume(t.Root, ctx)
	policyTrace(ctx, "Root's [%s] children verdict: [%s]\n", t.Root.path, sub_decision)
	switch sub_decision {
	case ALWAYS_ACCEPT, ACCEPT:
		decision = ACCEPT
	case DENY:
		decision = DENY
	case UNDECIDED:
		if decision == UNDECIDED {
			decision = DENY
		}
	}

end:
	policyTrace(ctx, "Final verdict: [%s]\n", strings.ToUpper(decision.String()))

	return decision
}

func (t *Tree) ResolveL4Policy(ctx *SearchContext) *L4Policy {
	result := NewL4Policy()

	policyTrace(ctx, "Resolving L4 policy for context %+v\n", ctx)

	if t.Root == nil {
		return nil
	}

	t.Root.ResolveL4Policy(ctx, result)
	policyTrace(ctx, "Final tree L4 policy: %+v\n", result)

	return result
}
