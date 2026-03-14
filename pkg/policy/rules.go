// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"cmp"
	"errors"
	"slices"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy/types"
)

// ErrTooManyPriorityLevels is returned if an endpoint's policy results in more than
// 2^24 distinct priorities for a given direction; the datapath cannot support more than that.
var ErrTooManyPriorityLevels = errors.New("endpoint policy direction has more than 2^24 distinct priorities")

// ErrUnorderedTiers is returned if tiers of policy entries are unordered when they are expected to
// be ordered.
var ErrUnorderedTiers = errors.New("Unordered policy entry tiers")
var ErrInvalidTier = errors.New("Too high tier value")

// ErrUnorderedRules is returned if prioritites of policy entries are unordered when they are
// expected to be ordered.
var ErrUnorderedRules = errors.New("Unordered policy entry priorities")

// ruleSlice is a wrapper around a slice of *rule, which allows for functions
// to be written with []*rule as a receiver.
type ruleSlice []*rule

func roundUp(n int, to int) int {
	return ((n + (to - 1)) / to) * to
}

var perTierRoundUp = 10

// computeTierPriorities determines the base priority for each tier, and the number of priority
// levels to reserve after each pass verdict on each tier. Two slices are returned: one with the
// base priority for each tier, and other with the number of priority levels to reserve after each
// pass verdict on each tier.
//
// The returned slices have the values for each tier (0, 1, ...) in the policy. Policy tiers are not
// compressed, but used 1:1, i.e., tier 3 in policy is at index 3, even if tier 2 had no rules int
// it.
func (rules ruleSlice) computeTierPriorities() ([]types.Priority, []int, error) {
	nTiers := int(rules[len(rules)-1].Tier) + 1
	tierPriorityLevels := make([]int, nTiers)
	numPassVerdicts := make([]int, nTiers)

	lastPrio := rules[0].Priority
	levels := 1 // each tier with any rules occupies at least one priority level
	lastPassLevel := 0
	lastTier := rules[0].Tier

	for _, r := range rules {
		if r.Tier != lastTier {
			if r.Tier < lastTier {
				return nil, nil, ErrUnorderedTiers
			}
			if int(r.Tier) >= nTiers {
				return nil, nil, ErrInvalidTier
			}
			// Keep the needed priority levels for the previous tier,
			// rounding up to next 10 to reduce policy map churn.
			tierPriorityLevels[lastTier] = roundUp(levels, 10)

			// reset counting priority levels for the next tier
			lastTier = r.Tier
			lastPrio = r.Priority
			levels = 1
			lastPassLevel = 0
		} else if r.Priority != lastPrio {
			if r.Priority < lastPrio {
				return nil, nil, ErrUnorderedRules
			}
			levels++
			lastPrio = r.Priority
		}

		// count the number of pass verdicts on different priorities on each tier
		if r.Verdict == types.Pass && levels != lastPassLevel {
			numPassVerdicts[lastTier]++
			lastPassLevel = levels
		}
	}
	// for the last tier
	tierPriorityLevels[lastTier] = roundUp(levels, perTierRoundUp)

	// Compute the whole priority range needed for each tier by adding the lower tier priorities
	// for each pass verdict so that when computing mapstate we can elevate priority of each
	// passed-to entry to the priorities following the pass verdict.
	for tier := int(lastTier) - 1; tier >= 0; tier-- {
		tierPriorityLevels[tier] += (numPassVerdicts[tier] + 1) * tierPriorityLevels[tier+1]
		tierPriorityLevels[tier] = types.Roundup(tierPriorityLevels[tier], perTierRoundUp)
	}

	if tierPriorityLevels[0] > int(types.LowestPriority) {
		return nil, nil, ErrTooManyPriorityLevels
	}

	tierBasePriorities := make([]types.Priority, nTiers)
	basePriority := types.Priority(0)
	for tier := 1; tier <= int(lastTier); tier++ {
		basePriority += types.Priority(tierPriorityLevels[tier-1] - tierPriorityLevels[tier])
		tierBasePriorities[tier] = basePriority
	}

	// transform tierPriority levels to the number of priority levels needed after each pass
	// verdict on any given tier by shifting up by one.
	tierPriorityLevels = append(tierPriorityLevels[1:], 0)
	return tierBasePriorities, tierPriorityLevels, nil
}

func (rules ruleSlice) resolveL4Policy(policyCtx PolicyContext) (L4DirectionPolicy, error) {
	state := traceState{}
	result := L4DirectionPolicy{
		PortRules: L4PolicyMaps{makeL4PolicyMap()},
	}

	if len(rules) == 0 {
		result.tierBasePriority = make([]types.Priority, 1)
		state.trace(len(rules), policyCtx)
		return result, nil
	}

	// compute how many priority levels are needed for each tier.
	tierBasePriorities, tierPassPriorities, err := rules.computeTierPriorities()
	if err != nil {
		return result, err
	}

	result.tierBasePriority = tierBasePriorities
	lastTier := types.Tier(len(tierBasePriorities) - 1)

	// add rules, computing the absolute priority for each rule,
	// making sufficient gaps after each pass verdict, but keeping entries with the same
	// priority at the same absolute priority
	priority := types.Priority(0)
	increment := types.Priority(1) // default increment
	tier := types.Tier(0)
	lastPrio := rules[0].Priority
	for _, r := range rules {
		if r.Tier != tier {
			tier = r.Tier
			priority = result.tierBasePriority[tier]
			increment = types.Priority(1) // reset increment to default
			lastPrio = r.Priority
		} else if r.Priority != lastPrio {
			// This rule's priority is greater than that of the previous, so we bump
			// level.  This has the effect of "flattening" an arbitrary float ordering
			// of rules in to a single integer sequence of levels.
			if !priority.Add(increment) {
				return result, ErrTooManyPriorityLevels
			}
			increment = types.Priority(1) // reset increment to default
			lastPrio = r.Priority
		}

		policyCtx.SetPriority(tier, priority)

		err := result.PortRules.resolveL4Policy(policyCtx, &state, r)
		if err != nil {
			return result, err
		}
		state.ruleID++

		// Adjust increment to make space after pass verdict for all the lower tier rules.
		// + 1 for the pass verdict itself so that there is space for all passed to entries
		// after the pass entry itself.
		if r.Verdict == types.Pass && tier < lastTier {
			increment = types.Priority(tierPassPriorities[tier]) + 1
		}
	}

	state.trace(len(rules), policyCtx)
	return result, nil
}

// Sort rules by tier and priority, then resource as a tiebreaker.
// Sorting rules by priority is necessary to convert from the float
// api priority to the integer datapath level.
func (rules ruleSlice) sort() {
	slices.SortFunc(rules, func(a, b *rule) int {
		// tier first
		if sign := cmp.Compare(a.Tier, b.Tier); sign != 0 {
			return sign
		}
		// priority next
		if sign := cmp.Compare(a.Priority, b.Priority); sign != 0 {
			return sign
		}
		// resource id for consistency
		if sign := cmp.Compare(a.key.resource, b.key.resource); sign != 0 {
			return sign
		}
		return cmp.Compare(a.key.idx, b.key.idx)
	})
}

// AsPolicyEntries return the internal PolicyEntry objects as a PolicyEntries object
func (rules ruleSlice) AsPolicyEntries() types.PolicyEntries {
	policyRules := make(types.PolicyEntries, 0, len(rules))
	for _, r := range rules {
		policyRules = append(policyRules, &r.PolicyEntry)
	}
	return policyRules
}

func (rules ruleSlice) AllIdentitySelections() set.Set[identity.NumericIdentity] {
	ids := set.NewSet[identity.NumericIdentity]()
	for _, r := range rules {
		for _, id := range r.getSubjects() {
			ids.Insert(id)
		}
	}
	return ids
}

// traceState is an internal structure used to collect information
// while determining policy decision
type traceState struct {
	// selectedRules is the number of rules with matching EndpointSelector
	selectedRules int

	// matchedRules is the number of rules that have allowed traffic
	matchedRules int

	// matchedDenyRules is the number of rules that have denied traffic
	matchedDenyRules int

	// ruleID is the rule ID currently being evaluated
	ruleID int
}

func (state *traceState) trace(rules int, policyCtx PolicyContext) {
	policyCtx.PolicyTrace("%d/%d rules selected\n", state.selectedRules, rules)
	if state.matchedRules > 0 {
		policyCtx.PolicyTrace("Found allow rule\n")
	} else {
		policyCtx.PolicyTrace("Found no allow rule\n")
	}
	if state.matchedDenyRules > 0 {
		policyCtx.PolicyTrace("Found deny rule\n")
	} else {
		policyCtx.PolicyTrace("Found no deny rule\n")
	}
}

func (state *traceState) selectRule(policyCtx PolicyContext, r *rule) {
	policyCtx.PolicyTrace("* Rule %s: selected\n", r)
	state.selectedRules++
}
