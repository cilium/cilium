// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/policy/types"
)

func TestComputeTierPriorities(t *testing.T) {
	oldRoundUp := perTierRoundUp
	defer func() { perTierRoundUp = oldRoundUp }()
	perTierRoundUp = 10

	// note that expected priorities are multiplied by perTierRoundUp
	for i, tc := range []struct {
		rules              []types.PolicyEntry
		expectedTiers      []types.Priority
		expectedPriorities []int
	}{
		{
			rules: []types.PolicyEntry{
				{
					Tier:     0,
					Priority: 0,
				},
			},
			expectedTiers:      []types.Priority{0},
			expectedPriorities: []int{1},
		},
		{
			rules: []types.PolicyEntry{
				{
					Tier:     1,
					Priority: 0,
				},
			},
			expectedTiers:      []types.Priority{0, 1},
			expectedPriorities: []int{2, 1},
		},
		{
			rules: []types.PolicyEntry{
				{
					Tier:     0,
					Priority: 0,
					Verdict:  types.Pass,
				},
				{
					Tier:     1,
					Priority: 0,
				},
				{
					Tier:     1,
					Priority: 1,
				},
				{
					Tier:     1,
					Priority: 2,
				},
				{
					Tier:     1,
					Priority: 3,
				},
				{
					Tier:     1,
					Priority: 4,
				},
				{
					Tier:     1,
					Priority: 5,
				},
				{
					Tier:     1,
					Priority: 6,
				},
				{
					Tier:     1,
					Priority: 7,
				},
				{
					Tier:     1,
					Priority: 8,
				},
				{
					Tier:     1,
					Priority: 9,
				},
				{
					Tier:     1,
					Priority: 10,
				},
			},
			expectedTiers:      []types.Priority{0, 3},
			expectedPriorities: []int{5, 2},
		},
		{
			rules: []types.PolicyEntry{
				{
					Tier:     0,
					Priority: 0,
					Verdict:  types.Pass,
				},
				{
					Tier:     1,
					Priority: 0,
				},
			},
			expectedTiers:      []types.Priority{0, 2},
			expectedPriorities: []int{3, 1},
		},
		{
			rules: []types.PolicyEntry{
				{
					Tier:     0,
					Priority: 0,
				},
				{
					Tier:     0,
					Priority: 1,
				},
				{
					Tier:     1,
					Priority: 0,
				},
			},
			expectedTiers:      []types.Priority{0, 1},
			expectedPriorities: []int{2, 1},
		},
		{
			rules: []types.PolicyEntry{
				{
					Tier:     0,
					Priority: 0,
				},
				{
					Tier:     1,
					Priority: 1,
				},
				{
					Tier:     2,
					Priority: 0,
				},
			},
			expectedTiers:      []types.Priority{0, 1, 2},
			expectedPriorities: []int{3, 2, 1},
		},
		{
			rules: []types.PolicyEntry{
				{
					Tier:     0,
					Priority: 0,
					Verdict:  types.Pass,
				},
				{
					Tier:     1,
					Priority: 1,
					Verdict:  types.Pass,
				},
				{
					Tier:     2,
					Priority: 0,
				},
			},
			expectedTiers:      []types.Priority{0, 4, 6},
			expectedPriorities: []int{7, 3, 1},
		},
		{
			rules: []types.PolicyEntry{
				{
					Tier:     0,
					Priority: 0,
					Verdict:  types.Pass,
				},
				{
					Tier:     2,
					Priority: 0,
				},
			},
			expectedTiers:      []types.Priority{0, 2, 2},
			expectedPriorities: []int{3, 1, 1},
		},
		{
			rules: []types.PolicyEntry{
				{
					Tier:     0,
					Priority: 0,
				},
				{
					Tier:     2,
					Priority: 0,
				},
			},
			expectedTiers:      []types.Priority{0, 1, 1},
			expectedPriorities: []int{2, 1, 1},
		},
	} {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			rs := make(ruleSlice, 0, len(tc.rules))
			for _, r := range tc.rules {
				rs = append(rs, &rule{
					PolicyEntry: r,
				})
			}
			rs.sort()

			for i := range tc.expectedPriorities {
				tc.expectedTiers[i] *= types.Priority(perTierRoundUp)
				tc.expectedPriorities[i] *= perTierRoundUp
			}

			actualPriorities, actualTiers, err := rs.computeTierPriorities()
			require.NoError(t, err)
			require.Equal(t, tc.expectedTiers, actualTiers)
			require.Equal(t, tc.expectedPriorities, actualPriorities)
		})
	}
}
