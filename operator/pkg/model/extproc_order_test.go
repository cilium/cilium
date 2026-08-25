// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package model

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAnalyzeExtProcOrderReportsLosingRouteAndKeepsUniqueFilters(t *testing.T) {
	old := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	analysis := AnalyzeExtProcOrder(&Model{HTTP: []HTTPListener{{Routes: []HTTPRoute{
		{ExtensionRefFilters: []ExtensionRefFilter{
			extProcOrderFilter("alpha", "old", old, 0, "old", 0),
			extProcOrderFilter("beta", "old", old, 0, "old", 1),
		}},
		{ExtensionRefFilters: []ExtensionRefFilter{
			extProcOrderFilter("beta", "new", newer, 0, "new", 0),
			extProcOrderFilter("alpha", "new", newer, 0, "new", 1),
			extProcOrderFilter("only-losing", "new", newer, 0, "new", 2),
		}},
	}}}})

	require.Equal(t, []string{"alpha", "beta", "only-losing"}, []string{
		analysis.Filters[0].Name,
		analysis.Filters[1].Name,
		analysis.Filters[2].Name,
	})
	require.Equal(t, []FullyQualifiedResource{{Name: "new", Namespace: "default", Kind: "HTTPRoute", UID: "new"}}, analysis.ConflictedRoutes)
}

func TestAnalyzeExtProcOrderKeepsRepeatedMatchesTogether(t *testing.T) {
	creation := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	analysis := AnalyzeExtProcOrder(&Model{HTTP: []HTTPListener{{Routes: []HTTPRoute{
		{ExtensionRefFilters: []ExtensionRefFilter{
			extProcOrderFilter("alpha", "route", creation, 0, "uid", 0),
			extProcOrderFilter("beta", "route", creation, 0, "uid", 1),
		}},
		{ExtensionRefFilters: []ExtensionRefFilter{
			extProcOrderFilter("alpha", "route", creation, 0, "uid", 0),
			extProcOrderFilter("beta", "route", creation, 0, "uid", 1),
		}},
	}}}})

	require.Equal(t, []string{"alpha", "beta"}, []string{analysis.Filters[0].Name, analysis.Filters[1].Name})
	require.Empty(t, analysis.ConflictedRoutes)
}

func TestAnalyzeExtProcOrderPrecedenceAndFallback(t *testing.T) {
	old := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := old.Add(time.Hour)

	tests := []struct {
		name     string
		routes   []HTTPRoute
		expected []string
	}{
		{
			name: "route UID breaks an otherwise equal conflict",
			routes: []HTTPRoute{
				{ExtensionRefFilters: []ExtensionRefFilter{
					extProcOrderFilter("beta", "same-name", old, 0, "uid-b", 0),
					extProcOrderFilter("alpha", "same-name", old, 0, "uid-b", 1),
				}},
				{ExtensionRefFilters: []ExtensionRefFilter{
					extProcOrderFilter("alpha", "same-name", old, 0, "uid-a", 0),
					extProcOrderFilter("beta", "same-name", old, 0, "uid-a", 1),
				}},
			},
			expected: []string{"alpha", "beta"},
		},
		{
			name: "three-way cycle rejects the lowest-precedence constraint",
			routes: []HTTPRoute{
				{ExtensionRefFilters: []ExtensionRefFilter{
					extProcOrderFilter("a", "old", old, 0, "a", 0),
					extProcOrderFilter("b", "old", old, 0, "a", 1),
				}},
				{ExtensionRefFilters: []ExtensionRefFilter{
					extProcOrderFilter("b", "middle", newer, 0, "b", 0),
					extProcOrderFilter("c", "middle", newer, 0, "b", 1),
				}},
				{ExtensionRefFilters: []ExtensionRefFilter{
					extProcOrderFilter("c", "new", newer.Add(time.Hour), 0, "c", 0),
					extProcOrderFilter("a", "new", newer.Add(time.Hour), 0, "c", 1),
				}},
			},
			expected: []string{"a", "b", "c"},
		},
		{
			name: "missing provenance preserves scan order",
			routes: []HTTPRoute{
				{ExtensionRefFilters: []ExtensionRefFilter{{Name: "second"}}},
				{ExtensionRefFilters: []ExtensionRefFilter{{Name: "first"}}},
			},
			expected: []string{"second", "first"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			analysis := AnalyzeExtProcOrder(&Model{HTTP: []HTTPListener{{Routes: tc.routes}}})
			names := make([]string, len(analysis.Filters))
			for i := range analysis.Filters {
				names[i] = analysis.Filters[i].Name
			}
			require.Equal(t, tc.expected, names)
		})
	}
}

func TestAnalyzeExtProcOrderKeepsHighestPrecedenceRepresentative(t *testing.T) {
	old := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := old.Add(time.Hour)
	newFilter := extProcOrderFilter("shared", "new", newer, 0, "new", 0)
	newFilter.TypeURL = "new-config"
	oldFilter := extProcOrderFilter("shared", "old", old, 0, "old", 0)
	oldFilter.TypeURL = "old-config"

	analysis := AnalyzeExtProcOrder(&Model{HTTP: []HTTPListener{{Routes: []HTTPRoute{
		{ExtensionRefFilters: []ExtensionRefFilter{newFilter}},
		{ExtensionRefFilters: []ExtensionRefFilter{oldFilter}},
	}}}})

	require.Len(t, analysis.Filters, 1)
	require.Equal(t, "old-config", analysis.Filters[0].TypeURL)
}

func extProcOrderFilter(name, routeName string, timestamp time.Time, ruleIndex int, uid string, matchIndex int) ExtensionRefFilter {
	return ExtensionRefFilter{
		Name:                         name,
		SourceRouteCreationTimestamp: timestamp,
		SourceRouteRule: &HTTPRouteRule{
			Source: FullyQualifiedResource{
				Name:      routeName,
				Namespace: "default",
				Kind:      "HTTPRoute",
				UID:       uid,
			},
			RuleIndex:  ruleIndex,
			MatchIndex: matchIndex,
		},
	}
}
