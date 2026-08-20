// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package model

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestOrderExtensionRefFilters(t *testing.T) {
	old := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		filters  []ExtensionRefFilter
		expected []string
	}{
		{
			name: "older source route wins a conflicting constraint",
			filters: []ExtensionRefFilter{
				extProcOrderFilter("beta", "new", newer, 0, 0, "new-uid", 0),
				extProcOrderFilter("alpha", "new", newer, 1, 1, "new-uid", 0),
				extProcOrderFilter("alpha", "old", old, 0, 0, "old-uid", 0),
				extProcOrderFilter("beta", "old", old, 1, 1, "old-uid", 0),
			},
			expected: []string{"alpha", "beta"},
		},
		{
			name: "duplicate matches from one source rule collapse",
			filters: []ExtensionRefFilter{
				extProcOrderFilter("alpha", "route", old, 0, 0, "uid", 0),
				extProcOrderFilter("beta", "route", old, 1, 0, "uid", 0),
				extProcOrderFilter("alpha", "route", old, 0, 0, "uid", 1),
				extProcOrderFilter("beta", "route", old, 1, 0, "uid", 1),
			},
			expected: []string{"alpha", "beta"},
		},
		{
			name: "repeated filter names within a rule collapse",
			filters: []ExtensionRefFilter{
				extProcOrderFilter("alpha", "route", old, 0, 0, "uid", 0),
				extProcOrderFilter("alpha", "route", old, 0, 1, "uid", 0),
				extProcOrderFilter("beta", "route", old, 1, 2, "uid", 0),
				extProcOrderFilter("beta", "route", old, 1, 3, "uid", 0),
			},
			expected: []string{"alpha", "beta"},
		},
		{
			name: "route UID is part of the conflict source identity",
			filters: []ExtensionRefFilter{
				// Put the route with UID uid-b first to ensure scan order alone
				// would select the opposite constraint.
				extProcOrderFilter("beta", "same-name", old, 0, 0, "uid-b", 0),
				extProcOrderFilter("alpha", "same-name", old, 1, 1, "uid-b", 0),
				extProcOrderFilter("alpha", "same-name", old, 0, 0, "uid-a", 0),
				extProcOrderFilter("beta", "same-name", old, 1, 1, "uid-a", 0),
			},
			expected: []string{"alpha", "beta"},
		},
		{
			name: "provenance sorts otherwise independent filters",
			filters: []ExtensionRefFilter{
				extProcOrderFilter("z-filter", "z-route", old, 0, 0, "z", 0),
				extProcOrderFilter("a-filter", "a-route", old, 0, 0, "a", 0),
			},
			expected: []string{"a-filter", "z-filter"},
		},
		{
			name: "missing provenance falls back to scan order",
			filters: []ExtensionRefFilter{
				{Name: "second"},
				{Name: "first"},
			},
			expected: []string{"second", "first"},
		},
		{
			name: "three-way cycles are resolved deterministically",
			filters: []ExtensionRefFilter{
				extProcOrderFilter("a", "old", old, 0, 0, "a", 0),
				extProcOrderFilter("b", "old", old, 1, 1, "a", 0),
				extProcOrderFilter("b", "middle", newer, 0, 0, "b", 0),
				extProcOrderFilter("c", "middle", newer, 1, 1, "b", 0),
				extProcOrderFilter("c", "new", newer.Add(time.Hour), 0, 0, "c", 0),
				extProcOrderFilter("a", "new", newer.Add(time.Hour), 1, 1, "c", 0),
			},
			expected: []string{"a", "b", "c"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := OrderExtensionRefFilters(tc.filters)
			gotNames := make([]string, len(got))
			for i := range got {
				gotNames[i] = got[i].Name
			}
			require.Equal(t, tc.expected, gotNames)
		})
	}
}

func TestOrderExtensionRefFiltersKeepsHighestPrecedenceRepresentative(t *testing.T) {
	old := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	filters := []ExtensionRefFilter{
		extProcOrderFilter("shared", "new", newer, 0, 0, "new", 0),
		extProcOrderFilter("shared", "old", old, 0, 0, "old", 0),
	}
	filters[0].TypeURL = "new-config"
	filters[1].TypeURL = "old-config"

	got := OrderExtensionRefFilters(filters)
	require.Len(t, got, 1)
	require.Equal(t, "old-config", got[0].TypeURL)
}

func TestAnalyzeExtProcOrderReportsLosingRouteAndKeepsUniqueFilters(t *testing.T) {
	old := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	newer := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	analysis := AnalyzeExtProcOrder(&Model{HTTP: []HTTPListener{{Routes: []HTTPRoute{
		{ExtensionRefFilters: []ExtensionRefFilter{
			extProcOrderFilter("alpha", "old", old, 0, 0, "old", 0),
			extProcOrderFilter("beta", "old", old, 0, 1, "old", 0),
		}},
		{ExtensionRefFilters: []ExtensionRefFilter{
			extProcOrderFilter("beta", "new", newer, 0, 0, "new", 0),
			extProcOrderFilter("alpha", "new", newer, 0, 1, "new", 0),
			extProcOrderFilter("only-losing", "new", newer, 0, 2, "new", 0),
		}},
	}}}})

	require.Equal(t, []string{"alpha", "beta", "only-losing"}, []string{
		analysis.Filters[0].Name,
		analysis.Filters[1].Name,
		analysis.Filters[2].Name,
	})
	require.Equal(t, []FullyQualifiedResource{{Name: "new", Namespace: "default", Kind: "HTTPRoute", UID: "new"}}, analysis.ConflictedRoutes)
}

func extProcOrderFilter(name, routeName string, timestamp time.Time, ruleIndex, filterIndex int, uid string, matchIndex int) ExtensionRefFilter {
	return ExtensionRefFilter{
		Name:                         name,
		SourceRouteCreationTimestamp: timestamp,
		SourceRouteFilterIndex:       filterIndex,
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
