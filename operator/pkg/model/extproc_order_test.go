// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package model

import (
	"slices"
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

func TestAnalyzeExtProcOrderEqualTimestampTies(t *testing.T) {
	tie := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	route := func(namespace, name string, timestamp time.Time, names ...string) HTTPRoute {
		var filters []ExtensionRefFilter
		for _, filterName := range names {
			filter := extProcOrderFilter(filterName, name, timestamp, 0, name, 0)
			filter.SourceRouteRule.Source.Namespace = namespace
			filters = append(filters, filter)
		}
		return HTTPRoute{ExtensionRefFilters: filters}
	}
	routes := []HTTPRoute{
		route("backend-b", "newest", tie.Add(time.Second), "newest-first", "newest-last"),
		route("backend-b", "b-tie", tie, "shared-b", "b-name-tie-last"),
		route("backend-b", "a-tie", tie, "b-tie-first", "shared-b", "b-tie-last"),
		route("backend-a", "a-tie", tie, "shared-a", "a-tie-last"),
		route("backend-a", "oldest", tie.Add(-time.Second), "oldest-first", "shared-a", "oldest-last"),
	}
	expected := []string{
		"oldest-first", "shared-a", "oldest-last", "a-tie-last",
		"b-tie-first", "shared-b", "b-tie-last", "b-name-tie-last",
		"newest-first", "newest-last",
	}

	for _, tc := range []struct {
		name    string
		reverse bool
	}{
		{name: "reverse precedence"},
		{name: "precedence", reverse: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := slices.Clone(routes)
			if tc.reverse {
				slices.Reverse(input)
			}
			analysis := AnalyzeExtProcOrder(&Model{HTTP: []HTTPListener{{Routes: input}}})
			var names []string
			for _, filter := range analysis.Filters {
				names = append(names, filter.Name)
			}
			require.Equal(t, expected, names)
			require.Empty(t, analysis.ConflictedRoutes)
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

func TestAnalyzeExtProcOrderComparisonTails(t *testing.T) {
	creation := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	filter := func(namespace, name, kind string, timestamp time.Time, ruleIndex int) ExtensionRefFilter {
		f := extProcOrderFilter("", name, timestamp, ruleIndex, "", 0)
		f.SourceRouteRule.Source.Namespace = namespace
		f.SourceRouteRule.Source.Kind = kind
		return f
	}
	sequence := func(f ExtensionRefFilter, names ...string) HTTPRoute {
		var route HTTPRoute
		for _, name := range names {
			f.Name = name
			route.ExtensionRefFilters = append(route.ExtensionRefFilters, f)
		}
		return route
	}

	tests := []struct {
		name          string
		first, second ExtensionRefFilter
		firstWins     bool
	}{
		{
			name:   "namespace prefixes compare separately from names",
			first:  filter("app-prod", "a", "HTTPRoute", creation, 0),
			second: filter("app", "z", "HTTPRoute", creation, 0),
		},
		{
			name:   "name breaks timestamp and namespace ties",
			first:  filter("app", "z", "HTTPRoute", creation, 0),
			second: filter("app", "a", "HTTPRoute", creation, 0),
		},
		{
			name:   "nanoseconds precede names",
			first:  filter("app", "a", "HTTPRoute", creation.Add(2*time.Nanosecond), 0),
			second: filter("app", "z", "HTTPRoute", creation.Add(time.Nanosecond), 0),
		},

		{
			name:   "kind breaks metadata ties",
			first:  filter("app", "route", "HTTPRoute", creation, 0),
			second: filter("app", "route", "GRPCRoute", creation, 0),
		},
		{
			name:   "rule index breaks source ties",
			first:  filter("app", "route", "HTTPRoute", creation, 1),
			second: filter("app", "route", "HTTPRoute", creation, 0),
		},
		{
			name:   "sourced zero time precedes unsourced epoch",
			first:  ExtensionRefFilter{},
			second: filter("app", "route", "HTTPRoute", time.Time{}, 0),
		},

		{
			name:      "equal unsourced keys keep input order in mixed input",
			first:     ExtensionRefFilter{},
			second:    ExtensionRefFilter{},
			firstWins: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.first.TypeURL, tc.second.TypeURL = "first-config", "second-config"
			routes := []HTTPRoute{
				sequence(tc.first, "beta", "alpha"),
				sequence(tc.second, "alpha", "beta"),
			}
			winner, loser := tc.second, tc.first
			names := []string{"alpha", "beta"}
			if tc.firstWins {
				winner, loser = tc.first, tc.second
				names = []string{"beta", "alpha"}
			}
			if tc.first.SourceRouteRule == nil && tc.second.SourceRouteRule == nil {
				routes = append(routes, HTTPRoute{ExtensionRefFilters: []ExtensionRefFilter{extProcOrderFilter("guard", "guard", creation, 0, "", 0)}})
				names = append(names, "guard")
			}
			analysis := AnalyzeExtProcOrder(&Model{HTTP: []HTTPListener{{Routes: routes}}})
			actualNames := make([]string, len(analysis.Filters))
			for i := range analysis.Filters {
				actualNames[i] = analysis.Filters[i].Name
			}
			require.Equal(t, names, actualNames)
			require.Equal(t, winner.TypeURL, analysis.Filters[0].TypeURL)
			require.Equal(t, winner.TypeURL, analysis.Filters[1].TypeURL)
			if loser.SourceRouteRule == nil {
				require.Empty(t, analysis.ConflictedRoutes)
			} else {
				require.Equal(t, []FullyQualifiedResource{loser.SourceRouteRule.Source}, analysis.ConflictedRoutes)
			}
		})
	}
}

func TestDeduplicateExtProcSequence(t *testing.T) {
	first := ExtensionRefFilter{Name: "beta", TypeURL: "first-config"}
	second := ExtensionRefFilter{Name: "alpha", TypeURL: "second-config"}
	duplicate := ExtensionRefFilter{Name: "beta", TypeURL: "duplicate-config"}
	third := ExtensionRefFilter{Name: "gamma", TypeURL: "third-config"}
	backing := []ExtensionRefFilter{first, second, duplicate, third, {Name: "sentinel"}}

	tests := []struct {
		name              string
		filters, expected []ExtensionRefFilter
	}{
		{name: "singleton is owned", filters: []ExtensionRefFilter{first}, expected: []ExtensionRefFilter{first}},

		{name: "nonadjacent duplicates keep first config", filters: backing[:4], expected: []ExtensionRefFilter{first, second, third}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := slices.Clone(tc.filters[:cap(tc.filters)])
			result := deduplicateExtProcSequence(tc.filters)
			require.Equal(t, tc.expected, result)
			require.Equal(t, before, tc.filters[:cap(tc.filters)])
			result[0].TypeURL = "changed-config"
			require.Equal(t, before, tc.filters[:cap(tc.filters)])
		})
	}
}

func TestMergeExtProcSequences(t *testing.T) {
	first := ExtensionRefFilter{Name: "beta", TypeURL: "existing-config"}
	second := ExtensionRefFilter{Name: "alpha", TypeURL: "additional-config"}
	duplicate := ExtensionRefFilter{Name: "beta", TypeURL: "duplicate-config"}
	third := ExtensionRefFilter{Name: "gamma", TypeURL: "third-config"}
	backing := []ExtensionRefFilter{first, second, duplicate, third, {Name: "sentinel"}}
	before := slices.Clone(backing)

	result := mergeExtProcSequences(backing[:1], backing[1:4])
	require.Equal(t, []ExtensionRefFilter{first, second, third}, result)
	require.Equal(t, before, backing)
	result[0].TypeURL = "changed-existing-config"
	result[1].TypeURL = "changed-additional-config"
	require.Equal(t, before, backing)
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
