// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package model

import "sort"

// ext_proc filter ordering.
//
// Envoy's HTTP filter chain belongs to the connection manager, so every route on
// a CEC shares one ext_proc filter order. Per-route configuration can enable,
// disable, or override a filter already in the chain, but cannot reorder it, so
// one order must satisfy every route at once.
//
// Each rule contributes its declared sequence as adjacency constraints, accepted
// atomically. A rule whose constraints would close a cycle keeps its filters in
// the chain but loses its ordering: a cycle means two rules demand opposite
// relative orders of the same filters, which no single chain satisfies.
//
// Rules are applied oldest-first, so conflicts resolve as they do elsewhere in
// Gateway API: creation timestamp, then namespace/name (see sortL4RoutesByAge and
// https://gateway-api.sigs.k8s.io/guides/api-design/#conflicts). Unlike the usual
// case, the loser is not discarded, only its ordering constraints are.
//
// ConflictedRoutes and ConflictedRules carry the losers to the Gateway API status
// layer, which maps them onto Route conditions.

// ExtProcOrderAnalysis is the result of analyzing ExtensionRef filter ordering
// across all HTTP routes in a model.
type ExtProcOrderAnalysis struct {
	// Filters is the deterministic HCM filter chain.
	Filters []ExtensionRefFilter
	// ConflictedRoutes contains routes whose ordering constraints could not be
	// added without introducing a cycle. Routes without provenance are not
	// included because they cannot be mapped back to Kubernetes status.
	ConflictedRoutes []FullyQualifiedResource
}

type extProcRuleSequence struct {
	source       FullyQualifiedResource
	hasSource    bool
	creationTime timeKey
	ruleIndex    int
	scanOrder    int
	filters      []ExtensionRefFilter
}

type timeKey struct {
	value int64
	nsec  int32
}

func (t timeKey) before(other timeKey) bool {
	if t.value != other.value {
		return t.value < other.value
	}
	return t.nsec < other.nsec
}

// AnalyzeExtProcOrder resolves ExtensionRef filter order as a set of compatible
// constraints. A rule's constraints are accepted atomically; a rule that would
// introduce a cycle loses its constraints, but its filters remain in the result.
func AnalyzeExtProcOrder(m *Model) ExtProcOrderAnalysis {
	if m == nil {
		return ExtProcOrderAnalysis{}
	}

	sequences := collectExtProcRuleSequences(m)
	if len(sequences) == 0 {
		return ExtProcOrderAnalysis{}
	}

	withProvenance := false
	for _, sequence := range sequences {
		withProvenance = withProvenance || sequence.hasSource
	}
	if withProvenance {
		sort.SliceStable(sequences, func(i, j int) bool {
			return extProcRuleSequenceLess(sequences[i], sequences[j])
		})
	}

	adjacency := map[string]map[string]struct{}{}
	firstOccurrence := map[string]int{}
	filters := map[string]ExtensionRefFilter{}
	occurrence := 0
	for _, sequence := range sequences {
		for _, filter := range sequence.filters {
			if _, ok := adjacency[filter.Name]; !ok {
				adjacency[filter.Name] = map[string]struct{}{}
			}
			if _, ok := firstOccurrence[filter.Name]; !ok {
				firstOccurrence[filter.Name] = occurrence
				filters[filter.Name] = filter
			}
			occurrence++
		}
	}

	var conflicts []FullyQualifiedResource
	seenConflicts := map[FullyQualifiedResource]struct{}{}
	for _, sequence := range sequences {
		candidate := adjacentExtProcEdges(sequence.filters)
		if len(candidate) == 0 {
			continue
		}

		copyAdjacency := cloneExtProcAdjacency(adjacency)
		for from, destinations := range candidate {
			if _, ok := copyAdjacency[from]; !ok {
				copyAdjacency[from] = map[string]struct{}{}
			}
			for to := range destinations {
				copyAdjacency[from][to] = struct{}{}
			}
		}

		if extProcGraphHasCycle(copyAdjacency) {
			if sequence.hasSource {
				if _, seen := seenConflicts[sequence.source]; !seen {
					seenConflicts[sequence.source] = struct{}{}
					conflicts = append(conflicts, sequence.source)
				}
			}
			continue
		}
		adjacency = copyAdjacency
	}

	orderedNames := stableExtProcTopologicalOrder(adjacency, firstOccurrence)
	orderedFilters := make([]ExtensionRefFilter, 0, len(orderedNames))
	for _, name := range orderedNames {
		orderedFilters = append(orderedFilters, filters[name])
	}
	return ExtProcOrderAnalysis{
		Filters:          orderedFilters,
		ConflictedRoutes: conflicts,
	}
}

func collectExtProcRuleSequences(m *Model) []extProcRuleSequence {
	sequences := make([]extProcRuleSequence, 0)
	byRule := map[extProcRuleKey]int{}
	scanOrder := 0

	for _, listener := range m.HTTP {
		for _, route := range listener.Routes {
			if len(route.ExtensionRefFilters) == 0 {
				continue
			}

			// A raw Gateway API rule is validated during ingestion before its
			// filters are copied to one model route per match. This normalization
			// remains necessary because repeated model routes from multiple
			// matches represent one source rule, not duplicate declarations.
			filters := deduplicateExtProcSequence(route.ExtensionRefFilters)
			source, hasSource := extProcRouteSource(filters[0])
			ruleIndex := extProcFilterRuleIndex(filters[0])
			if !hasSource {
				sequences = append(sequences, extProcRuleSequence{
					filters:   filters,
					scanOrder: scanOrder,
				})
				scanOrder++
				continue
			}

			key := extProcRuleKey{source: source, ruleIndex: ruleIndex}
			sequenceIndex, ok := byRule[key]
			if !ok {
				sequenceIndex = len(sequences)
				byRule[key] = sequenceIndex
				sequences = append(sequences, extProcRuleSequence{
					source:       source,
					hasSource:    true,
					creationTime: extProcCreationTime(filters[0]),
					ruleIndex:    ruleIndex,
					scanOrder:    scanOrder,
					filters:      filters,
				})
			} else {
				sequences[sequenceIndex].filters = mergeExtProcSequences(sequences[sequenceIndex].filters, filters)
			}
			scanOrder++
		}
	}
	return sequences
}

type extProcRuleKey struct {
	source    FullyQualifiedResource
	ruleIndex int
}

func extProcRouteSource(filter ExtensionRefFilter) (FullyQualifiedResource, bool) {
	if filter.SourceRouteRule == nil {
		return FullyQualifiedResource{}, false
	}
	return filter.SourceRouteRule.Source, true
}

func extProcFilterRuleIndex(filter ExtensionRefFilter) int {
	if filter.SourceRouteRule == nil {
		return 0
	}
	return filter.SourceRouteRule.RuleIndex
}

func extProcCreationTime(filter ExtensionRefFilter) timeKey {
	return timeKey{
		value: filter.SourceRouteCreationTimestamp.Unix(),
		nsec:  int32(filter.SourceRouteCreationTimestamp.Nanosecond()),
	}
}

func extProcRuleSequenceLess(a, b extProcRuleSequence) bool {
	if a.creationTime != b.creationTime {
		return a.creationTime.before(b.creationTime)
	}
	if a.source.Namespace != b.source.Namespace {
		return a.source.Namespace < b.source.Namespace
	}
	if a.source.Name != b.source.Name {
		return a.source.Name < b.source.Name
	}
	if a.source.Kind != b.source.Kind {
		return a.source.Kind < b.source.Kind
	}
	if a.source.UID != b.source.UID {
		return a.source.UID < b.source.UID
	}
	if a.ruleIndex != b.ruleIndex {
		return a.ruleIndex < b.ruleIndex
	}
	return a.scanOrder < b.scanOrder
}

func deduplicateExtProcSequence(filters []ExtensionRefFilter) []ExtensionRefFilter {
	result := make([]ExtensionRefFilter, 0, len(filters))
	seen := map[string]struct{}{}
	for _, filter := range filters {
		if _, ok := seen[filter.Name]; ok {
			continue
		}
		seen[filter.Name] = struct{}{}
		result = append(result, filter)
	}
	return result
}

func mergeExtProcSequences(existing, additional []ExtensionRefFilter) []ExtensionRefFilter {
	result := append([]ExtensionRefFilter(nil), existing...)
	seen := map[string]struct{}{}
	for _, filter := range result {
		seen[filter.Name] = struct{}{}
	}
	for _, filter := range additional {
		if _, ok := seen[filter.Name]; ok {
			continue
		}
		seen[filter.Name] = struct{}{}
		result = append(result, filter)
	}
	return result
}

func adjacentExtProcEdges(filters []ExtensionRefFilter) map[string]map[string]struct{} {
	edges := map[string]map[string]struct{}{}
	for index := 1; index < len(filters); index++ {
		from, to := filters[index-1].Name, filters[index].Name
		if from == to {
			continue
		}
		if edges[from] == nil {
			edges[from] = map[string]struct{}{}
		}
		edges[from][to] = struct{}{}
	}
	return edges
}

func cloneExtProcAdjacency(adjacency map[string]map[string]struct{}) map[string]map[string]struct{} {
	clone := make(map[string]map[string]struct{}, len(adjacency))
	for from, destinations := range adjacency {
		clone[from] = make(map[string]struct{}, len(destinations))
		for to := range destinations {
			clone[from][to] = struct{}{}
		}
	}
	return clone
}

func extProcGraphHasCycle(adjacency map[string]map[string]struct{}) bool {
	state := map[string]uint8{}
	var visit func(string) bool
	visit = func(node string) bool {
		switch state[node] {
		case 1:
			return true
		case 2:
			return false
		}
		state[node] = 1
		for next := range adjacency[node] {
			if visit(next) {
				return true
			}
		}
		state[node] = 2
		return false
	}

	for node := range adjacency {
		if state[node] == 0 && visit(node) {
			return true
		}
	}
	return false
}

func stableExtProcTopologicalOrder(adjacency map[string]map[string]struct{}, firstOccurrence map[string]int) []string {
	indegree := map[string]int{}
	for node := range adjacency {
		indegree[node] = 0
	}
	for _, destinations := range adjacency {
		for destination := range destinations {
			indegree[destination]++
		}
	}

	ready := make([]string, 0)
	for node, degree := range indegree {
		if degree == 0 {
			ready = append(ready, node)
		}
	}
	less := func(a, b string) bool {
		if firstOccurrence[a] != firstOccurrence[b] {
			return firstOccurrence[a] < firstOccurrence[b]
		}
		return a < b
	}
	result := make([]string, 0, len(indegree))
	for len(ready) > 0 {
		sort.Slice(ready, func(i, j int) bool { return less(ready[i], ready[j]) })
		node := ready[0]
		ready = ready[1:]
		result = append(result, node)
		for next := range adjacency[node] {
			indegree[next]--
			if indegree[next] == 0 {
				ready = append(ready, next)
			}
		}
	}
	return result
}
