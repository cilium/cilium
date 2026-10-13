// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"maps"
	"slices"

	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	cache_types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	cache "github.com/envoyproxy/go-control-plane/pkg/cache/v3"

	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

// ResourceScope identifies the resource revisions required by a wait. The
// common single-resource scope is inline. A zero scope is an explicit wait for
// the whole type, not evidence that a partial response covers that type.
type ResourceScope struct {
	name     string
	revision Revision
	more     map[string]Revision
}

func SingleResourceScope(name string, revision Revision) ResourceScope {
	return ResourceScope{name: name, revision: revision}
}

// OnlyRemovals classifies named requirements against desired state while the
// cache lock is held, before registration. Whole-type waits retain ordinary
// NACK failure handling. The resulting policy stays fixed for the caller wait.
func (scope *ResourceScope) OnlyRemovals(isRemoved func(string) bool) bool {
	if scope.name != "" {
		return isRemoved(scope.name)
	}
	for name := range scope.more {
		if !isRemoved(name) {
			return false
		}
	}
	return len(scope.more) != 0
}

// WithRevisions advances requirements after the cache commits prepared changes.
// A removal has no desired entry, so its prepared revision must not be lowered
// to zero or to an older acceptance fence when no rollback state is retained.
// The scope is owned by one wait and is not published until this returns.
func (scope ResourceScope) WithRevisions(revisionFor func(string) Revision) ResourceScope {
	if scope.name != "" {
		revision := revisionFor(scope.name)
		if revision.revision > scope.revision.revision {
			scope.revision = revision
		}
	}
	for name, required := range scope.more {
		revision := revisionFor(name)
		if revision.revision > required.revision {
			scope.more[name] = revision
		}
	}
	return scope
}

func (scope *ResourceScope) Insert(name string, revision Revision) {
	if scope.name == "" && scope.more == nil {
		scope.name, scope.revision = name, revision
		return
	}
	if scope.more == nil {
		if scope.name == name {
			scope.revision = revision
			return
		}
		scope.more = map[string]Revision{scope.name: scope.revision}
		scope.name = ""
	}
	scope.more[name] = revision
}

func (scope *ResourceScope) wholeType() bool {
	return scope != nil && scope.name == "" && scope.more == nil
}

func (scope *ResourceScope) coveredBy(coverage *responseCoverage, generation Generation) bool {
	if scope == nil {
		return false
	}
	if scope.wholeType() {
		return coverage == nil || coverage.complete()
	}
	if scope.name != "" {
		return scope.revision.revision <= generation && coverage.contains(scope.name)
	}
	for name, required := range scope.more {
		if required.revision > generation || !coverage.contains(name) {
			return false
		}
	}
	return true
}

func (scope *ResourceScope) intersects(coverage *responseCoverage, generation Generation) bool {
	if scope == nil {
		return false
	}
	if scope.wholeType() {
		return coverage == nil || coverage.complete()
	}
	if scope.name != "" {
		return scope.revision.revision <= generation && coverage.contains(scope.name)
	}
	for name, required := range scope.more {
		if required.revision <= generation && coverage.contains(name) {
			return true
		}
	}
	return false
}

// acknowledge consumes just the requirements represented by this response.
// Return true only when every requirement has been met. The caller removes
// the completed wait immediately, so the zero value need not encode completion.
func (scope *ResourceScope) acknowledge(coverage *responseCoverage, generation Generation) bool {
	if scope.wholeType() || scope.name != "" {
		return scope.coveredBy(coverage, generation)
	}
	for name, required := range scope.more {
		if required.revision <= generation && coverage.contains(name) {
			delete(scope.more, name)
		}
	}
	return len(scope.more) == 0
}

// acknowledgeRemovals accepts absence proofs, including synthesized empty CLAs.
// A positive resource can resolve a superseded removal only from the wait's
// publication onward. This prevents a delayed response containing an older
// live value from completing a repeated removal after its desired entry is removed.
func (scope *ResourceScope) acknowledgeRemovals(coverage *responseCoverage, generation, minimumPresentGeneration Generation) bool {
	covered := func(name string, revision Revision) bool {
		if revision.revision > generation || !coverage.contains(name) {
			return false
		}
		if generation >= minimumPresentGeneration || coverage == nil || coverage.resources[name].Resource == nil {
			return true
		}
		if coverage.typeURL == typeurl.Endpoint {
			assignment, ok := coverage.resources[name].Resource.(*endpoint.ClusterLoadAssignment)
			return ok && len(assignment.GetEndpoints()) == 0
		}
		return false
	}
	if scope.wholeType() {
		return scope.coveredBy(coverage, generation)
	}
	if scope.name != "" {
		return covered(scope.name, scope.revision)
	}
	for name, required := range scope.more {
		if covered(name, required) {
			delete(scope.more, name)
		}
	}
	return len(scope.more) == 0
}

// acknowledgeAcceptedRollback preserves ACKs which arrived while a failed
// revert ran outside the callback mutex. A newer accepted group generation
// alone proves nothing about names omitted from that response.
func (scope *ResourceScope) acknowledgeAcceptedRollback(group acceptedResourceGroup, index typeurl.Index, generation Generation) bool {
	if scope == nil {
		return false
	}
	if scope.wholeType() {
		return group.generation >= generation && len(group.requested) == 0 && typeHasDeletionSemantics(index)
	}
	if scope.name != "" {
		_, _, accepted := group.resource(scope.name, index)
		return accepted != 0 && scope.revision.revision <= accepted
	}
	for name, required := range scope.more {
		_, _, accepted := group.resource(name, index)
		if accepted != 0 && required.revision <= accepted {
			delete(scope.more, name)
		}
	}
	return len(scope.more) == 0
}

type responseCoverageContextKey struct{}

type snapshotPublication struct {
	generation Generation
	snapshot   cache.ResourceSnapshot
}

// WithSnapshotPublication retains the exact publication while go-control-plane
// constructs responses. Keep generation and resources in one context value:
// publication need not allocate a second context just to capture response coverage.
// Each delivered response's coverage retains only its own TypeURL group.
func WithSnapshotPublication(ctx context.Context, generation Generation, snapshot cache.ResourceSnapshot) context.Context {
	return context.WithValue(ctx, snapshotGenerationContextKey{}, &snapshotPublication{generation: generation, snapshot: snapshot})
}

// responseCoverage is immutable. A nil returned map means every resource in
// resources was delivered. Partial responses own a name map: go-control-plane
// may subsequently mutate its returned-resource map when a subscription changes.
type responseCoverage struct {
	resources map[string]cache_types.ResourceWithTTL
	returned  map[string]string
	requested []string
	typeURL   typeurl.Index
}

func (coverage *responseCoverage) complete() bool {
	return coverage == nil || (coverage.returned == nil && len(coverage.requested) == 0)
}

func (coverage *responseCoverage) contains(name string) bool {
	if coverage == nil {
		// Transport-only callback tests have no cache response metadata.
		return true
	}
	if coverage.returned != nil {
		if _, found := coverage.returned[name]; found {
			return true
		}
	} else if _, found := coverage.resources[name]; found {
		return true
	}
	// Omission conveys removal for LDS/CDS and Cilium's full-state policy APIs,
	// but not for SotW EDS/RDS/SDS. An empty EDS response is not a deletion ACK.
	if !typeHasDeletionSemantics(coverage.typeURL) {
		return false
	}
	return len(coverage.requested) == 0 || slices.Contains(coverage.requested, name)
}

func typeHasDeletionSemantics(index typeurl.Index) bool {
	return index == typeurl.Listener || index == typeurl.Cluster ||
		index == typeurl.NetworkPolicy || index == typeurl.NetworkPolicyHosts
}

// WithResponseCoverage captures the actual SotW response, not the resource
// names in the eventual ACK request. RawResponse.GetReturnedResources names
// the resources in this response; Delta's cumulative version map must not be
// used this way. No protobuf is decoded, copied, or marshaled here.
func WithResponseCoverage(response cache.Response, generation Generation, snapshot cache.ResourceSnapshot) cache.Response {
	response = WithResponseGeneration(response, generation)
	ctx := response.GetContext()
	if published, ok := ctx.Value(snapshotGenerationContextKey{}).(*snapshotPublication); ok {
		snapshot = published.snapshot
	}
	if snapshot == nil {
		return response
	}
	index, supported := typeurl.FromURL(response.GetRequest().GetTypeUrl())
	if !supported {
		return response
	}
	coverage := &responseCoverage{
		resources: snapshot.GetResourcesAndTTL(index.URL()),
		requested: slices.Clone(response.GetRequest().GetResourceNames()),
		typeURL:   index,
	}
	returned := response.GetReturnedResources()
	if len(returned) != len(coverage.resources) {
		coverage.returned = maps.Clone(returned)
		if coverage.returned == nil {
			coverage.returned = map[string]string{}
		}
	}
	return &generationResponse{Response: response, ctx: context.WithValue(ctx, responseCoverageContextKey{}, coverage)}
}

func responseCoverageFromContext(ctx context.Context) *responseCoverage {
	coverage, _ := ctx.Value(responseCoverageContextKey{}).(*responseCoverage)
	return coverage
}

// ResponseCoversResource is used under the cache lock to freeze only inverse
// entries communicated by this exact response. Caller removal waits are
// tracked separately from response-owned recovery.
// The transaction must be within the response boundary and its name must be
// represented; numerical ordering alone does not prove resource coverage.
func ResponseCoversResource(response cache.Response, name string, transaction TransactionID) bool {
	ctx := response.GetContext()
	return transaction.transaction <= snapshotGenerationFromContext(ctx) && responseCoverageFromContext(ctx).contains(name)
}

func ResponseCoversType(response cache.Response, generation Generation) bool {
	ctx := response.GetContext()
	return generation <= snapshotGenerationFromContext(ctx) && responseCoverageFromContext(ctx).complete()
}

type acceptedResource struct {
	resource cache_types.ResourceWithTTL
	// generation is the ACKed response boundary, not the resource's revision.
	generation Generation
}

func (group acceptedResourceGroup) resource(name string, index typeurl.Index) (cache_types.ResourceWithTTL, bool, Generation) {
	if accepted, exists := group.partial[name]; exists {
		return accepted.resource, accepted.resource.Resource != nil, accepted.generation
	}
	resource, exists := group.resources[name]
	if !exists && (!typeHasDeletionSemantics(index) ||
		(len(group.requested) != 0 && !slices.Contains(group.requested, name))) {
		return cache_types.ResourceWithTTL{}, false, 0
	}
	return resource, exists, group.generation
}

func (group *acceptedResourceGroup) acknowledge(coverage *responseCoverage, generation Generation) {
	if coverage.returned == nil && generation >= group.generation {
		group.generation = generation
		group.resources = coverage.resources
		group.requested = coverage.requested
		for name, accepted := range group.partial {
			if accepted.generation <= generation {
				delete(group.partial, name)
			}
		}
		if len(group.partial) == 0 {
			group.partial = nil
		}
		return
	}
	for name := range coverage.returned {
		group.acceptResource(name, coverage.resources[name], generation)
	}
	if typeHasDeletionSemantics(coverage.typeURL) {
		for _, name := range coverage.requested {
			if _, exists := coverage.resources[name]; !exists {
				group.acceptResource(name, cache_types.ResourceWithTTL{}, generation)
			}
		}
	}
}

func (group *acceptedResourceGroup) acceptResource(name string, resource cache_types.ResourceWithTTL, generation Generation) {
	if previous, exists := group.partial[name]; exists && previous.generation > generation {
		return
	}
	if group.generation > generation {
		return
	}
	if group.partial == nil {
		group.partial = make(map[string]acceptedResource)
	}
	group.partial[name] = acceptedResource{resource: resource, generation: generation}
}
