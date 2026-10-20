// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"context"
	"maps"
	"slices"

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

// WithRevisions fills revisions after the cache commits its prepared changes.
// The scope is owned by one wait and is not published until this returns.
func (scope ResourceScope) WithRevisions(revisionFor func(string) Revision) ResourceScope {
	if scope.name != "" {
		scope.revision = revisionFor(scope.name)
	}
	for name := range scope.more {
		scope.more[name] = revisionFor(name)
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

// intersectsChanges is the rejection counterpart of intersects. A wildcard
// Delta ACK reconciles unchanged resources from the client's version map, but
// a NACK can reject only updates and removals carried by that response.
func (scope *ResourceScope) intersectsChanges(coverage *responseCoverage, generation Generation) bool {
	if coverage == nil || !coverage.delta {
		return scope.intersects(coverage, generation)
	}
	if scope == nil {
		return false
	}
	if scope.wholeType() {
		return len(coverage.returned) != 0
	}
	if scope.name != "" {
		return scope.revision.revision <= generation && coverage.containsChange(scope.name)
	}
	for name, required := range scope.more {
		if required.revision <= generation && coverage.containsChange(name) {
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

// ResponseMetadata is the common context-bearing portion of SotW and Delta
// cache responses used by generation and rollback bookkeeping.
type ResponseMetadata interface {
	GetContext() context.Context
}

// responseCoverage is immutable. A nil returned map means every resource in
// resources was delivered. Partial responses own a name map: go-control-plane
// may subsequently mutate its returned-resource map when a subscription changes.
type responseCoverage struct {
	resources map[string]cache_types.ResourceWithTTL
	returned  map[string]string
	requested []string
	typeURL   typeurl.Index
	delta     bool
	full      bool
}

func (coverage *responseCoverage) complete() bool {
	return coverage == nil || coverage.full || (coverage.returned == nil && len(coverage.requested) == 0)
}

func (coverage *responseCoverage) contains(name string) bool {
	if coverage == nil {
		// Transport-only callback tests have no cache response metadata.
		return true
	}
	if coverage.delta && coverage.full {
		// Applying a wildcard Delta response reconciles the complete snapshot:
		// unchanged names came from the client's initial/returned version map.
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

// containsChange reports whether this response explicitly carries a resource
// update or removal. Unlike contains, it does not treat a wildcard Delta
// response as covering unchanged resources inherited from the client's version
// map. Rollback ownership must be limited to changes the response can NACK.
func (coverage *responseCoverage) containsChange(name string) bool {
	if coverage == nil {
		// Transport-only callback tests have no cache response metadata.
		return true
	}
	if coverage.delta {
		_, found := coverage.returned[name]
		return found
	}
	return coverage.contains(name)
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

type generationDeltaResponse struct {
	cache.DeltaResponse
	ctx context.Context
}

func (response *generationDeltaResponse) GetContext() context.Context {
	return response.ctx
}

// WithDeltaResponseCoverage captures the names actually changed or removed by
// a Delta response. GetReturnedResources is cumulative, so compare it with the
// subscription's pre-response map instead of treating the whole map as payload.
func WithDeltaResponseCoverage(response cache.DeltaResponse, generation Generation, snapshot cache.ResourceSnapshot, subscription cache.Subscription) cache.DeltaResponse {
	ctx := response.GetContext()
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Value(snapshotGenerationContextKey{}) == nil {
		ctx = WithSnapshotGeneration(ctx, generation)
	}
	if published, ok := ctx.Value(snapshotGenerationContextKey{}).(*snapshotPublication); ok {
		snapshot = published.snapshot
	}
	if snapshot == nil || subscription == nil {
		return &generationDeltaResponse{DeltaResponse: response, ctx: ctx}
	}
	index, supported := typeurl.FromURL(response.GetDeltaRequest().GetTypeUrl())
	if !supported {
		return &generationDeltaResponse{DeltaResponse: response, ctx: ctx}
	}
	previous := subscription.ReturnedResources()
	next := response.GetReturnedResources()
	changed := make(map[string]string)
	for name, version := range next {
		if oldVersion, exists := previous[name]; !exists || oldVersion != version {
			changed[name] = version
		}
	}
	subscribed := subscription.SubscribedResources()
	for name := range previous {
		if _, exists := next[name]; exists {
			continue
		}
		// Removing a name only from the subscription is not an xDS removal.
		if subscription.IsWildcard() {
			changed[name] = ""
		} else if _, stillSubscribed := subscribed[name]; stillSubscribed {
			changed[name] = ""
		}
	}
	coverage := &responseCoverage{
		resources: snapshot.GetResourcesAndTTL(index.URL()),
		returned:  changed,
		typeURL:   index,
		delta:     true,
		full:      subscription.IsWildcard(),
	}
	ctx = context.WithValue(ctx, responseCoverageContextKey{}, coverage)
	return &generationDeltaResponse{DeltaResponse: response, ctx: ctx}
}

func responseCoverageFromContext(ctx context.Context) *responseCoverage {
	coverage, _ := ctx.Value(responseCoverageContextKey{}).(*responseCoverage)
	return coverage
}

// ResponseCoversResource is used under the cache lock to freeze only inverse
// entries which this exact response can test, including observable removals.
// The transaction must be within the response boundary and its name must be
// represented; numerical ordering alone does not prove resource coverage.
func ResponseCoversResource(response ResponseMetadata, name string, transaction TransactionID) bool {
	ctx := response.GetContext()
	return transaction.transaction <= snapshotGenerationFromContext(ctx) && responseCoverageFromContext(ctx).containsChange(name)
}

func ResponseCoversType(response ResponseMetadata, generation Generation) bool {
	ctx := response.GetContext()
	coverage := responseCoverageFromContext(ctx)
	// A wildcard Delta response reconciles the complete client state, but only
	// its explicit changes can be rejected. Claim rollback per resource below.
	return generation <= snapshotGenerationFromContext(ctx) && (coverage == nil || !coverage.delta) && coverage.complete()
}

// SnapshotResourceStateIsObservable reports whether SotW can communicate this
// name's presence or removal in the snapshot. EDS/RDS/SDS omission is not a
// removal, so an absent name must not acquire response-owned recovery state.
func SnapshotResourceStateIsObservable(snapshot cache.ResourceSnapshot, index typeurl.Index, name string) bool {
	if typeHasDeletionSemantics(index) {
		return true
	}
	_, exists := snapshot.GetResourcesAndTTL(index.URL())[name]
	return exists
}

// ResourceStateIsObservable reports whether SotW responses from the source
// snapshot can communicate this resource's presence or removal. An absent name
// is observable only for types where omission means removal, not EDS/RDS/SDS.
//
// It ignores which names this response delivered: unrequested resources
// can still require a later partial response. ResponseCoversResource
// checks actual coverage and generation. Missing metadata is conservatively
// treated as observable.
func ResourceStateIsObservable(response ResponseMetadata, name string) bool {
	coverage := responseCoverageFromContext(response.GetContext())
	if coverage != nil && coverage.delta {
		return coverage.containsChange(name)
	}
	if coverage == nil || typeHasDeletionSemantics(coverage.typeURL) {
		return true
	}
	_, exists := coverage.resources[name]
	return exists
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
	if !exists && ((!group.delta && !typeHasDeletionSemantics(index)) ||
		(len(group.requested) != 0 && !slices.Contains(group.requested, name))) {
		return cache_types.ResourceWithTTL{}, false, 0
	}
	return resource, exists, group.generation
}

func (group *acceptedResourceGroup) acknowledge(coverage *responseCoverage, generation Generation) {
	if coverage.delta && coverage.full {
		group.generation = generation
		group.resources = coverage.resources
		group.requested = nil
		group.partial = nil
		group.delta = true
		return
	}
	if coverage.returned == nil && generation >= group.generation {
		group.generation = generation
		group.resources = coverage.resources
		group.requested = coverage.requested
		group.delta = false
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
