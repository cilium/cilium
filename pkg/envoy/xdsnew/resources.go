// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"errors"
	"iter"

	cache_types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/envoy/xds"
	callbacks "github.com/cilium/cilium/pkg/envoy/xdsnew/callbacks"
	"github.com/cilium/cilium/pkg/envoy/xdsnew/typeurl"
)

// ResourceMutations is a sparse transaction for Envoy's Listener, Route,
// Cluster, Endpoint, and Secret resources. NPDS/NPHDS are updated only through
// the single-resource API, so they cannot share a transaction with a Listener.
// Unchanged resource maps remain nil. Keeping the Resources values inline lets
// callers keep the sparse headers on their stack; only referenced maps escape.
type ResourceMutations struct {
	Removed  xds.Resources
	Upserted xds.Resources
}

// resourceEntry keeps the immutable protobuf, its current revision, and its
// originating API transaction together. A nil resource is a removal tombstone;
// retaining its transaction makes remove/recreate/remove ABA sequences safe.
// Entries are stored by value, keeping the resource interface and metadata
// inline rather than allocating an entry wrapper.
type resourceEntry struct {
	// resource refers to the immutable protobuf; storing or copying an entry
	// does not copy that protobuf.
	resource cache_types.Resource
	// revision identifies the current named value, including its absence.
	// It advances on every semantic change or deletion, whether made by an API
	// transaction or a revert, and never rolls back when restoring an older value.
	revision callbacks.Revision
	// transaction identifies the API transaction which originally inserted or
	// deleted this value. API changes use the same number as revision; reverts
	// restore it with the previous value while assigning a fresh revision.
	// Zero in an inverse entry records that no cached entry existed.
	transaction callbacks.TransactionID
}

// resourceMaps groups revision-tagged entries by TypeURL. Desired state and
// sparse resource containers share this layout, but own their maps independently.
// The zero value has no entries; each resource type's map is allocated on demand.
type resourceMaps typeurl.Slots[map[string]resourceEntry]

// commitEntry applies an entry to desired state. A nil value with transaction
// zero restores prior absence without retaining a tombstone, even with a fresh
// revision. Inverse containers must store zero entries explicitly, since they
// record which resources were previously absent.
func (resources *resourceMaps) commitEntry(typeURL typeurl.Index, name string, entry resourceEntry) {
	if entry.resource == nil && entry.transaction.IsZero() {
		delete(resources[typeURL], name)
	} else {
		if resources[typeURL] == nil {
			resources[typeURL] = make(map[string]resourceEntry)
		}
		resources[typeURL][name] = entry
	}
}

// resources keeps a single entry inline and uses resourceMaps for larger
// collections. The representations are mutually exclusive. An entry may be zero
// to record prior absence, so presence is determined by its name, not its value.
type resources struct {
	entries   resourceMaps
	singleton singletonResource
}

type singletonResource struct {
	name    string
	entry   resourceEntry
	typeURL typeurl.Index
}

func singleResource(typeURL typeurl.Index, name string, entry resourceEntry) resources {
	return resources{singleton: singletonResource{
		name:    name,
		entry:   entry,
		typeURL: typeURL,
	}}
}

func (r *resources) get(typeURL typeurl.Index, name string) (resourceEntry, bool) {
	if r.hasSingleton() {
		if r.singleton.typeURL == typeURL && r.singleton.name == name {
			return r.singleton.entry, true
		}
		return resourceEntry{}, false
	}
	entry, exists := r.entries[typeURL][name]
	return entry, exists
}

func (r *resources) hasSingleton() bool {
	return r.singleton.name != ""
}

func (r *resources) len(typeURL typeurl.Index) int {
	if r.hasSingleton() {
		if r.singleton.typeURL == typeURL {
			return 1
		}
		return 0
	}
	return len(r.entries[typeURL])
}

func (r *resources) resources(typeURL typeurl.Index) iter.Seq2[string, resourceEntry] {
	return func(yield func(string, resourceEntry) bool) {
		if r.hasSingleton() {
			if r.singleton.typeURL == typeURL {
				yield(r.singleton.name, r.singleton.entry)
			}
			return
		}
		for name, entry := range r.entries[typeURL] {
			if !yield(name, entry) {
				return
			}
		}
	}
}

func (r *resources) empty() bool {
	if r.hasSingleton() {
		return false
	}
	for typeURL := range typeurl.Indices() {
		if len(r.entries[typeURL]) != 0 {
			return false
		}
	}
	return true
}

// resourceChange is one semantic change to the cache-private desired state.
// The protobufs are immutable; a nil next.resource removes the named resource.
// API updates assign the same fresh revision and transaction; rollback restores
// the previous transaction but assigns a fresh revision before committing.
// previous also permits recovery if snapshot publication fails.
type resourceChange struct {
	typeURL  typeurl.Index
	name     string
	previous resourceEntry
	next     resourceEntry
}

// resourceChanges keeps the common single-resource transaction inline. Bulk
// transactions use one slice instead of separate removed and upserted maps
// for every resource type. Empty names are rejected at the API
// boundary, so the first change's name also indicates whether it is present.
type resourceChanges struct {
	first resourceChange
	more  []resourceChange
	types typeurl.Set
}

func (changes *resourceChanges) add(typeURL typeurl.Index, name string, previous, next resourceEntry) {
	change := resourceChange{typeURL: typeURL, name: name, previous: previous, next: next}
	if changes.first.name == "" {
		changes.first = change
	} else {
		changes.more = append(changes.more, change)
	}
	changes.types.Insert(typeURL)
}

func (changes resourceChanges) empty() bool {
	return changes.first.name == ""
}

func (changes resourceChanges) hasRemovals() bool {
	if !changes.empty() && changes.first.next.resource == nil {
		return true
	}
	for _, change := range changes.more {
		if change.next.resource == nil {
			return true
		}
	}
	return false
}

func (changes resourceChanges) typeURLs() typeurl.Set {
	return changes.types
}

func (changes resourceChanges) affectsStrictConsistency() bool {
	return changes.types.Has(typeurl.Listener) || changes.types.Has(typeurl.Route) ||
		changes.types.Has(typeurl.Cluster) || changes.types.Has(typeurl.Endpoint)
}

func (changes resourceChanges) inverse() resources {
	if changes.empty() {
		return resources{}
	}
	if len(changes.more) == 0 {
		return singleResource(changes.first.typeURL, changes.first.name, changes.first.previous)
	}
	var inverse resources
	add := func(change resourceChange) {
		entries := inverse.entries[change.typeURL]
		if entries == nil {
			entries = make(map[string]resourceEntry)
			inverse.entries[change.typeURL] = entries
		}
		entries[change.name] = change.previous
	}
	add(changes.first)
	for _, change := range changes.more {
		add(change)
	}
	return inverse
}

func resourceValue[V interface {
	proto.Message
	comparable
}](resource V) cache_types.Resource {
	var zero V
	if resource == zero {
		return nil
	}
	return resource
}

func typedResource[V proto.Message](resource cache_types.Resource) V {
	if resource == nil {
		var zero V
		return zero
	}
	return resource.(V)
}

func prepareResourceMap[V interface {
	proto.Message
	comparable
}](changes *resourceChanges, typeURL typeurl.Index, generation callbacks.Generation, current map[string]resourceEntry, removed, upserted map[string]V) {
	for name := range removed {
		if _, replaced := upserted[name]; replaced {
			continue
		}
		old := current[name]
		if old.resource != nil {
			changes.add(typeURL, name, old, resourceEntry{revision: generation.Revision(), transaction: generation.TransactionID()})
		}
	}
	for name, resource := range upserted {
		old := current[name]
		desired := resourceValue(resource)
		if old.resource == desired ||
			(old.resource != nil && desired != nil && xds.ResourceEqual(old.resource, desired)) {
			continue
		}
		changes.add(typeURL, name, old, resourceEntry{resource: desired, revision: generation.Revision(), transaction: generation.TransactionID()})
	}
}

var errEmptyName = errors.New("resource name must not be empty")

func validateResourceMapNames[V any](removed, upserted map[string]V) error {
	if _, exists := removed[""]; exists {
		return errEmptyName
	}
	if _, exists := upserted[""]; exists {
		return errEmptyName
	}
	return nil
}

// set extends or replaces a prepared response rollback without adding a second
// change for the same name. previous remains the original desired entry so
// validation, commit, and publication-failure recovery each see one transition.
func (changes *resourceChanges) set(typeURL typeurl.Index, name string, previous, next resourceEntry) {
	if changes.first.typeURL == typeURL && changes.first.name == name {
		changes.first.next = next
		return
	}
	for i := range changes.more {
		if changes.more[i].typeURL == typeURL && changes.more[i].name == name {
			changes.more[i].next = next
			return
		}
	}
	changes.add(typeURL, name, previous, next)
}

// resourceAfter returns the proposed value without committing the rollback.
// Names not affected by the prepared changes retain their current value.
func (changes resourceChanges) resourceAfter(typeURL typeurl.Index, name string, current cache_types.Resource) cache_types.Resource {
	if changes.first.typeURL == typeURL && changes.first.name == name {
		return changes.first.next.resource
	}
	for _, change := range changes.more {
		if change.typeURL == typeURL && change.name == name {
			return change.next.resource
		}
	}
	return current
}

func validateResourceMutations(mutations ResourceMutations) error {
	removed, upserted := mutations.Removed, mutations.Upserted
	if err := validateResourceMapNames(removed.Listeners, upserted.Listeners); err != nil {
		return err
	}
	if err := validateResourceMapNames(removed.Routes, upserted.Routes); err != nil {
		return err
	}
	if err := validateResourceMapNames(removed.Clusters, upserted.Clusters); err != nil {
		return err
	}
	if err := validateResourceMapNames(removed.Endpoints, upserted.Endpoints); err != nil {
		return err
	}
	if err := validateResourceMapNames(removed.Secrets, upserted.Secrets); err != nil {
		return err
	}
	return nil
}
