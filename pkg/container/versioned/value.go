// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package versioned

import (
	"errors"
	"math"
	"runtime"
	"slices"
	"sync/atomic"

	"github.com/hashicorp/go-hclog"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type version uint64

const (
	// invalidVersion is never found from the value range.
	// Also used as the upper bound for new values, so that the value is
	// found when looking with 'maxVersion'
	invalidVersion = version(math.MaxUint64)

	// maxVersion in a VersionHold finds the latest version of all non-removed values
	maxVersion = version(math.MaxUint64 - 1)
)

// KeepVersion is an exported version type used when releasing memory held for old versions.
type KeepVersion version

// NextVersion is an exported version type used to add or remove new versions of values.
type NextVersion version

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "versioned")

	errInvalidVersion  = errors.New("invalid version")
	errStaleVersion    = errors.New("stale version")
	errVersionNotFound = errors.New("version not found")
)

// VersionHold is used to keep values valid for a specific version from being released, so that they
// are available for use for as long as the VersionHold is not closed.
//
// A special form with a nil manager, which is returned by Latest(), always finds the latest
// versions and does not keep any versions from being released.
type VersionHold struct {
	// 'version' is the version this VersionHold keeps from being released
	version version
	// Manager of this VersionHold, if any. Used for closing if non-nil.
	// Atomic due to nilling and for copy prevention.
	manager atomic.Pointer[Manager]
}

// versionHoldFinalizer is used to warn about missing Close() calls.
func versionHoldFinalizer(h *VersionHold) {
	log.Errorf("Hold for SelectorCache version %d not closed.", h.version)
	h.Close()
}

func newVersionHold(version version, manager *Manager) *VersionHold {
	// hold on maxVersion never expires
	if version == maxVersion {
		manager = nil
	}
	h := &VersionHold{version: version}
	h.manager.Store(manager)
	if manager != nil {
		// Set a finalizer to catch unclosed holds. The finalizer function complains
		// loudly, so that we do not rely the finalizer for closing.
		runtime.SetFinalizer(h, versionHoldFinalizer)
	}
	return h
}

// Latest returns a VersionHold for the latest version of current/non-removed values
// Only to be used in cases where the latest values are needed and no transactionality is required.
func Latest() *VersionHold {
	return newVersionHold(maxVersion, nil)
}

func (h *VersionHold) IsValid() bool {
	return h != nil && (h.version == maxVersion || h.manager.Load() != nil)
}

func (h *VersionHold) Close() (err error) {
	if !h.IsValid() {
		return errInvalidVersion
	}
	manager := h.manager.Load()
	if manager != nil {
		runtime.SetFinalizer(h, nil)
		err = manager.releaseVersion(h.version)
		h.manager.Store(nil)
	}
	return err
}

type atomicVersion struct {
	version atomic.Uint64
}

func (a *atomicVersion) load() version {
	return version(a.version.Load())
}

func (a *atomicVersion) store(version version) {
	a.version.Store(uint64(version))
}

func (a *atomicVersion) compareAndSwap(old, new version) bool {
	return a.version.CompareAndSwap(uint64(old), uint64(new))
}

type versionCount struct {
	version version
	count   int
}

// Manager defines a common version number space for multiple versioned.Values,
// and provides facilities for cleaning out stale versions.
type Manager struct {
	version atomicVersion

	// cleaner is called with the earliest version that must be kept
	cleaner func(KeepVersion)

	// mutex protects the rest of the fields
	mutex lock.RWMutex

	// versions is an ordered list of outstanding VersionHolds with a reference count.
	// Outdated values can be cleaned when there are no outstanding VersionHolds for them.
	versions []versionCount

	// latest cleaned version
	cleanedVersion version
}

// NewManager returns a new VersionManager
func NewManager(cleaner func(KeepVersion)) *Manager {
	return &Manager{
		cleaner: cleaner,
	}
}

// GetNextVersion returns NextVersion to be used when adding or removing values.
//
// Callers need to coordinate so that a single goroutine is performing modifications at any one
// time, consisting of the following operations:
// - next := manager.GetNextVersion()
//   - SetValueAtVersion(... , next)
//   - RemoveValueAtVersion(..., next)
//   - ...
//
// - manager.Publish(next)
func (v *Manager) GetNextVersion() NextVersion {
	return NextVersion(v.version.load() + 1)
}

// Publish makes a new version of values available to readers
func (v *Manager) Publish(next NextVersion) error {
	version := version(next)
	ok := v.version.compareAndSwap(version-1, version)
	if !ok {
		return errStaleVersion
	}
	return nil
}

func versionHoldCmp(a versionCount, b version) int {
	if a.version < b {
		return -1
	}
	if a.version == b {
		return 0
	}
	return 1
}

func (v *Manager) releaseVersion(version version) error {
	if version == invalidVersion {
		return errInvalidVersion
	}

	v.mutex.Lock()
	n, found := slices.BinarySearchFunc(v.versions, version, versionHoldCmp)
	if !found {
		v.mutex.Unlock()
		return errVersionNotFound
	}
	v.versions[n].count--
	if v.versions[n].count <= 0 {
		v.versions = slices.Delete(v.versions, n, n+1)
	}

	// clean if needed

	// 'keepVersion' is the current version if there are no outstanding VersionHolds
	keepVersion := v.version.load()
	if len(v.versions) > 0 {
		keepVersion = v.versions[0].version
	}
	clean := false
	if keepVersion > v.cleanedVersion {
		v.cleanedVersion = keepVersion
		clean = true
	}
	v.mutex.Unlock()

	// Call the cleaner for 'keepVersion' only if not already called for this 'keepVersion'.
	// The cleaner is called without holding the Manager lock.
	if clean {
		v.cleaner(KeepVersion(keepVersion))
	}
	return nil
}

// getVersionHold returns a VersionHold for the given version.
func (v *Manager) getVersionHold(version version) *VersionHold {
	// never get a hold for the invalid version
	if version == invalidVersion {
		version = maxVersion
	}
	v.mutex.Lock()
	n, found := slices.BinarySearchFunc(v.versions, version, versionHoldCmp)
	if !found {
		v.versions = slices.Insert(v.versions, n, versionCount{version, 1})
	} else {
		v.versions[n].count++
	}
	v.mutex.Unlock()

	return newVersionHold(version, v)
}

// GetNextVersionHold returns a VersionHold for the given NextVersion.
// Should be called before the associated PublishVersion(next) so that there is no chance of this
// version to be cleaned off before getting this VersionHold.
func (v *Manager) GetNextVersionHold(next NextVersion) *VersionHold {
	return v.getVersionHold(version(next))
}

// GetCurrentVersionHold returns a VersionHold for the current version, so that it can not be
// cleaned off before the returned VersionHold is closed.
func (v *Manager) GetCurrentVersionHold() *VersionHold {
	return v.getVersionHold(v.version.load())
}

// versionRange is a range from the first to one-past-the-last version, "[first, past)".
// 'past' is atomically modified to a smaller value when removing or a new version is added.
type versionRange struct {
	first version       // first version this value is valid for
	past  atomicVersion // first version this value is invalid for
}

func (r *versionRange) contains(version version) bool {
	return r.first <= version && version < r.past.load()
}

// valueNode is the node used in the linked list rooted at Value[T]
type valueNode[T any] struct {
	versions versionRange
	next     atomic.Pointer[valueNode[T]]
	value    T
}

// Value is a container for versioned values, implemented as a lock-free linked list.
type Value[T any] struct {
	// valueNodes are non-overlapping and in sorted by version in ascending order.
	head atomic.Pointer[valueNode[T]]
}

// SetAt adds the value with validity starting from 'version'.  All values are added with "infinite"
// validity, which is then truncated when an overlapping entry is added, or the value is removed.
// 'next' version must be later than any the current version visible to the readers.
// Returns an error if this is not the case.
// Callers must coordinate for mutual exclusion.
func (v *Value[T]) SetAt(value T, next NextVersion) error {
	version := version(next)
	if version == invalidVersion {
		return errInvalidVersion
	}

	newNode := &valueNode[T]{
		versions: versionRange{
			first: version,
		},
		value: value,
	}
	// All new values are initially set to never expire
	// ('invalidVersion' is one past 'maxVersion')
	newNode.versions.past.store(invalidVersion)

	// find if there is a current value that is valid for this new version
	node := v.head.Load()
	prev := &v.head
	for node != nil {
		if version < node.versions.first {
			stacktrace := hclog.Stacktrace()
			log.Errorf("AddValueAtVersion may not add values at versions lower than those already added! (%d < %d). Stacktrace: %s", version, node.versions.first, stacktrace)
			return errStaleVersion
		}

		if node.versions.contains(version) {
			// link the new node after the current one
			newNode.next.Store(node.next.Load())
			node.next.Store(newNode)

			// truncate the validity of this node to end at 'version' *after* the new
			// node with validity starting from 'version' has been linked after it
			// (above), so that either this or the new value is reachable at all times
			// for readers with 'version'
			node.versions.past.store(version)
			break
		}

		node = node.next.Load()
		prev = &node.next
	}
	if node == nil {
		// Add the new value at the end
		prev.Store(newNode)
	}

	return nil
}

// RemoveAt changes the validity of the stored value previously valid at version 'next' to have
// ended at version 'next'.
// 'next' must be later than any the current version visible to the readers.
// Returns an error if this is not the case.
// Callers must coordinate for mutual exclusion.
func (v *Value[T]) RemoveAt(next NextVersion) error {
	version := version(next)
	if version == invalidVersion {
		return errInvalidVersion
	}

	for node := v.head.Load(); node != nil; node = node.next.Load() {
		if version < node.versions.first {
			stacktrace := hclog.Stacktrace()
			log.Errorf("DeleteValueAtVersion may not be called with version lower than existing already! (%d < %d). Stacktrace: %s", version, node.versions.first, stacktrace)
			return errStaleVersion
		}

		if node.versions.contains(version) {
			// Truncate the validity of this node to end at 'version'.
			// After this readers with 'version' and above no longer see this value,
			// while readers with versions before 'version' still see this.
			node.versions.past.store(version)
			break
		}
	}
	return nil
}

// RemoveBefore removes all values whose validity ends before 'keepVersion'.
// Must be called from a single writer!
func (v *Value[T]) RemoveBefore(keepVersion KeepVersion) {
	version := version(keepVersion)
	// find all values that are no longer valid at 'version'
	node := v.head.Load()
	for node != nil && node.versions.past.load() <= version {
		// This node is no longer visible for readers with 'version' and above,
		// so this can be safely removed.
		node = node.next.Load()
	}
	v.head.Store(node)
}

// At returns value of type 'T' valid for the given version, or an empty value if none is found.
func (v *Value[T]) At(hold *VersionHold) T {
	version := invalidVersion
	if hold != nil {
		version = hold.version
	}
	if version == invalidVersion {
		stacktrace := hclog.Stacktrace()
		log.Errorf("versioned.ValueAtVersion: Invalid handle finds nothing; Stacktrace: %s", stacktrace)
	}

	for node := v.head.Load(); node != nil; node = node.next.Load() {
		if node.versions.contains(version) {
			return node.value
		}
	}
	var empty T
	return empty
}

// Versioned is a pair of a version and any type T
type Versioned[T any] struct {
	version version
	value   T
}

type VersionedSlice[T any] []Versioned[T]

// Append appends a pair of 'nextVersion' and 'value' to VersionedSlice 's', returning updated
// 's'. Needed to keep members private.
// Should only be called with monotonically increasing 'nextVersion's, so that the slice remains
// sorted by version in ascending order.
func (s VersionedSlice[T]) Append(nextVersion NextVersion, value T) VersionedSlice[T] {
	return append(s, Versioned[T]{
		version: version(nextVersion),
		value:   value,
	})
}

// ForEachBefore iterates the elements in VersionedSlice 's', calling function 'f(T)' with each
// value associated with versions earlier than 'keepVersion'.
// The slice is assumed to be sorted by version in ascending order.
// Returns the number of calls made.
func (s VersionedSlice[T]) ForEachBefore(keepVersion KeepVersion, f func(T)) (n int) {
	version := version(keepVersion)
	for n = 0; n < len(s); n++ {
		if s[n].version >= version {
			break
		}
		f(s[n].value)
	}
	return n
}
