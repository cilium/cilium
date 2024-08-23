// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package versioned

import (
	"errors"
	"fmt"
	"math"
	"runtime"
	"slices"
	"strconv"
	"sync/atomic"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type version uint64

const (
	// invalidVersion is never found from the value range.
	// Also used as the upper bound for new values, so that the value is
	// found when looking with 'maxVersion'
	invalidVersion = version(math.MaxUint64)

	// maxVersion in a VersionHandle finds the latest version of all non-removed values
	maxVersion = version(math.MaxUint64 - 1)
)

// KeepVersion is an exported version type used when releasing memory held for old versions.
type KeepVersion version

var (
	ErrInvalidVersion   = errors.New("invalid version")
	ErrStaleTransaction = errors.New("stale transaction")
	ErrStaleVersion     = errors.New("stale version")
	ErrVersionNotFound  = errors.New("version not found")
)

// VersionHandle is used to keep values valid for a specific version from being released, so that
// they are available for use for as long as the VersionHandle is not closed.
//
// A special form with a nil coordinator, which is returned by Latest(), always finds the latest
// versions and does not keep any versions from being released.
type VersionHandle struct {
	// 'version' is the version this versionHandle keeps from being released
	version version
	// Coordinator of this versionHandle, if any. Used for closing if non-nil.
	// Atomic due to nilling and for copy prevention.
	coordinator atomic.Pointer[Coordinator]
}

func (h *VersionHandle) IsValid() bool {
	return h != nil && (h.version == maxVersion || h.coordinator.Load() != nil)
}

func (h *VersionHandle) Version() version {
	if h == nil {
		return invalidVersion
	}
	return h.version
}

func (h *VersionHandle) String() string {
	if h == nil {
		return "version: <nil>"
	}
	validity := "invalid"
	if h.IsValid() {
		validity = "valid"
	}
	return fmt.Sprintf("%d (%s)", h.version, validity)
}

// Close releases the held version for removal once no handle for it are no longer held.
// This may not be called while holding any locks that the 'closer' function passed to the
// coordinator may take!
func (h *VersionHandle) Close() (err error) {
	if !h.IsValid() {
		return ErrInvalidVersion
	}
	coordinator := h.coordinator.Load()
	if coordinator != nil {
		runtime.SetFinalizer(h, nil)
		err = coordinator.releaseVersion(h.version)
		h.coordinator.Store(nil)
	}
	return err
}

// versionHandleFinalizer is used to warn about missing Close() calls.
func versionHandleFinalizer(h *VersionHandle) {
	coordinator := h.coordinator.Load()
	if coordinator != nil && coordinator.Logger != nil {
		coordinator.Logger.WithField(logfields.Version, h.version).Error("Handle for version not closed.")
	}
	h.Close()
}

func newVersionHandle(version version, coordinator *Coordinator) *VersionHandle {
	// handle on maxVersion never expires
	if version == maxVersion {
		coordinator = nil
	}
	h := &VersionHandle{version: version}
	h.coordinator.Store(coordinator)
	if coordinator != nil {
		// Set a finalizer to catch unclosed handles. The finalizer function complains
		// loudly, so that we do not rely the finalizer for closing.
		runtime.SetFinalizer(h, versionHandleFinalizer)
	}
	return h
}

// Latest returns a VersionHandle for the latest version of current/non-removed values
// Only to be used in cases where the latest values are needed and no transactionality is required.
func Latest() *VersionHandle {
	return newVersionHandle(maxVersion, nil)
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

// Coordinator defines a common version number space for multiple versioned.Values,
// and provides facilities for cleaning out stale versions.
// The Value's are not directly managed by the Coordinator, but all the values under coordination
// should be cleaned by the 'cleaner' function given to the Coordinator.
type Coordinator struct {
	// Logger supplied to NewCoordinator. Should be set if logging is desired.
	Logger *logrus.Entry

	// Cleaner is called with the earliest version that must be kept.
	// Must be set to clean up resources held for old versions.
	// Cleaner function may be called concurrently, the function must synchronize
	// use of any shared resources.
	// May also be called from VersionHandle.Close, do none of the needed locks may
	// be held while calling Close().
	Cleaner func(KeepVersion)

	// version is the version number of the last applied change
	version atomicVersion

	// mutex protects the rest of the fields
	mutex lock.RWMutex

	// versions is an ordered list of outstanding VersionHandles with a reference count.
	// Outdated values can be cleaned when there are no outstanding VersionHandles for them.
	versions []versionCount

	// oldest version not cleaned off
	oldestVersion version
}

// PrepareNextVersion returns a transaction to be used when adding or removing values.
//
// Callers need to coordinate so that a single goroutine is performing modifications at any one
// time, consisting of the following operations:
//
// - tx := coordinator.PrepareNextVersion()
//   - value.SetAt(... , tx)
//   - value.RemoveAt(..., tx)
//   - ...
//
// - tx.Commit()
func (v *Coordinator) PrepareNextVersion() *Tx {
	return &Tx{
		nextVersion: v.version.load() + 1,
		coordinator: v,
	}
}

// All values in Tx are constants
type Tx struct {
	nextVersion version
	coordinator *Coordinator
}

// LatestTx refers to maxVersion without having a coordinator, should only be used for testing.
var LatestTx = &Tx{nextVersion: maxVersion}

func (tx *Tx) String() string {
	return strconv.FormatUint(uint64(tx.nextVersion), 10)
}

// Commit makes a new version of values available to readers
// Commit call may be omitted if no changes were actually made.
func (tx *Tx) Commit() error {
	if tx == nil {
		return ErrStaleTransaction
	}
	version := version(tx.nextVersion)
	ok := tx.coordinator.version.compareAndSwap(version-1, version)
	if !ok {
		return ErrStaleVersion
	}
	return nil
}

// GetVersionHandle returns a VersionHandle for the given transaction.
func (tx *Tx) GetVersionHandle() *VersionHandle {
	if tx.coordinator == nil {
		return Latest()
	}
	return tx.coordinator.getVersionHandle(tx.nextVersion)
}

func versionHandleCmp(a versionCount, b version) int {
	if a.version < b {
		return -1
	}
	if a.version == b {
		return 0
	}
	return 1
}

func (v *Coordinator) releaseVersion(version version) error {
	if version == invalidVersion {
		return ErrInvalidVersion
	}

	v.mutex.Lock()
	n, found := slices.BinarySearchFunc(v.versions, version, versionHandleCmp)
	if !found {
		v.mutex.Unlock()
		return ErrVersionNotFound
	}
	v.versions[n].count--
	if v.versions[n].count <= 0 {
		v.versions = slices.Delete(v.versions, n, n+1)
	}

	// clean if needed

	// 'keepVersion' is the current version if there are no outstanding VersionHandles
	keepVersion := v.version.load()
	if len(v.versions) > 0 {
		keepVersion = v.versions[0].version
	}
	clean := false
	if keepVersion > v.oldestVersion {
		v.oldestVersion = keepVersion
		clean = true
	}
	v.mutex.Unlock()

	// Call the cleaner for 'keepVersion' only if not already called for this 'keepVersion'.
	// The cleaner is called without holding the Coordinator lock.
	// Consider pooling cleaner calls so that we would do more work at each invocation.
	if clean {
		if v.Cleaner != nil {
			v.Cleaner(KeepVersion(keepVersion))
		} else if v.Logger != nil {
			v.Logger.Warnf("VersionHandle.Close: Cleaner function not set")
		}
	}
	return nil
}

// getVersionHandle returns a VersionHandle for the given version.
func (v *Coordinator) getVersionHandle(version version) *VersionHandle {
	// never get a handle for the invalid version
	if version == invalidVersion {
		version = maxVersion
	}

	v.mutex.Lock()
	if version < v.oldestVersion {
		oldVersion := version
		version = v.oldestVersion
		if v.Logger != nil {
			v.Logger.WithFields(logrus.Fields{
				logfields.Version:    version,
				logfields.OldVersion: oldVersion,
			}).Warn("GetVersionHandle: Handle to a stale version requested, returning oldest valid version instead")
		}
	}
	n, found := slices.BinarySearchFunc(v.versions, version, versionHandleCmp)
	if !found {
		v.versions = slices.Insert(v.versions, n, versionCount{version, 1})
	} else {
		v.versions[n].count++
	}
	v.mutex.Unlock()

	return newVersionHandle(version, v)
}

// GetVersionHandle returns a VersionHandle for the current version, so that it can not be
// cleaned off before the returned VersionHandle is closed.
func (v *Coordinator) GetVersionHandle() *VersionHandle {
	return v.getVersionHandle(v.version.load())
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
func (v *Value[T]) SetAt(value T, tx *Tx) error {
	version := version(tx.nextVersion)
	if version == invalidVersion {
		return ErrInvalidVersion
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
			return fmt.Errorf("SetAt may not add values at versions lower than those already added (%d<%d): %w", version, node.versions.first, ErrStaleVersion)
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
		if node != nil {
			prev = &node.next
		}
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
func (v *Value[T]) RemoveAt(tx *Tx) error {
	version := version(tx.nextVersion)
	if version == invalidVersion {
		return ErrInvalidVersion
	}

	for node := v.head.Load(); node != nil; node = node.next.Load() {
		if version < node.versions.first {
			return fmt.Errorf("RemoveAt may not be called with version lower than existing already (%d<%d): %w", version, node.versions.first, ErrStaleVersion)
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
// Caller must coordinate for mutual exclusion.
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
func (v *Value[T]) At(handle *VersionHandle) (empty T) {
	if handle != nil {
		version := handle.Version()
		for node := v.head.Load(); node != nil; node = node.next.Load() {
			if node.versions.contains(version) {
				return node.value
			}
		}
	}
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
func (s VersionedSlice[T]) Append(value T, tx *Tx) VersionedSlice[T] {
	return append(s, Versioned[T]{
		version: version(tx.nextVersion),
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
