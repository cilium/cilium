// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package versioned

import (
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"math"
	"runtime"
	"slices"
	"strconv"
	"sync/atomic"

	"github.com/hashicorp/go-hclog"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
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
	// Optional stack trace of the caller for debugging purposes
	stacktrace hclog.CapturedStacktrace
}

func (h *VersionHandle) IsValid() bool {
	return h != nil && (h.version == maxVersion || h.coordinator.Load() != nil)
}

func (h *VersionHandle) Version() KeepVersion {
	return KeepVersion(h.version)
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
func (h *VersionHandle) Close() error {
	if h == nil || h.version == invalidVersion {
		return ErrInvalidVersion
	}
	// handle with 'maxVersion' is never closed
	if h.version != maxVersion {
		// Using CompareAndSwap makes sure each handle is closed at most once
		coordinator := h.coordinator.Load()
		if coordinator != nil && h.coordinator.CompareAndSwap(coordinator, nil) {
			runtime.SetFinalizer(h, nil)
			return coordinator.releaseVersion(h.version)
		}
		return ErrStaleVersion
	}
	return nil
}

// versionHandleFinalizer is used to warn about missing Close() calls.
func versionHandleFinalizer(h *VersionHandle) {
	coordinator := h.coordinator.Load()
	if coordinator != nil && coordinator.Logger != nil {
		logger := coordinator.Logger
		if h.stacktrace != "" {
			logger = logger.With(logfields.Stacktrace, h.stacktrace)
		}
		logger.Error("Handle for version not closed.", logfields.Version, h.version)
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

		if option.Config.Debug {
			// capture a stacktrace for debugging
			h.stacktrace = hclog.Stacktrace()
		}
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
	Logger *slog.Logger

	// Cleaner is called with the earliest version that must be kept.
	// Must be set to clean up resources held for old versions.
	// Cleaner function may be called concurrently, the function must synchronize
	// use of any shared resources.
	Cleaner func(KeepVersion)

	// mutex protects the rest of the fields
	mutex lock.RWMutex

	// version is the version number of the last applied change
	version version

	// oldest version not cleaned off
	oldestVersion version

	// versions is an ordered list of outstanding VersionHandles with a reference count.
	// Outdated values can be cleaned when there are no outstanding VersionHandles for them.
	versions []versionCount
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
	v.mutex.Lock()
	defer v.mutex.Unlock()
	return &Tx{
		nextVersion: v.version + 1,
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

func (tx *Tx) After(v KeepVersion) bool {
	return tx.nextVersion > version(v)
}

// Commit makes a new version of values available to readers
// Commit call may be omitted if no changes were actually made.
func (tx *Tx) Commit() error {
	return tx.coordinator.commit(tx.nextVersion)
}

// GetVersionHandle returns a VersionHandle for the given transaction.
func (tx *Tx) GetVersionHandle() *VersionHandle {
	// This is only needed to support LatestTx to make some testing easier
	if tx.coordinator == nil && tx.nextVersion == maxVersion {
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

// commit makes a new version of values available to readers
// and cleans up any possible stale versions
func (v *Coordinator) commit(version version) error {
	v.mutex.Lock()
	defer v.mutex.Unlock()

	if v.version != version-1 {
		return ErrStaleVersion
	}
	v.version = version

	// clean up stale versions if any
	v.clean()
	return nil
}

func (v *Coordinator) releaseVersion(version version) error {
	if version == invalidVersion {
		return ErrInvalidVersion
	}

	v.mutex.Lock()
	defer v.mutex.Unlock()

	n, found := slices.BinarySearchFunc(v.versions, version, versionHandleCmp)
	if !found {
		if v.Logger != nil {
			v.Logger.Error(
				"Version not found.",
				logfields.Version, version,
				logfields.Stacktrace, hclog.Stacktrace(),
			)
		}
		return ErrVersionNotFound
	}
	v.versions[n].count--
	if v.versions[n].count <= 0 {
		v.versions = slices.Delete(v.versions, n, n+1)
	}

	// clean if needed
	v.clean()
	return nil
}

// clean must be called with lock held
func (v *Coordinator) clean() {
	// 'keepVersion' is the current version if there are no outstanding VersionHandles
	keepVersion := v.version
	if len(v.versions) > 0 {
		// otherwise it is the oldest version for which there is an outstanding handle, if
		// older than the current version, as if there was an implicit outstanding handle
		// for the current version.
		keepVersion = min(v.version, v.versions[0].version)
	}

	// Call the cleaner for 'keepVersion' only if not already called for this 'keepVersion'.
	if keepVersion > v.oldestVersion {
		// The cleaner is called from a goroutine without holding any locks
		if v.Cleaner != nil {
			if v.Logger != nil {
				v.Logger.Debug(
					"releaseVersion: calling cleaner",
					logfields.OldVersion, v.oldestVersion,
					logfields.NewVersion, keepVersion,
				)
			}
			go v.Cleaner(KeepVersion(keepVersion))
			v.oldestVersion = keepVersion
		} else if v.Logger != nil {
			v.Logger.Warn("VersionHandle.Close: Cleaner function not set")
		}
	}
}

// getVersionHandle returns a VersionHandle for the given version.
func (v *Coordinator) getVersionHandle(version version) *VersionHandle {
	v.mutex.Lock()
	defer v.mutex.Unlock()
	return v.getVersionHandleLocked(version)
}

func (v *Coordinator) getVersionHandleLocked(version version) *VersionHandle {
	// never get a handle for the invalid version
	if version == invalidVersion {
		version = maxVersion
	}

	if version < v.oldestVersion {
		oldVersion := version
		version = v.oldestVersion
		if v.Logger != nil {
			v.Logger.Warn(
				"GetVersionHandle: Handle to a stale version requested, returning oldest valid version instead",
				logfields.Stacktrace, hclog.Stacktrace(),
				logfields.Version, version,
				logfields.OldVersion, oldVersion,
			)
		}
	}
	n, found := slices.BinarySearchFunc(v.versions, version, versionHandleCmp)
	if !found {
		v.versions = slices.Insert(v.versions, n, versionCount{version, 1})
	} else {
		v.versions[n].count++
	}

	return newVersionHandle(version, v)
}

// GetVersionHandle returns a VersionHandle for the current version, so that it can not be
// cleaned off before the returned VersionHandle is closed.
func (v *Coordinator) GetVersionHandle() *VersionHandle {
	v.mutex.Lock()
	defer v.mutex.Unlock()
	return v.getVersionHandleLocked(v.version)
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
	version := tx.nextVersion
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
	version := tx.nextVersion
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
func (v *Value[T]) At(handle *VersionHandle) T {
	if handle != nil {
		version := handle.version
		for node := v.head.Load(); node != nil; node = node.next.Load() {
			if node.versions.contains(version) {
				return node.value
			}
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
func (s VersionedSlice[T]) Append(value T, tx *Tx) VersionedSlice[T] {
	return append(s, Versioned[T]{
		version: tx.nextVersion,
		value:   value,
	})
}

// Before returns an iterator over the elements in VersionedSlice 's' having a version earlier than
// 'keepVersion'.
// The slice is assumed to be sorted by version in ascending order.
func (s VersionedSlice[T]) Before(keepVersion KeepVersion) iter.Seq[T] {
	return func(yield func(T) bool) {
		version := version(keepVersion)
		for n := range s {
			if s[n].version >= version {
				break
			}
			if !yield(s[n].value) {
				return
			}
		}
	}
}
