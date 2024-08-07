// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package versioned

import (
	"math"
	"slices"
	"sync/atomic"

	"github.com/hashicorp/go-hclog"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type Version uint64

const (
	// invalidVersion is never found from the value range.
	// Also used as the upper bound for new values, so that the value is
	// found when looking with 'maxVersion'
	invalidVersion = Version(math.MaxUint64)

	// maxVersion in a handle finds all non-removed values
	maxVersion = Version(math.MaxUint64 - 1)

	maxEmptyHandles = 1024
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "versioned")
)

type Closer func() bool

// Handle is the object needed for getting values containing the latest version available at the
// time of getting the Handle.
type Handle struct {
	// Handle stores version + 1 so that the zero value translates to invalidVersion
	versionPlus1 Version
	// closer releases the handle, can be nil
	closer Closer
}

func initHandle(version Version, closer Closer) Handle {
	return Handle{version + 1, closer}
}

// AllHandle returns a handle that matches all current/non-removed values
func AllHandle() Handle {
	return initHandle(maxVersion, nil)
}

func (h *Handle) getVersion() Version {
	return h.versionPlus1 - 1
}

func (h *Handle) IsValid() bool {
	return h.versionPlus1 != 0
}

func (h *Handle) Release() (released bool) {
	if h.IsValid() {
		if h.closer != nil {
			released = h.closer()
			h.closer = nil
		}
		h.versionPlus1 = 0
	}
	return released
}

type atomicVersion struct {
	version atomic.Uint64
}

func (a *atomicVersion) Load() Version {
	return Version(a.version.Load())
}

func (a *atomicVersion) Store(version Version) {
	a.version.Store(uint64(version))
}

func (a *atomicVersion) CompareAndSwap(old, new Version) bool {
	return a.version.CompareAndSwap(uint64(old), uint64(new))
}

type versionCount struct {
	version Version
	count   int
}

// Manager manages the versioning for multiple VersionedValues.
// It is to be stored wherever VersionedValues are stored
type Manager struct {
	version atomicVersion

	// cleaner is called with the earliest version that must be kept
	cleaner func(keepVersion Version)

	// mutex protects 'handles'
	mutex lock.RWMutex

	// handles is an ordered list of outstanding handle versions with a reference count.
	// Outdated values can be removed when there are no outstanding handles for it.
	handles []versionCount

	// latest cleaned version
	cleanedVersion Version
}

func NewVersionManager(cleaner func(keepVersion Version)) *Manager {
	return &Manager{
		cleaner: cleaner,
	}
}

func (v *Manager) GetVersion() (current, next Version) {
	current = v.version.Load()
	return current, current + 1
}

func (v *Manager) PublishVersion(current, new Version) bool {
	return v.version.CompareAndSwap(current, new)
}

func handleVersionCmp(a versionCount, b Version) int {
	if a.version < b {
		return -1
	}
	if a.version == b {
		return 0
	}
	return 1
}

func (v *Manager) releaseVersion(version Version, name string) bool {
	if version == invalidVersion {
		return false
	}

	v.mutex.Lock()
	n, found := slices.BinarySearchFunc(v.handles, version, handleVersionCmp)
	if !found {
		log.WithFields(logrus.Fields{
			"version": version,
			"handle":  name,
		}).Error("closer: Handle for version not found")

		v.mutex.Unlock()
		return false
	}
	v.handles[n].count--
	if v.handles[n].count <= 0 {
		v.handles = slices.Delete(v.handles, n, n+1)

		// release memory for long empty slice
		if len(v.handles) == 0 && cap(v.handles) > maxEmptyHandles {
			v.handles = nil
		}
	}

	// clean if needed

	// 'keepVersion' is the current version if there are no outstanding handles
	keepVersion := v.version.Load()
	if len(v.handles) > 0 {
		keepVersion = v.handles[0].version
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
		v.cleaner(keepVersion)
	}
	return true
}

// GetHandle returns a Handle for the current version and a closer for releasing old versions held
// for this version.
// 'name' is for debugging purposes only
func (v *Manager) GetHandleForVersion(version Version, name string) Handle {
	v.mutex.Lock()
	n, found := slices.BinarySearchFunc(v.handles, version, handleVersionCmp)
	if !found {
		v.handles = slices.Insert(v.handles, n, versionCount{version, 1})
	} else {
		v.handles[n].count++
	}
	v.mutex.Unlock()

	return initHandle(version, func() bool {
		released := v.releaseVersion(version, name)
		version = invalidVersion
		return released
	})
}

func (v *Manager) GetHandle(name string) (handle Handle) {
	return v.GetHandleForVersion(v.version.Load(), name)
}

// versionRange is a range from the first to last version.
// 'past' can be atomically modified to a smaller value.
type versionRange struct {
	first Version       // first version this value is valid for
	past  atomicVersion // first version this value is invalid for
}

func (r *versionRange) Contains(version Version) bool {
	return r.first <= version && version < r.past.Load()
}

type valueNode[T any] struct {
	versions versionRange
	next     atomic.Pointer[valueNode[T]]
	value    T
}

// Value is a container for versioned value, implemented as a lock-free linked list
type Value[T any] struct {
	// versionedNodes are non-overlapping and in sorted order
	head atomic.Pointer[valueNode[T]]
}

// SetValueAtVersion adds the value with validity starting from 'version'.
// All values are added with "infinite" validity, which is then truncated
// when an overlapping entry is added, or a value is removed.
//
// 'version' must be later than any the current version visible to the readers.
// Must be called from a single writer!
func SetValueAtVersion[T any](v *Value[T], value T, version Version) {
	newNode := &valueNode[T]{
		versions: versionRange{
			first: version,
		},
		value: value,
	}
	// All new values are initially set to never expire
	newNode.versions.past.Store(invalidVersion)

	// find if there is a current value that is valid for this new version
	node := v.head.Load()
	prev := &v.head
	for node != nil {
		if version < node.versions.first {
			stacktrace := hclog.Stacktrace()
			log.Errorf("AddValueAtVersion may not add values at versions lower than those already added! (%d < %d). Stacktrace: %s", version, node.versions.first, stacktrace)
		}

		if node.versions.Contains(version) {
			// link the new node after the current one
			newNode.next.Store(node.next.Load())
			node.next.Store(newNode)

			// truncate the validity of this node to end at 'version' after the new node
			// with validity starting from 'version' has been added after it, so that
			// either this or the new value is reachable at all times for lookups with 'version'
			node.versions.past.Store(version)
			break
		}

		node = node.next.Load()
		prev = &node.next
	}
	if node == nil {
		// Add the new value at the end
		prev.Store(newNode)
	}
}

// RemoveValueAtVersion changes the validity of the stored value valid at 'version' to have ended at
// 'version'.
// 'version' must be later than any the current version visible to the readers.
// Must be called from a single writer!
func RemoveValueAtVersion[T any](v *Value[T], version Version) {
	for node := v.head.Load(); node != nil; node = node.next.Load() {
		if version < node.versions.first {
			stacktrace := hclog.Stacktrace()
			log.Errorf("DeleteValueAtVersion may not be called with version lower than existing already! (%d < %d). Stacktrace: %s", version, node.versions.first, stacktrace)
		}

		if node.versions.Contains(version) {
			// truncate the validity of this node to end at 'version'
			node.versions.past.Store(version)
			break
		}
	}
}

// Cleaner removes all values whose validity ends at or before 'keepVersion'.
// Must be called from a single writer!
func Cleaner[T any](v *Value[T], keepVersion Version) {
	// find all values that are no longer valid at 'version'
	node := v.head.Load()
	for node != nil && node.versions.past.Load() <= keepVersion {
		// This node is no longer visible for readers who are all version 'keepVersion' or
		// later.
		node = node.next.Load()
		v.head.Store(node)
	}
}

// GetValue returns value of type 'T' valid for the given version, or an empty value if none is
// found.
func GetValue[T any](v *Value[T], handle Handle) T {
	version := handle.getVersion()
	for node := v.head.Load(); node != nil; node = node.next.Load() {
		if node.versions.Contains(version) {
			return node.value
		}
	}
	var empty T
	return empty
}

// Pair is a struct of a version and any type T
type Pair[T any] struct {
	version Version
	value   T
}

// PairSlice is a slice of Pairs
type PairSlice[T any] []Pair[T]

// NewPairSlice returns a new PairSlice of given 'capacity'
func NewPairSlice[T any](capacity int) PairSlice[T] {
	return make(PairSlice[T], 0, capacity)
}

// AppendPair appends a pair of 'version' and 'value' to PairSlice 's', returning 's'
func AppendPair[T any](s PairSlice[T], version Version, value T) PairSlice[T] {
	s = append(s, Pair[T]{
		version: version,
		value:   value,
	})
	return s
}

// ForEachUpToVersion traverses the Pairs in PairSlice 's', calling function 'f(T)' with each value
// associated with a values earlier than and including 'version'.
// Returns the number of calls made.
func ForEachUpToVersion[T any](s PairSlice[T], version Version, f func(T)) (n int) {
	for n = 0; n < len(s); n++ {
		if s[n].version > version {
			break
		}
		f(s[n].value)
	}
	return n
}

// TrimFrontPairSlice trims the first 'n' Pairs off of the PairSlice 's', returning 's'.
// If 's' gets empty it is reallocated if its capacity exceeds 'capacity'.
func TrimFrontPairSlice[T any](s PairSlice[T], n int, capacity int) PairSlice[T] {
	// Trim 'n' values at front
	s = s[n:]

	// release excess capacity
	if len(s) == 0 && cap(s) > capacity {
		s = NewPairSlice[T](capacity)
	}

	return s
}
