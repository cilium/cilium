// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lock

// KeyedMutex serializes operations on equal keys.
// Its zero value is ready for use.
// A KeyedMutex must not be copied after first use.
type KeyedMutex[K comparable] struct {
	mu      Mutex
	entries map[K]*mutexEntry
}

type mutexEntry struct {
	mu   Mutex
	refs int // Holders and waiters; protected by KeyedMutex.mu.
}

// UnlockFunc releases a previously acquired lock.
type UnlockFunc func()

// Lock acquires the mutex for key and returns its release function.
// The caller must invoke the release function exactly once.
func (m *KeyedMutex[K]) Lock(key K) UnlockFunc {
	m.mu.Lock()

	if m.entries == nil {
		m.entries = make(map[K]*mutexEntry)
	}
	entry := m.entries[key]
	if entry == nil {
		entry = &mutexEntry{}
		m.entries[key] = entry
	}
	entry.refs++
	m.mu.Unlock()

	entry.mu.Lock()

	return func() {
		entry.mu.Unlock()

		m.mu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(m.entries, key)
		}
		m.mu.Unlock()
	}
}
