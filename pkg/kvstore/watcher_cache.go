// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

type watchState struct {
	deletionMark bool
}

type watcherCache map[string]watchState

func (wc watcherCache) Exists(key []byte) bool {
	if _, ok := wc[string(key)]; ok {
		return true
	}

	return false
}

// RemoveDeleted removes keys marked for deletion from the local cache exiting
// early if the given function returns false.
func (wc watcherCache) RemoveDeleted(f func(string) bool) bool {
	for k, localKey := range wc {
		if localKey.deletionMark {
			if !f(k) {
				return false
			}
			delete(wc, k)
		}
	}
	return true
}

func (wc watcherCache) MarkAllForDeletion() {
	for k := range wc {
		wc[k] = watchState{deletionMark: true}
	}
}

func (wc watcherCache) MarkInUse(key []byte) {
	wc[string(key)] = watchState{deletionMark: false}
}

func (wc watcherCache) RemoveKey(key []byte) {
	delete(wc, string(key))
}
