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

func (wc watcherCache) RemoveDeleted(f func(string)) {
	for k, localKey := range wc {
		if localKey.deletionMark {
			f(k)
			delete(wc, k)
		}
	}
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
