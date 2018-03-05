// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
