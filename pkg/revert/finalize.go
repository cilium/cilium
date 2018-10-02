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

package revert

// FinalizeFunc is a function returned by a successful function call, which
// finalizes the initial function call. A call that returns an error should
// return a nil FinalizeFunc.
// When a call returns both a RevertFunc and a FinalizeFunc, at most one may be
// called. The side effects of the FinalizeFunc are not reverted by the
// RevertFunc.
type FinalizeFunc func()

// FinalizeList is a list of FinalizeFuncs to be executed in the same order
// they were appended.
type FinalizeList struct {
	// finalizeFuncs is the list of finalize functions in the order they were
	// appended.
	finalizeFuncs []FinalizeFunc
}

// Append appends the given FinalizeFunc at the end of this list. If the
// function is nil, it is ignored.
func (f *FinalizeList) Append(finalizeFunc FinalizeFunc) {
	if finalizeFunc != nil {
		f.finalizeFuncs = append(f.finalizeFuncs, finalizeFunc)
	}
}

// Finalize executes all the FinalizeFuncs in the given list in the same order
// they were pushed.
func (f *FinalizeList) Finalize() {
	for _, f := range f.finalizeFuncs {
		f()
	}
}
