// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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
