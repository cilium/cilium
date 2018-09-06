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

package endpoint

// RevertFunc is a function returned by a successful function call, which
// reverts the side-effects of the initial function call. A call that returns
// an error should return a nil RevertFunc.
type RevertFunc func() error

// RevertStack is a stack of RevertFuncs to be executed in the reverse order
// they were pushed.
type RevertStack struct {
	// revertFuncs is the list of revert functions in the order they were
	// pushed.
	revertFuncs []RevertFunc
}

// Push pushes the given RevertFunc on top of this stack. If the function is
// nil, it is ignored.
func (s *RevertStack) Push(revertFunc RevertFunc) {
	if revertFunc != nil {
		s.revertFuncs = append(s.revertFuncs, revertFunc)
	}
}

// Revert executes all the RevertFuncs in the given stack in the reverse order
// they were pushed.
func (e *Endpoint) Revert(s *RevertStack) error {
	for i := len(s.revertFuncs) - 1; i >= 0; i-- {
		if err := s.revertFuncs[i](); err != nil {
			e.getLogger().WithError(err).Errorf("Failed to execute revert function; skipping %d functions in this stack", i)
			return err
		}
	}
	return nil
}

// RevertFunc returns a RevertFunc that executes all the RevertFuncs in the
// given stack in the reverse order they were pushed.
func (e *Endpoint) RevertFunc(s *RevertStack) RevertFunc {
	return func() error { return e.Revert(s) }
}

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
func (s *FinalizeList) Append(finalizeFunc FinalizeFunc) {
	if finalizeFunc != nil {
		s.finalizeFuncs = append(s.finalizeFuncs, finalizeFunc)
	}
}

// Finalize executes all the FinalizeFuncs in the given list in the same order
// they were pushed.
func (e *Endpoint) Finalize(s *FinalizeList) {
	for _, f := range s.finalizeFuncs {
		f()
	}
}

// FinalizeFunc returns a FinalizeFunc that executes all the FinalizeFuncs in the
// given list in the same order they were appended.
func (e *Endpoint) FinalizeFunc(s *FinalizeList) FinalizeFunc {
	return func() { e.Finalize(s) }
}
