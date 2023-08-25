// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package revert

import "fmt"

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
func (s *RevertStack) Revert() error {
	for i := len(s.revertFuncs) - 1; i >= 0; i-- {
		if err := s.revertFuncs[i](); err != nil {
			return fmt.Errorf("failed to execute revert function; skipping %d revert functions: %s", i, err)
		}
	}
	return nil
}

// Extend extends the revert stack by the given stack.
func (s *RevertStack) Extend(t RevertStack) {
	for _, f := range t.revertFuncs {
		s.Push(f)
	}
}
