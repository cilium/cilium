// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resiliency

import (
	"errors"
	"fmt"
)

type tuple struct {
	index int
	err   error
}

// ErrorSet tracks a collection of unique errors.
type ErrorSet struct {
	total, failed int
	msg           string
	errs          map[string]tuple
}

// NewErrorSet returns a new instance.
func NewErrorSet(msg string, c int) *ErrorSet {
	return &ErrorSet{
		msg:   msg,
		total: c,
		errs:  make(map[string]tuple),
	}
}

// Add adds one or more errors to the set.
func (e *ErrorSet) Add(errs ...error) {
	for _, err := range errs {
		if err == nil {
			continue
		}
		if _, ok := e.errs[err.Error()]; ok {
			continue
		}
		e.errs[err.Error()] = tuple{index: e.failed, err: err}
		e.failed++
	}
}

// Error returns a list of unique errors or nil.
func (e *ErrorSet) Errors() []error {
	if len(e.errs) == 0 {
		return nil
	}
	errs := make([]error, len(e.errs)+1)
	errs[0] = fmt.Errorf("%s (%d/%d) failed", e.msg, e.failed, e.total)
	for _, t := range e.errs {
		errs[t.index+1] = t.err
	}

	return errs
}

// Error returns a new composite error or nil.
func (e *ErrorSet) Error() error {
	return errors.Join(e.Errors()...)
}
