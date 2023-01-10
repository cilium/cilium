// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package workerpool

import (
	"context"
	"fmt"
)

// Task is a unit of work.
type Task interface {
	// String returns the task identifier.
	fmt.Stringer
	// Err returns the error resulting from processing the
	// unit of work.
	Err() error
}

type task struct {
	run func(context.Context) error
	id  string
}

type taskResult struct {
	err error
	id  string
}

// Ensure that taskResult implements the Task interface.
var _ Task = &taskResult{}

// String implements fmt.Stringer for taskResult.
func (t *taskResult) String() string {
	return t.id
}

// Err returns the error resulting from processing the taskResult. It ensures
// that the taskResult struct implements the Task interface.
func (t *taskResult) Err() error {
	return t.err
}
