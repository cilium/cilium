// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package workerpool

import (
	"context"
	"fmt"
	"time"
)

// Task is a unit of work.
type Task interface {
	// String returns the task identifier.
	fmt.Stringer
	// Err returns the error resulting from processing the
	// unit of work.
	Err() error
}

// Result is a completed Task that also reports its execution duration.
// It is passed to the callback registered with [WithResultCallback].
type Result interface {
	Task
	// Duration returns the time taken to execute the task.
	Duration() time.Duration
}

type task struct {
	run func(context.Context) error
	id  string
}

type taskResult struct {
	err      error
	id       string
	duration time.Duration
}

// Ensure that taskResult implements the Result interface.
var _ Result = &taskResult{}

// String implements [fmt.Stringer] for taskResult.
func (t *taskResult) String() string {
	return t.id
}

// Err returns the error resulting from processing the taskResult.
func (t *taskResult) Err() error {
	return t.err
}

// Duration returns the time taken to execute the task.
func (t *taskResult) Duration() time.Duration {
	return t.duration
}
