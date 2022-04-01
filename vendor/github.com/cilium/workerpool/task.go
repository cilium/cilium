// Copyright 2021 Authors of Cilium
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
