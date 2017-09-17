/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package framework

import (
	"testing"
	"time"
)

const (
	DefaultWaitInterval = 50 * time.Millisecond
)

// SetUp is likely to be fixture-specific, but TearDown needs to be
// consistent to enable TearDownOnPanic.
type TestFixture interface {
	TearDown(t *testing.T)
}

// TearDownOnPanic can be used to ensure cleanup on setup failure.
func TearDownOnPanic(t *testing.T, f TestFixture) {
	if r := recover(); r != nil {
		f.TearDown(t)
		panic(r)
	}
}
