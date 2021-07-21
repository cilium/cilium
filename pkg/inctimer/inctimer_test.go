// Copyright 2020 Authors of Cilium
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

// +build !privileged_tests

package inctimer

import (
	"testing"
	"time"
)

func TestTimerAfter(t *testing.T) {
	for i := 0; i < 100_000; i++ {
		tr, done := New()
		select {
		case <-tr.After(time.Second):
			t.Fatal("`IncTimer` fired too soon")
		default:
		}
		done()
	}
}

func TestTimerHardReset(t *testing.T) {
	tr, done := New()
	defer done()
	for i := 0; i < 100; i++ {
		select {
		case <-tr.After(time.Millisecond):
		case <-time.After(time.Millisecond * 2):
			t.Fatal("`IncTimer`, after being reset, did not fire")
		}
	}
}
