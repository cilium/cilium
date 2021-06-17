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

package testutils

import (
	"fmt"
	"time"
)

// ConditionFunc is the function implementing the condition, it must return
// true if the condition has been met
type ConditionFunc func() bool

// WaitUntil evaluates the condition every 10 milliseconds and waits for the
// condition to be met. The function will time out and return an error after
// timeout

func WaitUntil(condition ConditionFunc, timeout time.Duration) error {
	return WaitUntilWithSleep(condition, timeout, 10*time.Millisecond)
}

// WaitUntilWithSleep does the same as WaitUntil except that the sleep time
// between the condition checks is given.
func WaitUntilWithSleep(condition ConditionFunc, timeout, sleep time.Duration) error {
	now := time.Now()
	for {
		if time.Since(now) > timeout {
			return fmt.Errorf("timeout reached while waiting for condition")
		}

		if condition() {
			return nil
		}

		time.Sleep(sleep)
	}
}
