// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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
