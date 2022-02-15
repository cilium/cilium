// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

// A checkResult is the result of a check.
type checkResult int

const (
	checkSkipped checkResult = -1 // The check was skipped.
	checkOK      checkResult = 0  // The check completed and did not find any problems.
	checkInfo    checkResult = 1  // The check completed and found something of interest which is probably not a problem.
	checkWarning checkResult = 2  // The check completed and found something that might indicate a problem.
	checkError   checkResult = 3  // The check completed and found a definite problem.
	checkFailed  checkResult = 4  // The check could not be completed.
)

// A check is an individual check.
type check interface {
	Name() string               // Name returns the check's name.
	Run() (checkResult, string) // Run runs the check.
	Hint() string               // Hint returns a hint on how to fix the problem, if any.
}

var checkResultStr = map[checkResult]string{
	checkSkipped: "skipped",
	checkOK:      "ok",
	checkInfo:    "info",
	checkWarning: "warning",
	checkError:   "error",
	checkFailed:  "failed",
}
