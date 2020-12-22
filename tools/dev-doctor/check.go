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
