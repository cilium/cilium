// Copyright 2017 Authors of Cilium
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

import (
	"time"

	. "gopkg.in/check.v1"
)

func (ds *DaemonSuite) TestK8sErrorLogTimeout(c *C) {
	errstr := "I am an error string"

	// ensure k8sErrMsg is empty for tests that use it
	k8sErrMsgMU.Lock()
	k8sErrMsg = map[string]time.Time{}
	k8sErrMsgMU.Unlock()

	// Returns true because it's the first time we see this message
	startTime := time.Now()
	c.Assert(k8sErrorUpdateCheckUnmuteTime(errstr, startTime), Equals, true)

	// Returns false because <= k8sErrLogTimeout time has passed
	noLogTime := startTime.Add(k8sErrLogTimeout)
	c.Assert(k8sErrorUpdateCheckUnmuteTime(errstr, noLogTime), Equals, false)

	// Returns true because k8sErrLogTimeout has passed
	shouldLogTime := startTime.Add(k8sErrLogTimeout).Add(time.Nanosecond)
	c.Assert(k8sErrorUpdateCheckUnmuteTime(errstr, shouldLogTime), Equals, true)
}
