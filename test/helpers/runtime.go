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

package helpers

import (
	"fmt"

	"github.com/onsi/ginkgo"
	"github.com/sirupsen/logrus"
)

// InitRuntimeHelper returns SSHMeta helper for running the runtime tests
// on the provided VM target and using logger 'log'. It marks the test as Fail
// if it cannot get the ssh meta information or cannot execute a `ls` on the
// virtual machine.
//
// This function does not set up cilium, so it should only be run by the
// test_suite; test writers should use CreateNewRuntimeHelper() instead.
func InitRuntimeHelper(target string, log *logrus.Entry) *SSHMeta {
	node := GetVagrantSSHMeta(target)
	if node == nil {
		ginkgo.Fail(fmt.Sprintf("Cannot connect to target '%s'", target), 1)
		return nil
	}

	// This `ls` command is a sanity check, sometimes the meta ssh info is not
	// nil but new commands cannot be executed using SSH, tests failed and it
	// was hard to debug.
	res := node.Exec("ls /tmp/")
	if !res.WasSuccessful() {
		ginkgo.Fail(fmt.Sprintf(
			"Cannot execute ls command on target '%s'", target), 1)
		return nil
	}

	node.logger = log
	return node
}

// CreateNewRuntimeHelper returns SSHMeta helper for running the runtime tests
// on the provided VM target and using logger log. It marks the test as Fail if
// the framework is unable to gain SSH access to the VM and run commands.
func CreateNewRuntimeHelper(target string, log *logrus.Entry) *SSHMeta {
	node := InitRuntimeHelper(target, log)
	node.WaitUntilReady(100)
	node.NetworkCreate(CiliumDockerNetwork, "")

	res := node.SetPolicyEnforcement(PolicyEnforcementDefault)
	if !res.WasSuccessful() {
		ginkgo.Fail(fmt.Sprintf(
			"Cannot set default policy enforcement on target '%s'",
			target), 1)
		return nil
	}

	return node
}
