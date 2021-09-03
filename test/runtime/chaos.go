// Copyright 2017-2020 Authors of Cilium
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

package RuntimeTest

import (
	"time"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	"github.com/cilium/cilium/test/helpers/constants"

	. "github.com/onsi/gomega"
)

var _ = Describe("RuntimeChaos", func() {
	var (
		vm            *helpers.SSHMeta
		testStartTime time.Time
	)

	BeforeAll(func() {
		vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)
		ExpectCiliumReady(vm)

		vm.ContainerCreate(helpers.Client, constants.NetperfImage, helpers.CiliumDockerNetwork, "-l id.client")
		vm.ContainerCreate(helpers.Server, constants.NetperfImage, helpers.CiliumDockerNetwork, "-l id.server")
	})

	BeforeEach(func() {
		Expect(vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")
	})

	AfterAll(func() {
		vm.ContainerRm(helpers.Client)
		vm.ContainerRm(helpers.Server)
		vm.SampleContainersActions(helpers.Delete, helpers.CiliumDockerNetwork)
		vm.CloseSSHClient()
	})

	AfterEach(func() {
		vm.PolicyDelAll()
	})

	JustBeforeEach(func() {
		testStartTime = time.Now()
	})

	JustAfterEach(func() {
		vm.ValidateNoErrorsInLogs(time.Since(testStartTime))
		ExpectDockerContainersMatchCiliumEndpoints(vm)
	})

	AfterFailed(func() {
		vm.ReportFailed()
	})

	Context("Endpoint", endpointChaosTest)

	Context("Cilium agent", agentChaosTests)

	Context("Connectivity over restarts", restartChaosTest)

	Context("KVStore", kvstoreChaosTests)
})
