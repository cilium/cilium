// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package RuntimeTest

import (
	"time"

	. "github.com/onsi/gomega"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	"github.com/cilium/cilium/test/helpers/constants"
)

var _ = Describe("RuntimeAgentChaos", func() {
	var (
		vm            *helpers.SSHMeta
		testStartTime time.Time
	)

	BeforeAll(func() {
		vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)
		ExpectCiliumReady(vm)

		res := vm.ContainerCreate(helpers.Client, constants.NetperfImage, helpers.CiliumDockerNetwork, "-l id.client")
		res.ExpectSuccess("failed to create client container")
		res = vm.ContainerCreate(helpers.Server, constants.NetperfImage, helpers.CiliumDockerNetwork, "-l id.server")
		res.ExpectSuccess("failed to create server container")
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
