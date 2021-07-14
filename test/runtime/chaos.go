// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2020 Authors of Cilium

package RuntimeTest

import (
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	"github.com/cilium/cilium/test/helpers/constants"

	. "github.com/onsi/gomega"
)

var _ = Describe("RuntimeChaos", func() {
	var vm *helpers.SSHMeta

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

	JustAfterEach(func() {
		vm.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
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
