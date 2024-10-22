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

var _ = Describe("RuntimeAgentKVStoreTest", func() {
	var vm *helpers.SSHMeta
	var testStartTime time.Time

	BeforeAll(func() {
		vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)
		vm.ExecWithSudo("systemctl stop cilium")
		ExpectCiliumNotRunning(vm)
	})

	containers := func(option string) {
		switch option {
		case helpers.Create:
			vm.NetworkCreate(helpers.CiliumDockerNetwork, "")
			res := vm.ContainerCreate(helpers.Client, constants.NetperfImage, helpers.CiliumDockerNetwork, "-l id.client")
			res.ExpectSuccess("failed to create client container")
		case helpers.Delete:
			vm.ContainerRm(helpers.Client)

		}
	}

	JustBeforeEach(func() {
		testStartTime = time.Now()
	})

	AfterEach(func() {
		containers(helpers.Delete)
	})

	JustAfterEach(func() {
		vm.ValidateNoErrorsInLogs(time.Since(testStartTime))
	})

	AfterFailed(func() {
		vm.ReportFailed("cilium-dbg status")
	})

	AfterAll(func() {
		// Other runtime tests fail if using etcd, as cilium-operator is not functional
		// without k8s.
		err := vm.SetUpCilium()
		Expect(err).Should(BeNil(), "Cilium failed to start")
		ExpectCiliumReady(vm)
		vm.CloseSSHClient()
	})

	Context("KVStore tests", func() {
		It("Etcd KVStore", func() {
			By("Starting Cilium with etcd as kvstore")
			err := vm.SetUpCiliumWithOptions("--kvstore etcd --kvstore-opt etcd.address=127.0.0.1:4001")
			Expect(err).Should(BeNil(), "Cilium failed to start")

			By("Restarting cilium-docker service")
			vm.Exec("sudo systemctl restart cilium-docker")
			Expect(vm.WaitDockerPluginReady()).Should(BeTrue(), "Docker plugin is not ready after timeout")
			ExpectCiliumReady(vm)

			containers(helpers.Create)

			Expect(vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")

			eps, err := vm.GetEndpointsNames()
			Expect(err).Should(BeNil(), "Error getting names of endpoints from cilium")
			Expect(len(eps)).To(Equal(1), "Number of endpoints in Cilium differs from what is expected")
		})
	})
})
