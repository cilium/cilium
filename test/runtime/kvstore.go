// Copyright 2017-2019 Authors of Cilium
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

var _ = Describe("RuntimeKVStoreTest", func() {
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
			vm.ContainerCreate(helpers.Client, constants.NetperfImage, helpers.CiliumDockerNetwork, "-l id.client")
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
		vm.ReportFailed("cilium status")
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
		It("Consul KVStore", func() {
			By("Starting Cilium with consul as kvstore")
			err := vm.SetUpCiliumWithOptions("--kvstore consul --kvstore-opt consul.address=127.0.0.1:8500")
			Expect(err).Should(BeNil(), "Cilium failed to start")

			By("Restarting cilium-docker service")
			vm.Exec("sudo systemctl restart cilium-docker")
			Expect(vm.WaitDockerPluginReady()).Should(BeTrue(), "Docker plugin is not ready after timeout")
			ExpectCiliumReady(vm)

			containers(helpers.Create)
			vm.WaitEndpointsReady()
			eps, err := vm.GetEndpointsNames()
			Expect(err).Should(BeNil(), "Error getting names of endpoints from cilium")
			Expect(len(eps)).To(Equal(1), "Number of endpoints in Cilium differs from what is expected")
		})

		It("Etcd KVStore", func() {
			By("Starting Cilium with etcd as kvstore")
			err := vm.SetUpCiliumWithOptions("--kvstore etcd --kvstore-opt etcd.address=127.0.0.1:4001")
			Expect(err).Should(BeNil(), "Cilium failed to start")

			By("Restarting cilium-docker service")
			vm.Exec("sudo systemctl restart cilium-docker")
			Expect(vm.WaitDockerPluginReady()).Should(BeTrue(), "Docker plugin is not ready after timeout")
			ExpectCiliumReady(vm)

			containers(helpers.Create)

			vm.WaitEndpointsReady()

			eps, err := vm.GetEndpointsNames()
			Expect(err).Should(BeNil(), "Error getting names of endpoints from cilium")
			Expect(len(eps)).To(Equal(1), "Number of endpoints in Cilium differs from what is expected")
		})
	})
})
