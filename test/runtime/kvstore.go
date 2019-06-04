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
	"context"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	"github.com/cilium/cilium/test/helpers/constants"

	. "github.com/onsi/gomega"
)

var _ = Describe("RuntimeKVStoreTest", func() {

	var vm *helpers.SSHMeta

	BeforeAll(func() {
		vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)
		ExpectCiliumReady(vm)
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

	BeforeEach(func() {
		res := vm.ExecWithSudo("systemctl stop cilium")
		res.ExpectSuccess("Failed trying to stop cilium via systemctl")
		ExpectCiliumNotRunning(vm)
	}, 150)

	AfterEach(func() {
		containers(helpers.Delete)
		err := vm.RestartCilium()
		Expect(err).Should(BeNil(), "restarting Cilium failed")
	})

	JustAfterEach(func() {
		vm.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
	})

	AfterFailed(func() {
		vm.ReportFailed("cilium status")
	})

	AfterAll(func() {
		vm.CloseSSHClient()
	})

	It("Consul KVStore", func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		By("Starting Cilium with consul as kvstore")
		vm.ExecInBackground(
			ctx,
			"sudo cilium-agent --kvstore consul --kvstore-opt consul.address=127.0.0.1:8500 --debug")
		err := vm.WaitUntilReady(helpers.CiliumStartTimeout)
		Expect(err).Should(BeNil())

		By("Restarting cilium-docker service")
		vm.Exec("sudo systemctl restart cilium-docker")
		helpers.Sleep(2)
		containers(helpers.Create)
		vm.WaitEndpointsReady()
		eps, err := vm.GetEndpointsNames()
		Expect(err).Should(BeNil(), "Error getting names of endpoints from cilium")
		Expect(len(eps)).To(Equal(1), "Number of endpoints in Cilium differs from what is expected")
	})

	It("Etcd KVStore", func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		By("Starting Cilium with etcd as kvstore")
		vm.ExecInBackground(
			ctx,
			"sudo cilium-agent --kvstore etcd --kvstore-opt etcd.address=127.0.0.1:4001 2>&1 | logger -t cilium")
		err := vm.WaitUntilReady(helpers.CiliumStartTimeout)
		Expect(err).Should(BeNil(), "Timed out waiting for VM to be ready after restarting Cilium")

		By("Restarting cilium-docker service")
		vm.Exec("sudo systemctl restart cilium-docker")
		helpers.Sleep(2)
		containers(helpers.Create)

		vm.WaitEndpointsReady()

		eps, err := vm.GetEndpointsNames()
		Expect(err).Should(BeNil(), "Error getting names of endpoints from cilium")
		Expect(len(eps)).To(Equal(1), "Number of endpoints in Cilium differs from what is expected")
	})
})
