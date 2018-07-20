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

package RuntimeTest

import (
	"context"
	"sync"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

var _ = Describe("RuntimeValidatedKVStoreTest", func() {

	var once sync.Once
	var vm *helpers.SSHMeta

	initialize := func() {
		vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)
		ExpectCiliumReady(vm)
	}
	containers := func(option string) {
		switch option {
		case helpers.Create:
			vm.NetworkCreate(helpers.CiliumDockerNetwork, "")
			vm.ContainerCreate(helpers.Client, helpers.NetperfImage, helpers.CiliumDockerNetwork, "-l id.client")
		case helpers.Delete:
			vm.ContainerRm(helpers.Client)

		}
	}

	BeforeEach(func() {
		once.Do(initialize)
		vm.Exec("sudo systemctl stop cilium")
	}, 150)

	AfterEach(func() {
		containers(helpers.Delete)
		vm.Exec("sudo systemctl start cilium")
	})

	JustAfterEach(func() {
		vm.ValidateNoErrorsOnLogs(CurrentGinkgoTestDescription().Duration)
	})

	AfterFailed(func() {
		vm.ReportFailed("cilium status")
	})

	It("Consul KVStore", func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		vm.ExecContext(
			ctx,
			"sudo cilium-agent --kvstore consul --kvstore-opt consul.address=127.0.0.1:8500 --debug")
		err := vm.WaitUntilReady(150)
		Expect(err).Should(BeNil())

		vm.Exec("sudo systemctl restart cilium-docker")
		helpers.Sleep(2)
		containers(helpers.Create)
		vm.WaitEndpointsReady()
		eps, err := vm.GetEndpointsNames()
		Expect(err).Should(BeNil())
		Expect(len(eps)).To(Equal(1))
	})

	It("Etcd KVStore", func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		vm.ExecContext(
			ctx,
			"sudo cilium-agent --kvstore etcd --kvstore-opt etcd.address=127.0.0.1:4001 2>&1 | logger -t cilium")
		err := vm.WaitUntilReady(150)
		Expect(err).Should(BeNil())

		vm.Exec("sudo systemctl restart cilium-docker")
		helpers.Sleep(2)
		containers(helpers.Create)

		vm.WaitEndpointsReady()

		eps, err := vm.GetEndpointsNames()
		Expect(err).Should(BeNil())
		Expect(len(eps)).To(Equal(1))
	})
})
