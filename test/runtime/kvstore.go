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
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/identity"
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

	JustBeforeEach(func() {
		testStartTime = time.Now()
	})

	AfterEach(func() {
		containers(helpers.Delete)
		err := vm.RestartCilium()
		Expect(err).Should(BeNil(), "restarting Cilium failed")
	})

	JustAfterEach(func() {
		vm.ValidateNoErrorsInLogs(time.Since(testStartTime))
	})

	AfterFailed(func() {
		vm.ReportFailed("cilium status")
	})

	AfterAll(func() {
		vm.CloseSSHClient()
	})

	Context("KVStore tests", func() {
		It("Consul KVStore", func() {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			By("Starting Cilium with consul as kvstore")
			vm.ExecInBackground(
				ctx,
				"sudo cilium-agent --kvstore consul --kvstore-opt consul.address=127.0.0.1:8500 --debug 2>&1 | logger -t cilium")
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
				"sudo cilium-agent --kvstore etcd --kvstore-opt etcd.address=127.0.0.1:4001 --debug 2>&1 | logger -t cilium")
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
})

var kvstoreChaosTests = func() {
	var vm *helpers.SSHMeta

	BeforeAll(func() {
		vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)
	})

	AfterAll(func() {
		vm.CloseSSHClient()
	})

	It("Validate that delete events on KVStore do not release in use identities", func() {
		// This validates that if a kvstore delete event is send the identity
		// is not release if it is in use. For more info issue #7240

		prefix := "http://127.0.0.1:8500/v1/kv/cilium/state/identities/v1/id"
		identities, err := vm.GetEndpointsIdentityIds()
		Expect(err).To(BeNil(), "Cannot get identities")

		By("Deleting identities from kvstore")
		for _, identityID := range identities {
			action := helpers.CurlFail("%s/%s -X DELETE", prefix, identityID)
			vm.Exec(action).ExpectSuccess("Key %s cannot be deleted correctly", identityID)
		}

		newidentities, err := vm.GetEndpointsIdentityIds()
		Expect(err).To(BeNil(), "Cannot get identities after delete keys")

		Expect(newidentities).To(Equal(identities),
			"Identities are not the same after delete keys from kvstore")

		By("Checking that identities were restored correctly after deletion")
		for _, identityID := range newidentities {
			id, err := identity.ParseNumericIdentity(identityID)
			Expect(err).To(BeNil(), "Cannot parse identity")
			if id.IsReservedIdentity() {
				continue
			}
			action := helpers.CurlFail("%s/%s", prefix, identityID)
			vm.Exec(action).ExpectSuccess("Key %s was not restored correctly", identityID)
		}
	})

	It("Delete event on KVStore with CIDR identities", func() {
		// Validate that if when a delete event happens on kvstore the CIDR
		// identity (local one) is not deleted.  This happens on the past where
		// other cilium agent executes a deletion of a key that was used by
		// another cilium agent, that means that on policy regeneration the
		// identity was not present.
		jqFilter := `jq -r '.[] | select(.labels|join("") | contains("cidr")) | .id'`
		prefix := "http://127.0.0.1:8500/v1/kv/cilium/state/identities/v1/id"

		By("Installing CIDR policy")
		policy := `
		[{
			"endpointSelector": {"matchLabels":{"test":""}},
			"egress":
			[{
				"toCIDR": [
					"10.10.10.10/32"
				]
			}]
		}]
		`
		_, err := vm.PolicyRenderAndImport(policy)
		Expect(err).To(BeNil(), "Unable to import policy: %s", err)

		CIDRIdentities := vm.Exec(fmt.Sprintf(`cilium identity list -o json| %s`, jqFilter))
		CIDRIdentities.ExpectSuccess("Cannot get cidr identities")

		for _, identityID := range CIDRIdentities.ByLines() {
			action := helpers.CurlFail("%s/%s -X DELETE", prefix, identityID)
			vm.Exec(action).ExpectSuccess("Key %s cannot be deleted correctly", identityID)
		}

		newCIDRIdentities := vm.Exec(fmt.Sprintf(`cilium identity list -o json| %s`, jqFilter))
		newCIDRIdentities.ExpectSuccess("Cannot get cidr identities")

		Expect(CIDRIdentities.ByLines()).To(Equal(newCIDRIdentities.ByLines()),
			"Identities are deleted in kvstore delete event")
	})
}
