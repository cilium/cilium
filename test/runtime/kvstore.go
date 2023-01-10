// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package RuntimeTest

import (
	"fmt"
	"time"

	. "github.com/onsi/gomega"

	"github.com/cilium/cilium/pkg/identity"
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
			Expect(vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")
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

			Expect(vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")

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
