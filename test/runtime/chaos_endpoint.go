// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package RuntimeTest

import (
	"crypto/md5"
	"fmt"
	"strings"

	. "github.com/onsi/gomega"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
)

var endpointChaosTest = func() {
	var vm *helpers.SSHMeta

	BeforeAll(func() {
		vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)
	})

	AfterAll(func() {
		vm.CloseSSHClient()
	})

	It("Endpoint recovery on restart", func() {
		hasher := md5.New()

		originalIps := vm.Exec(`
		curl -s --unix-socket /var/run/cilium/cilium.sock \
		http://localhost/v1beta/healthz/ | jq ".ipam.ipv4|length"`)

		// List the endpoints, but skip the reserved:health endpoint
		// (4) because it doesn't matter if that endpoint is different.
		// Remove fields that are expected to change across restart.
		//
		// We don't use -o jsonpath... here due to GH-2395.
		//
		// jq 'map(select(.status.identity.id != 4), del(.status.controllers, ..., (.status.identity.labels | sort)))'
		filterHealthEP := fmt.Sprintf("select(.status.identity.id != %d)", helpers.ReservedIdentityHealth)
		nonPersistentEndpointFields := strings.Join([]string{
			".status.controllers",     // Timestamps, UUIDs
			".status.labels",          // Slice ordering
			".status.log",             // Timestamp
			".status.identity.labels", // Slice ordering
			".status.policy",          // Allowed identities order
		}, ", ")
		// Delete fields we're not interested in
		filterFields := fmt.Sprintf("del(%s)", nonPersistentEndpointFields)
		// Go back and add the identity labels back into the output
		getSortedLabels := "(.status.identity.labels | sort)"
		jqCmd := fmt.Sprintf("jq 'map(%s) | map(%s, %s)'", filterHealthEP, filterFields, getSortedLabels)
		endpointListCmd := fmt.Sprintf("cilium endpoint list -o json | %s", jqCmd)
		originalEndpointList := vm.Exec(endpointListCmd)

		err := vm.RestartCilium()
		Expect(err).Should(BeNil(), "restarting Cilium failed")

		ips := vm.Exec(`
		curl -s --unix-socket /var/run/cilium/cilium.sock \
		http://localhost/v1beta/healthz/ | jq ".ipam.ipv4|length"`)
		Expect(originalIps.Stdout()).To(Equal(ips.Stdout()))

		EndpointList := vm.Exec(endpointListCmd)
		By("original: %s", originalEndpointList.Stdout())
		By("new: %s", EndpointList.Stdout())
		Expect(EndpointList.Stdout()).To(Equal(originalEndpointList.Stdout()))
		Expect(hasher.Sum(EndpointList.GetStdOut().Bytes())).To(
			Equal(hasher.Sum(originalEndpointList.GetStdOut().Bytes())))

	}, 300)
}
