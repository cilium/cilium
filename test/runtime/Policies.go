// Copyright 2017-2018 Authors of Cilium
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
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/cilium/cilium/pkg/policy/api"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	"github.com/sirupsen/logrus"
)

const (
	// Commands
	ping         = "ping"
	ping6        = "ping6"
	http         = "http"
	http6        = "http6"
	httpPrivate  = "http_private"
	http6Private = "http6_private"

	// Policy files
	policyJSON         = "policy.json"
	invalidJSON        = "invalid.json"
	sampleJSON         = "sample_policy.json"
	ingressJSON        = "ingress.json"
	egressJSON         = "egress.json"
	multL7PoliciesJSON = "Policies-l7-multiple.json"
	policiesL7JSON     = "Policies-l7-simple.json"
	policiesL3JSON     = "Policies-l3-policy.json"
)

var _ = Describe("RuntimeValidatedPolicyEnforcement", func() {

	var logger *logrus.Entry
	var vm *helpers.SSHMeta

	BeforeAll(func() {
		logger = log.WithFields(logrus.Fields{"testName": "RuntimePolicyEnforcement"})
		logger.Info("Starting")
		vm = helpers.CreateNewRuntimeHelper(helpers.Runtime, logger)
		vm.ContainerCreate("app", "cilium/demo-httpd", helpers.CiliumDockerNetwork, "-l id.app")
		areEndpointsReady := vm.WaitEndpointsReady()
		Expect(areEndpointsReady).Should(BeTrue(), "Endpoints are not ready after timeout")
	})

	AfterAll(func() {
		vm.ContainerRm("app")
	})

	BeforeEach(func() {
		vm.PolicyDelAll()

		areEndpointsReady := vm.WaitEndpointsReady()
		Expect(areEndpointsReady).Should(BeTrue(), "Endpoints are not ready after timeout")
	})

	JustAfterEach(func() {
		vm.ValidateNoErrorsOnLogs(CurrentGinkgoTestDescription().Duration)
	})

	AfterFailed(func() {
		vm.ReportFailed()
	})

	Context("Policy Enforcement Default", func() {

		BeforeEach(func() {
			res := vm.SetPolicyEnforcement(helpers.PolicyEnforcementDefault)
			res.ExpectSuccess()

			areEndpointsReady := vm.WaitEndpointsReady()
			Expect(areEndpointsReady).Should(BeTrue())
		})

		It("Default values", func() {

			By("Policy Enforcement should be disabled for containers", func() {
				endPoints, err := vm.PolicyEndpointsSummary()
				Expect(err).Should(BeNil())
				Expect(endPoints[helpers.Disabled]).To(Equal(1))
			})

			By("Apply a new sample policy")
			_, err := vm.PolicyImportAndWait(vm.GetFullPath(sampleJSON), helpers.HelperTimeout)
			Expect(err).Should(BeNil())

			endPoints, err := vm.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(1))
		})

		It("Default to Always without policy", func() {
			By("Check no policy enforcement")
			endPoints, err := vm.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Disabled]).To(Equal(1))

			By("Setting to Always")

			res := vm.SetPolicyEnforcement(helpers.PolicyEnforcementAlways)
			res.ExpectSuccess()

			areEndpointsReady := vm.WaitEndpointsReady()
			Expect(areEndpointsReady).Should(BeTrue())

			endPoints, err = vm.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(1))

			By("Setting to default from Always")
			res = vm.SetPolicyEnforcement(helpers.PolicyEnforcementDefault)
			res.ExpectSuccess()

			areEndpointsReady = vm.WaitEndpointsReady()
			Expect(areEndpointsReady).Should(BeTrue())

			endPoints, err = vm.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Disabled]).To(Equal(1))
		})

		It("Default to Always with policy", func() {
			_, err := vm.PolicyImportAndWait(vm.GetFullPath(sampleJSON), helpers.HelperTimeout)
			Expect(err).Should(BeNil())

			endPoints, err := vm.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(1))
			//DEfault =APP with PolicyEnforcement

			res := vm.SetPolicyEnforcement(helpers.PolicyEnforcementAlways)
			res.ExpectSuccess()

			areEndpointsReady := vm.WaitEndpointsReady()
			Expect(areEndpointsReady).Should(BeTrue())

			endPoints, err = vm.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(1))

			res = vm.SetPolicyEnforcement(helpers.PolicyEnforcementDefault)
			res.ExpectSuccess()

			areEndpointsReady = vm.WaitEndpointsReady()
			Expect(areEndpointsReady).Should(BeTrue())

			endPoints, err = vm.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(1))
		})

		It("Default to Never without policy", func() {
			endPoints, err := vm.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Disabled]).To(Equal(1))

			res := vm.SetPolicyEnforcement(helpers.PolicyEnforcementNever)
			res.ExpectSuccess()

			areEndpointsReady := vm.WaitEndpointsReady()
			Expect(areEndpointsReady).Should(BeTrue())

			endPoints, err = vm.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Disabled]).To(Equal(1))

			endPoints, err = vm.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Disabled]).To(Equal(1))
		})

		It("Default to Never with policy", func() {

			_, err := vm.PolicyImportAndWait(vm.GetFullPath(sampleJSON), helpers.HelperTimeout)
			Expect(err).Should(BeNil())

			endPoints, err := vm.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(1))

			res := vm.SetPolicyEnforcement(helpers.PolicyEnforcementNever)
			res.ExpectSuccess()

			areEndpointsReady := vm.WaitEndpointsReady()
			Expect(areEndpointsReady).Should(BeTrue())

			endPoints, err = vm.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(0))

			res = vm.SetPolicyEnforcement(helpers.PolicyEnforcementDefault)
			res.ExpectSuccess()

			areEndpointsReady = vm.WaitEndpointsReady()
			Expect(areEndpointsReady).Should(BeTrue())

			endPoints, err = vm.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(1))
		})
	})

	Context("Policy Enforcement Always", func() {
		//The test Always to Default is already tested in from default-always
		BeforeEach(func() {
			res := vm.SetPolicyEnforcement(helpers.PolicyEnforcementAlways)
			res.ExpectSuccess()

			areEndpointsReady := vm.WaitEndpointsReady()
			Expect(areEndpointsReady).Should(BeTrue())
		})

		It("Container creation", func() {
			//Check default containers are in place.
			endPoints, err := vm.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(1))
			Expect(endPoints[helpers.Disabled]).To(Equal(0))

			By("Create a new container")
			vm.ContainerCreate("new", "cilium/demo-httpd", helpers.CiliumDockerNetwork, "-l id.new")
			endPoints, err = vm.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(2))
			Expect(endPoints[helpers.Disabled]).To(Equal(0))
			vm.ContainerRm("new")
		}, 300)

		It("Always to Never with policy", func() {
			endPoints, err := vm.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(1))
			Expect(endPoints[helpers.Disabled]).To(Equal(0))

			_, err = vm.PolicyImportAndWait(vm.GetFullPath(sampleJSON), helpers.HelperTimeout)
			Expect(err).Should(BeNil())

			endPoints, err = vm.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(1))
			Expect(endPoints[helpers.Disabled]).To(Equal(0))

			res := vm.SetPolicyEnforcement(helpers.PolicyEnforcementNever)
			res.ExpectSuccess()

			areEndpointsReady := vm.WaitEndpointsReady()
			Expect(areEndpointsReady).Should(BeTrue())

			endPoints, err = vm.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(0))

			res = vm.SetPolicyEnforcement(helpers.PolicyEnforcementAlways)
			res.ExpectSuccess()

			areEndpointsReady = vm.WaitEndpointsReady()
			Expect(areEndpointsReady).Should(BeTrue())

			endPoints, err = vm.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(1))
		})

		It("Always to Never without policy", func() {
			endPoints, err := vm.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(1))
			Expect(endPoints[helpers.Disabled]).To(Equal(0))

			res := vm.SetPolicyEnforcement(helpers.PolicyEnforcementNever)
			res.ExpectSuccess()

			areEndpointsReady := vm.WaitEndpointsReady()
			Expect(areEndpointsReady).Should(BeTrue())

			endPoints, err = vm.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(0))
			Expect(endPoints[helpers.Disabled]).To(Equal(1))

			res = vm.SetPolicyEnforcement(helpers.PolicyEnforcementAlways)
			res.ExpectSuccess()

			areEndpointsReady = vm.WaitEndpointsReady()
			Expect(areEndpointsReady).Should(BeTrue())

			endPoints, err = vm.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(1))
		})

	})

	Context("Policy Enforcement Never", func() {
		//The test Always to Default is already tested in from default-always
		BeforeEach(func() {
			res := vm.SetPolicyEnforcement(helpers.PolicyEnforcementNever)
			res.ExpectSuccess()
		})

		It("Container creation", func() {
			//Check default containers are in place.
			endPoints, err := vm.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(0))
			Expect(endPoints[helpers.Disabled]).To(Equal(1))

			vm.ContainerCreate("new", "cilium/demo-httpd", helpers.CiliumDockerNetwork, "-l id.new")
			vm.WaitEndpointsReady()
			endPoints, err = vm.PolicyEndpointsSummary()

			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(0))
			Expect(endPoints[helpers.Disabled]).To(Equal(2))
			vm.ContainerRm("new")
		}, 300)

		It("Never to default with policy", func() {
			endPoints, err := vm.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(0))
			Expect(endPoints[helpers.Disabled]).To(Equal(1))

			_, err = vm.PolicyImportAndWait(vm.GetFullPath(sampleJSON), helpers.HelperTimeout)
			Expect(err).Should(BeNil())

			endPoints, err = vm.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(0))
			Expect(endPoints[helpers.Disabled]).To(Equal(1))

			res := vm.SetPolicyEnforcement(helpers.PolicyEnforcementDefault)
			res.ExpectSuccess()

			areEndpointsReady := vm.WaitEndpointsReady()
			Expect(areEndpointsReady).Should(BeTrue())

			endPoints, err = vm.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(1))
			Expect(endPoints[helpers.Disabled]).To(Equal(0))

			res = vm.SetPolicyEnforcement(helpers.PolicyEnforcementNever)
			res.ExpectSuccess()

			areEndpointsReady = vm.WaitEndpointsReady()
			Expect(areEndpointsReady).Should(BeTrue())

			endPoints, err = vm.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(0))
			Expect(endPoints[helpers.Disabled]).To(Equal(1))
		})

		It("Never to default without policy", func() {
			endPoints, err := vm.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(0))
			Expect(endPoints[helpers.Disabled]).To(Equal(1))

			res := vm.SetPolicyEnforcement(helpers.PolicyEnforcementDefault)
			res.ExpectSuccess()

			areEndpointsReady := vm.WaitEndpointsReady()
			Expect(areEndpointsReady).Should(BeTrue())

			endPoints, err = vm.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(0))
			Expect(endPoints[helpers.Disabled]).To(Equal(1))

			res = vm.SetPolicyEnforcement(helpers.PolicyEnforcementNever)
			res.ExpectSuccess()

			areEndpointsReady = vm.WaitEndpointsReady()
			Expect(areEndpointsReady).Should(BeTrue())

			endPoints, err = vm.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(0))
			Expect(endPoints[helpers.Disabled]).To(Equal(1))
		})
	})
})

var _ = Describe("RuntimeValidatedPolicies", func() {

	var logger *logrus.Entry
	var vm *helpers.SSHMeta

	BeforeAll(func() {
		logger = log.WithFields(logrus.Fields{"test": "RunPolicies"})
		logger.Info("Starting")
		vm = helpers.CreateNewRuntimeHelper(helpers.Runtime, logger)

		vm.SampleContainersActions(helpers.Create, helpers.CiliumDockerNetwork)
		vm.PolicyDelAll()

		areEndpointsReady := vm.WaitEndpointsReady()
		Expect(areEndpointsReady).Should(BeTrue(), "Endpoints are not ready after timeout")
	})

	BeforeEach(func() {
		res := vm.SetPolicyEnforcement(helpers.PolicyEnforcementDefault)
		res.ExpectSuccess()

		areEndpointsReady := vm.WaitEndpointsReady()
		Expect(areEndpointsReady).Should(BeTrue(), "Endpoints are not ready after timeout")
	})

	AfterEach(func() {
		vm.PolicyDelAll().ExpectSuccess("Unable to delete all policies")
	})

	JustAfterEach(func() {
		vm.ValidateNoErrorsOnLogs(CurrentGinkgoTestDescription().Duration)
	})

	AfterFailed(func() {
		vm.ReportFailed()
	})

	AfterAll(func() {
		vm.PolicyDelAll().ExpectSuccess("Unable to delete all policies")
		vm.SampleContainersActions(helpers.Delete, helpers.CiliumDockerNetwork)
	})

	pingRequests := []string{ping, ping6}
	httpRequestsPublic := []string{http, http6}
	httpRequestsPrivate := []string{httpPrivate, http6Private}
	httpRequests := append(httpRequestsPublic, httpRequestsPrivate...)
	allRequests := append(pingRequests, httpRequests...)
	connectivityTest := func(tests []string, client, server string, expectsSuccess bool) {
		var assertFn func() types.GomegaMatcher
		if expectsSuccess {
			assertFn = BeTrue
		} else {
			assertFn = BeFalse
		}

		_, err := vm.ContainerInspectNet(client)
		ExpectWithOffset(1, err).Should(BeNil(), fmt.Sprintf(
			"could not get container %q (client) meta", client))

		srvIP, err := vm.ContainerInspectNet(server)
		ExpectWithOffset(1, err).Should(BeNil(), fmt.Sprintf(
			"could not get container %q (server) meta", server))
		for _, test := range tests {
			var command, commandName, dst, resultName string
			switch test {
			case ping:
				command = helpers.Ping(srvIP[helpers.IPv4])
				dst = srvIP[helpers.IPv4]
			case ping6:
				command = helpers.Ping6(srvIP[helpers.IPv6])
				dst = srvIP[helpers.IPv6]
			case http, httpPrivate:
				dst = srvIP[helpers.IPv4]
			case http6, http6Private:
				dst = fmt.Sprintf("[%s]", srvIP[helpers.IPv6])
			}
			switch test {
			case ping, ping6:
				commandName = "ping"
			case http, http6:
				commandName = "curl public URL on"
				command = helpers.CurlFail("http://%s:80/public", dst)
			case httpPrivate, http6Private:
				commandName = "curl private URL on"
				command = helpers.CurlFail("http://%s:80/private", dst)
			}
			if expectsSuccess {
				resultName = "succeed"
			} else {
				resultName = "fail"
			}
			By(fmt.Sprintf("Client %q attempting to %s %s", client, commandName, server))
			res := vm.ContainerExec(client, command)
			ExpectWithOffset(1, res.WasSuccessful()).Should(assertFn(),
				fmt.Sprintf("%q expects %s %s (%s) to %s", client, commandName, server, dst, resultName))
		}
	}

	It("L3/L4 Checks", func() {
		_, err := vm.PolicyImportAndWait(vm.GetFullPath(policiesL3JSON), helpers.HelperTimeout)
		Expect(err).Should(BeNil())

		//APP1 can connect to all Httpd1
		connectivityTest(allRequests, helpers.App1, helpers.Httpd1, true)

		//APP2 can't connect to Httpd1
		connectivityTest([]string{http}, helpers.App2, helpers.Httpd1, false)

		// APP1 can reach using TCP HTTP2
		connectivityTest(httpRequestsPublic, helpers.App1, helpers.Httpd2, true)

		// APP2 can't reach using TCP to HTTP2
		connectivityTest(httpRequestsPublic, helpers.App2, helpers.Httpd2, false)

		// APP3 can reach using TCP to HTTP2, but can't ping due to egress rule.
		connectivityTest(httpRequestsPublic, helpers.App3, helpers.Httpd2, true)
		connectivityTest(pingRequests, helpers.App3, helpers.Httpd2, false)

		// APP3 can't reach using TCP to HTTP3
		connectivityTest(allRequests, helpers.App3, helpers.Httpd3, false)

		// app2 can reach httpd3 for all requests due to l3-only label-based allow policy.
		connectivityTest(allRequests, helpers.App2, helpers.Httpd3, true)

		// app2 cannot reach httpd2 for all requests.
		connectivityTest(allRequests, helpers.App2, helpers.Httpd2, false)

		By("Deleting all policies; all tests should succeed")

		status := vm.PolicyDelAll()
		status.ExpectSuccess()

		vm.WaitEndpointsReady()

		connectivityTest(allRequests, helpers.App1, helpers.Httpd1, true)
		connectivityTest(allRequests, helpers.App2, helpers.Httpd1, true)
	})

	It("L4Policy Checks", func() {
		_, err := vm.PolicyImportAndWait(vm.GetFullPath("Policies-l4-policy.json"), helpers.HelperTimeout)
		Expect(err).Should(BeNil())

		for _, app := range []string{helpers.App1, helpers.App2} {
			connectivityTest(pingRequests, app, helpers.Httpd1, false)
			connectivityTest(httpRequestsPublic, app, helpers.Httpd1, true)
			connectivityTest(pingRequests, app, helpers.Httpd2, false)
			connectivityTest(httpRequestsPublic, app, helpers.Httpd2, true)
		}
		connectivityTest(allRequests, helpers.App3, helpers.Httpd1, false)
		connectivityTest(pingRequests, helpers.App1, helpers.Httpd3, false)

		By("Disabling all the policies. All should work")

		status := vm.PolicyDelAll()
		Expect(status.WasSuccessful()).Should(BeTrue())

		vm.WaitEndpointsReady()

		for _, app := range []string{helpers.App1, helpers.App2} {
			connectivityTest(allRequests, app, helpers.Httpd1, true)
			connectivityTest(allRequests, app, helpers.Httpd2, true)
		}
	})

	It("L7 Checks", func() {

		_, err := vm.PolicyImportAndWait(vm.GetFullPath(policiesL7JSON), helpers.HelperTimeout)
		Expect(err).Should(BeNil())

		By("Simple Ingress")
		// app1 can connect to /public, but not to /private.
		connectivityTest(httpRequestsPublic, helpers.App1, helpers.Httpd1, true)
		connectivityTest(httpRequestsPrivate, helpers.App1, helpers.Httpd1, false)

		// app cannot connect to httpd1 because httpd1 only allows ingress from app1.
		connectivityTest(httpRequestsPublic, helpers.App2, helpers.Httpd1, false)

		By("Simple Egress")

		// app2 can connect to public, but no to private
		connectivityTest(httpRequestsPublic, helpers.App2, helpers.Httpd2, true)
		connectivityTest(httpRequestsPrivate, helpers.App2, helpers.Httpd2, false)

		// TODO (1488) - uncomment when l3-dependent-l7 is merged for egress.
		//connectivityTest(httpRequestsPublic, helpers.App3, helpers.Httpd3, true)
		//connectivityTest(httpRequestsPrivate, helpers.App3, helpers.Httpd3, false)
		//connectivityTest(allRequests, helpers.App3, helpers.Httpd2, false)

		By("Disabling all the policies. All should work")

		status := vm.PolicyDelAll()
		status.ExpectSuccess()

		vm.WaitEndpointsReady()

		connectivityTest(allRequests, helpers.App1, helpers.Httpd1, true)
		connectivityTest(allRequests, helpers.App2, helpers.Httpd1, true)

		By("Multiple Ingress")

		vm.PolicyDelAll()
		_, err = vm.PolicyImportAndWait(vm.GetFullPath(multL7PoliciesJSON), helpers.HelperTimeout)
		Expect(err).Should(BeNil())

		//APP1 can connnect to public, but no to private

		connectivityTest(httpRequestsPublic, helpers.App1, helpers.Httpd1, true)
		connectivityTest(httpRequestsPrivate, helpers.App1, helpers.Httpd1, false)

		//App2 can't connect
		connectivityTest(httpRequestsPublic, helpers.App2, helpers.Httpd1, false)

		By("Multiple Egress")
		// app2 can connect to /public, but not to /private
		connectivityTest(httpRequestsPublic, helpers.App2, helpers.Httpd2, true)
		connectivityTest(httpRequestsPrivate, helpers.App2, helpers.Httpd2, false)

		By("Disabling all the policies. All should work")

		status = vm.PolicyDelAll()
		status.ExpectSuccess()
		vm.WaitEndpointsReady()

		connectivityTest(allRequests, helpers.App1, helpers.Httpd1, true)
		connectivityTest(allRequests, helpers.App2, helpers.Httpd1, true)
	})

	It("Checks CIDR Policy", func() {

		ipv4Host := "192.168.254.254"
		ipv4OtherHost := "192.168.254.111"
		ipv4OtherNet := "99.11.0.0/16"
		ipv6Host := "fdff::ff"
		httpd2Label := "id.httpd2"
		httpd1Label := "id.httpd1"
		app3Label := "id.app3"

		log.Infof("IPV4 Address Host: %s", ipv4Host)
		log.Infof("IPV4 Address Other Host: %s", ipv4OtherHost)
		log.Infof("IPV4 Other Net: %s", ipv4OtherNet)
		log.Infof("IPV6 Host: %s", ipv6Host)

		// If the pseudo host IPs have not been removed since the last run but
		// Cilium was restarted, the IPs may have been picked up as valid host
		// IPs. Remove them from the list so they are not regarded as localhost
		// entries.
		// Don't care about success or failure as the BPF endpoint may not even be
		// present; this is best-effort.
		_ = vm.ExecCilium(fmt.Sprintf("bpf endpoint delete %s", ipv4Host))
		_ = vm.ExecCilium(fmt.Sprintf("bpf endpoint delete %s", ipv6Host))

		httpd1DockerNetworking, err := vm.ContainerInspectNet(helpers.Httpd1)
		Expect(err).Should(BeNil(), fmt.Sprintf(
			"could not get container %s Docker networking", helpers.Httpd1))

		ipv6Prefix := fmt.Sprintf("%s/112", httpd1DockerNetworking["IPv6Gateway"])
		ipv4Address := httpd1DockerNetworking[helpers.IPv4]

		// Get prefix of node-local endpoints.
		By("Getting IPv4 and IPv6 prefixes of node-local endpoints")
		getIpv4Prefix := vm.Exec(fmt.Sprintf(`expr %s : '\([0-9]*\.[0-9]*\.\)'`, ipv4Address)).SingleOut()
		ipv4Prefix := fmt.Sprintf("%s0.0/16", getIpv4Prefix)
		getIpv4PrefixExcept := vm.Exec(fmt.Sprintf(`expr %s : '\([0-9]*\.[0-9]*\.\)'`, ipv4Address)).SingleOut()
		ipv4PrefixExcept := fmt.Sprintf(`%s0.0/18`, getIpv4PrefixExcept)

		By(fmt.Sprintf("IPV6 Prefix: %s", ipv6Prefix))
		By(fmt.Sprintf("IPV4 Address Endpoint: %s", ipv4Address))
		By(fmt.Sprintf("IPV4 Prefix: %s", ipv4Prefix))
		By(fmt.Sprintf("IPV4 Prefix Except: %s", ipv4PrefixExcept))

		By("Setting PolicyEnforcement to always enforce (default-deny)")
		res := vm.SetPolicyEnforcement(helpers.PolicyEnforcementAlways)
		res.ExpectSuccess("Unable to set PolicyEnforcement to %s", helpers.PolicyEnforcementAlways)

		areEndpointsReady := vm.WaitEndpointsReady()
		Expect(areEndpointsReady).To(BeTrue())

		// Delete the pseudo-host IPs that we added to localhost after test
		// finishes. Don't care about success; this is best-effort.
		cleanup := func() {
			_ = vm.Exec(fmt.Sprintf("sudo ip addr del dev lo %s/32", ipv4Host))
			_ = vm.Exec(fmt.Sprintf("sudo ip addr del dev lo %s/128", ipv6Host))
		}

		defer cleanup()

		By("Adding Pseudo-Host IPs to localhost")
		res = vm.Exec(fmt.Sprintf("sudo ip addr add dev lo %s/32", ipv4Host))
		res.ExpectSuccess("Unable to add %s to pseudo-host IP to localhost", ipv4Host)
		res = vm.Exec(fmt.Sprintf("sudo ip addr add dev lo %s/128", ipv6Host))
		res.ExpectSuccess("Unable to add %s to pseudo-host IP to localhost", ipv6Host)

		By("Pinging host IPv4 from httpd2 (should NOT work due to default-deny PolicyEnforcement mode)")

		res = vm.ContainerExec(helpers.Httpd2, helpers.Ping(ipv4Host))
		res.ExpectFail("Unexpected success pinging host (%s) from %s: %s", ipv4Host, helpers.Httpd2, res.CombineOutput().String())

		By(fmt.Sprintf("Importing L3 CIDR Policy for IPv4 Egress Allowing Egress to %s, %s from %s", ipv4OtherHost, ipv4OtherHost, httpd2Label))
		script := fmt.Sprintf(`
		[{
			"endpointSelector": {"matchLabels":{"%s":""}},
			"egress":
			[{
				"toCIDR": [
					"%s/24",
					"%s/20"
				]
			}]
		}]`, httpd2Label, ipv4OtherHost, ipv4OtherHost)
		_, err = vm.PolicyRenderAndImport(script)
		Expect(err).To(BeNil(), "Unable to import policy: %s", err)

		By(fmt.Sprintf("Pinging host IPv4 (%s) from %s (should work) because it is contained within CIDR %s", ipv4Host, helpers.Httpd2, ipv4OtherHost))
		res = vm.ContainerExec(helpers.Httpd2, helpers.Ping(ipv4Host))
		res.ExpectSuccess("Unexpected failure pinging host (%s) from %s: %s", ipv4Host, helpers.Httpd2, res.CombineOutput().String())

		vm.PolicyDelAll().ExpectSuccess("Unable to delete all policies")

		By("Pinging host IPv6 from httpd2 (should NOT work because we did not specify IPv6 CIDR of host as part of previously imported policy)")
		res = vm.ContainerExec(helpers.Httpd2, helpers.Ping6(ipv6Host))
		res.ExpectFail("Unexpected success pinging host (%s) from %s", ipv6Host, helpers.Httpd2)

		By("Importing L3 CIDR Policy for IPv6 Egress")
		script = fmt.Sprintf(`
		[{
			"endpointSelector": {"matchLabels":{"%s":""}},
			"egress": [{
				"toCIDR": [
					"%s"
				]
			}]
		}]`, httpd2Label, ipv6Host)
		_, err = vm.PolicyRenderAndImport(script)
		Expect(err).To(BeNil(), "Unable to import policy: %s", err)

		By(fmt.Sprintf("Pinging host IPv6 from httpd2 (should work because policy allows IPv6 CIDR %s)", ipv6Host))
		res = vm.ContainerExec(helpers.Httpd2, helpers.Ping6(ipv6Host))
		res.ExpectSuccess("Unexpected failure pinging host (%s) from %s: %s", ipv6Host, helpers.Httpd2, res.CombineOutput().String())

		vm.PolicyDelAll().ExpectSuccess("Unable to delete all policies")

		// This test case checks that ping works even without explicit CIDR policies
		// imported.
		By("Importing L3 Label-Based Policy Allowing traffic from httpd2 to httpd1")
		script = fmt.Sprintf(`
		[{
			"endpointSelector": {"matchLabels":{"%[1]s":""}},
			"ingress": [{
				"fromEndpoints": [
					{"matchLabels":{"%[2]s":""}}
				]
			}]
		},
		{
			"endpointSelector": {"matchLabels":{"%[2]s":""}},
			"egress": [{
				"toEndpoints": [
					{"matchLabels":{"%[1]s":""}}
				]
			}]
		}]`, httpd1Label, httpd2Label)
		_, err = vm.PolicyRenderAndImport(script)
		Expect(err).To(BeNil(), "Unable to import policy: %s", err)

		By("Pinging httpd1 IPV4 from httpd2 (should work because we allowed traffic to httpd1 labels from httpd2 labels)")
		res = vm.ContainerExec(helpers.Httpd2, helpers.Ping(httpd1DockerNetworking[helpers.IPv4]))
		res.ExpectSuccess("Unexpected failure pinging %s (%s) from %s: %s", helpers.Httpd1, httpd1DockerNetworking[helpers.IPv4], helpers.Httpd2, res.CombineOutput().String())

		By("Pinging httpd1 IPv6 from httpd2 (should work because we allowed traffic to httpd1 labels from httpd2 labels)")
		res = vm.ContainerExec(helpers.Httpd2, helpers.Ping6(httpd1DockerNetworking[helpers.IPv6]))
		res.ExpectSuccess("Unexpected failure pinging %s (%s) from %s: %s", helpers.Httpd1, httpd1DockerNetworking[helpers.IPv6], helpers.Httpd2, res.CombineOutput().String())

		By("Pinging httpd1 IPv4 from app3 (should NOT work because app3 hasn't been whitelisted to communicate with httpd1)")
		res = vm.ContainerExec(helpers.App3, helpers.Ping(helpers.Httpd1))
		res.ExpectFail("Unexpected success pinging %s IPv4 from %s: %s", helpers.Httpd1, helpers.App3, res.CombineOutput().String())

		By("Pinging httpd1 IPv6 from app3 (should NOT work because app3 hasn't been whitelisted to communicate with httpd1)")
		res = vm.ContainerExec(helpers.App3, helpers.Ping6(helpers.Httpd1))
		res.ExpectFail("Unexpected success pinging %s IPv6 from %s: %s", helpers.Httpd1, helpers.App3, res.CombineOutput().String())

		vm.PolicyDelAll().ExpectSuccess("Unable to delete all policies")

		// Checking combined policy allowing traffic from IPv4 and IPv6 CIDR ranges.
		By(fmt.Sprintf("Importing Policy Allowing Ingress From %s --> %s And From CIDRs %s, %s", helpers.Httpd2, helpers.Httpd1, ipv4Prefix, ipv6Prefix))
		script = fmt.Sprintf(`
		[{
			"endpointSelector": {"matchLabels":{"%[1]s":""}},
			"ingress": [{
				"fromEndpoints":  [
					{"matchLabels":{"%s":""}}
				]
			}, {
				"fromCIDR": [
					"%s",
					"%s"
				]
			}]
		},
		{
			"endpointSelector": {"matchLabels":{"%s":""}},
			"egress": [{
				"toEndpoints":  [
					{"matchLabels":{"%[1]s":""}}
				]
			}]
		}]`, httpd1Label, httpd2Label, ipv4Prefix, ipv6Prefix, app3Label)

		_, err = vm.PolicyRenderAndImport(script)
		Expect(err).To(BeNil(), "Unable to import policy: %s", err)

		By(fmt.Sprintf("Pinging httpd1 IPv4 from app3 (should work because we allow ingress from CIDR %s which app3 is included)", ipv4Prefix))
		res = vm.ContainerExec(helpers.App3, helpers.Ping(helpers.Httpd1))
		res.ExpectSuccess("Unexpected failure pinging %s IPv4 from %s: %s", helpers.Httpd1, helpers.App3, res.CombineOutput().String())

		By(fmt.Sprintf("Pinging httpd1 IPv6 from app3 (should work because we allow ingress from CIDR %s which app3 is included)", ipv6Prefix))
		res = vm.ContainerExec(helpers.App3, helpers.Ping6(helpers.Httpd1))
		res.ExpectSuccess("Unexpected failure pinging %s IPv6 from %s: %s", helpers.Httpd1, helpers.App3, res.CombineOutput().String())

		vm.PolicyDelAll().ExpectSuccess("Unable to delete all policies")

		// Make sure that combined label-based and CIDR-based policy works.
		By(fmt.Sprintf("Importing Policy Allowing Ingress From %s --> %s And From CIDRs %s", helpers.Httpd2, helpers.Httpd1, ipv4OtherNet))
		script = fmt.Sprintf(`
		[{
			"endpointSelector": {"matchLabels":{"%[1]s":""}},
			"ingress": [{
				"fromEndpoints": [
					{"matchLabels":{"%s":""}}
				]
			}, {
				"fromCIDR": [
					"%s"
				]
			}]
		},
		{
			"endpointSelector": {"matchLabels":{"%s":""}},
			"egress": [{
				"toEndpoints": [
					{"matchLabels":{"%[1]s":""}}
				]
			}]
		}]`, httpd1Label, httpd2Label, ipv4OtherNet, app3Label)
		_, err = vm.PolicyRenderAndImport(script)
		Expect(err).To(BeNil(), "Unable to import policy: %s", err)

		By(fmt.Sprintf("Pinging httpd1 IPv4 from app3 (should NOT work because we only allow traffic from %s to %s)", httpd2Label, httpd1Label))
		res = vm.ContainerExec(helpers.App3, helpers.Ping(helpers.Httpd1))
		res.ExpectFail("Unexpected success pinging %s IPv4 from %s: %s", helpers.Httpd1, helpers.App3, res.CombineOutput().String())

		By(fmt.Sprintf("Pinging httpd1 IPv6 from app3 (should NOT work because we only allow traffic from %s to %s)", httpd2Label, httpd1Label))
		res = vm.ContainerExec(helpers.App3, helpers.Ping6(helpers.Httpd1))
		res.ExpectFail("Unexpected success pinging %s IPv6 from %s: %s", helpers.Httpd1, helpers.App3, res.CombineOutput().String())

		vm.PolicyDelAll().ExpectSuccess("Unable to delete all policies")

		By("Testing CIDR Exceptions in Cilium Policy")
		By(fmt.Sprintf("Importing Policy Allowing Ingress From %s --> %s And From CIDRs %s Except %s", helpers.Httpd2, helpers.Httpd1, ipv4Prefix, ipv4PrefixExcept))
		script = fmt.Sprintf(`
		[{
			"endpointSelector": {"matchLabels":{"%s":""}},
			"ingress": [{
				"fromEndpoints": [
					{"matchLabels":{"%s":""}}
				]
			}, {
				"fromCIDRSet": [ {
					"cidr": "%s",
					"except": [
						"%s"
					]
				}
				]
			}]
		}]`, httpd1Label, httpd2Label, ipv4Prefix, ipv4PrefixExcept)
		_, err = vm.PolicyRenderAndImport(script)
		Expect(err).To(BeNil(), "Unable to import policy: %s", err)

	})

	It("Extended HTTP Methods tests", func() {
		// This also tests L3-dependent L7.
		httpMethods := []string{"GET", "POST"}
		TestMethodPolicy := func(method string) {
			vm.PolicyDelAll().ExpectSuccess("Cannot delete all policies")
			policy := `
			[{
				"endpointSelector": {"matchLabels": {"id.httpd1": ""}},
				"ingress": [{
					"fromEndpoints": [{"matchLabels": {"id.app1": ""}}],
					"toPorts": [{
						"ports": [{"port": "80", "protocol": "tcp"}],
						"rules": {
							"HTTP": [{
							  "method": "%[1]s",
							  "path": "/public"
							}]
						}
					}]
				}]
			},{
				"endpointSelector": {"matchLabels": {"id.httpd1": ""}},
				"ingress": [{
					"fromEndpoints": [{"matchLabels": {"id.app2": ""}}],
					"toPorts": [{
						"ports": [{"port": "80", "protocol": "tcp"}],
						"rules": {
							"HTTP": [{
								"method": "%[1]s",
								"path": "/public",
								"headers": ["X-Test: True"]
							}]
						}
					}]
				}]
			}]`

			_, err := vm.PolicyRenderAndImport(fmt.Sprintf(policy, method))
			Expect(err).To(BeNil(), "Cannot import policy for %q", method)

			srvIP, err := vm.ContainerInspectNet(helpers.Httpd1)
			Expect(err).Should(BeNil(), "could not get container %q meta", helpers.Httpd1)

			dest := helpers.CurlFail("http://%s/public -X %s", srvIP[helpers.IPv4], method)
			destHeader := helpers.CurlFail("http://%s/public -H 'X-Test: True' -X %s",
				srvIP[helpers.IPv4], method)

			vm.ContainerExec(helpers.App1, dest).ExpectSuccess(
				"%q cannot http request to Public", helpers.App1)

			vm.ContainerExec(helpers.App2, dest).ExpectFail(
				"%q can http request to Public", helpers.App2)

			vm.ContainerExec(helpers.App2, destHeader).ExpectSuccess(
				"%q cannot http request to Public", helpers.App2)

			vm.ContainerExec(helpers.App1, destHeader).ExpectSuccess(
				"%q can http request to Public", helpers.App1)

			vm.ContainerExec(helpers.App3, destHeader).ExpectFail(
				"%q can http request to Public", helpers.App3)

			vm.ContainerExec(helpers.App3, dest).ExpectFail(
				"%q can http request to Public", helpers.App3)
		}

		for _, method := range httpMethods {
			By(fmt.Sprintf("Testing method %s", method))
			TestMethodPolicy(method)
		}
	})

	It("Tests Egress To World", func() {

		// Set policy enforcement to default deny so that we can do negative tests
		// before importing policy
		res := vm.SetPolicyEnforcement(helpers.PolicyEnforcementAlways)
		res.ExpectSuccess()

		areEndpointsReady := vm.WaitEndpointsReady()
		Expect(areEndpointsReady).Should(BeTrue(), "Endpoints are not ready after timeout")

		googleDNS := "8.8.8.8"
		failedPing := vm.ContainerExec(helpers.App1, helpers.Ping(googleDNS))
		failedPing.ExpectFail("unexpectedly able to ping %s", googleDNS)

		app1Label := "id.app1"
		policy := fmt.Sprintf(`
		[{
			"endpointSelector": {"matchLabels":{"%s":""}},
			"egress": [{
				"toEntities": [
					"%s"
				]
			}]
		}]`, app1Label, api.EntityWorld)

		_, err := vm.PolicyRenderAndImport(policy)
		Expect(err).To(BeNil(), "Unable to import policy: %s", err)

		areEndpointsReady = vm.WaitEndpointsReady()
		Expect(areEndpointsReady).Should(BeTrue(), "Endpoints are not ready after timeout")

		successPing := vm.ContainerExec(helpers.App1, helpers.Ping(googleDNS))
		successPing.ExpectSuccess("not able to ping %s", googleDNS)

		res = vm.ContainerExec(helpers.App1, helpers.Ping(helpers.App2))
		res.ExpectFail("unexpectedly able to ping %s", helpers.App2)

	})
})

var _ = Describe("RuntimeValidatedPolicyImportTests", func() {
	var once sync.Once
	var logger *logrus.Entry
	var vm *helpers.SSHMeta

	initialize := func() {
		logger = log.WithFields(logrus.Fields{"test": "RuntimeValidatedPoliciesImportTests"})
		logger.Info("Starting")
		vm = helpers.CreateNewRuntimeHelper(helpers.Runtime, logger)
		areEndpointsReady := vm.WaitEndpointsReady()
		Expect(areEndpointsReady).Should(BeTrue())
	}

	BeforeEach(func() {
		once.Do(initialize)
		vm.PolicyDelAll()

		vm.SampleContainersActions(helpers.Create, helpers.CiliumDockerNetwork)
		areEndpointsReady := vm.WaitEndpointsReady()
		Expect(areEndpointsReady).Should(BeTrue(), "Timed out waiting for endpoints to be ready")

	})

	AfterEach(func() {
		vm.ValidateNoErrorsOnLogs(CurrentGinkgoTestDescription().Duration)
		if CurrentGinkgoTestDescription().Failed {
			vm.ReportFailed()
		}

		vm.SampleContainersActions(helpers.Delete, helpers.CiliumDockerNetwork)
		allEndpointsDeleted := vm.WaitEndpointsDeleted()
		Expect(allEndpointsDeleted).Should(BeTrue(), "Not all endpoints were able to be deleted")
	})

	It("Invalid Policies", func() {

		testInvalidPolicy := func(data string) {
			err := helpers.RenderTemplateToFile(invalidJSON, data, 0777)
			Expect(err).Should(BeNil())

			path := helpers.GetFilePath(invalidJSON)
			_, err = vm.PolicyImportAndWait(path, helpers.HelperTimeout)
			Expect(err).Should(HaveOccurred())
			defer os.Remove(invalidJSON)
		}
		By("Invalid Json")

		invalidJSON := fmt.Sprintf(`
		[{
			"endpointSelector": {
				"matchLabels":{"id.httpd1":""}
			},`)
		testInvalidPolicy(invalidJSON)

		By("Test maximum tcp ports")
		var ports string
		for i := 0; i < 50; i++ {
			ports += fmt.Sprintf(`{"port": "%d", "protocol": "tcp"}`, i)
		}
		tooManyTCPPorts := fmt.Sprintf(`[{
		"endpointSelector": {
			"matchLabels": {
				"foo": ""
			}
		},
		"ingress": [{
			"fromEndpoints": [{
					"matchLabels": {
						"reserved:host": ""
					}
				},
				{
					"matchLabels": {
						"bar": ""
					}
				}
			],
			"toPorts": [{
				"ports": [%s]
			}]
		}]
		}]`, ports)
		testInvalidPolicy(tooManyTCPPorts)
	})

	It("Policy cmd", func() {
		By("Policy Labels")

		policy := `[{
			"endpointSelector": {"matchLabels":{"role":"frontend"}},
			"labels": ["key1"]
		},{
			"endpointSelector": {"matchLabels":{"role":"frontend"}},
			"labels": ["key2"]
		},{
			"endpointSelector": {"matchLabels":{"role":"frontend"}},
			"labels": ["key3"]
		}]`

		err := helpers.RenderTemplateToFile(policyJSON, policy, 0777)
		Expect(err).Should(BeNil())

		path := helpers.GetFilePath(policyJSON)
		_, err = vm.PolicyImportAndWait(path, helpers.HelperTimeout)
		Expect(err).Should(BeNil())
		defer os.Remove(policyJSON)
		for _, v := range []string{"key1", "key2", "key3"} {
			res := vm.PolicyGet(v)
			res.ExpectSuccess(fmt.Sprintf("cannot get key %q", v))
		}

		res := vm.PolicyDel("key2")
		res.ExpectSuccess()

		res = vm.PolicyGet("key2")
		res.ExpectFail()

		//Key1 and key3 should still exist. Test to delete it
		for _, v := range []string{"key1", "key3"} {
			res := vm.PolicyGet(v)
			res.ExpectSuccess(fmt.Sprintf("Key %s can't get get", v))

			res = vm.PolicyDel(v)
			res.ExpectSuccess()
		}

		res = vm.PolicyGetAll()
		res.ExpectSuccess()

		res = vm.PolicyDelAll()
		res.ExpectSuccess()
	})

	It("Check Endpoint PolicyMap Generation", func() {
		endpointIDMap, err := vm.GetEndpointsIds()
		Expect(err).Should(BeNil(), "Unable to get endpoint IDs")

		for _, endpointID := range endpointIDMap {
			By(fmt.Sprintf("Checking that endpoint policy map exists for endpoint %s", endpointID))
			epPolicyMap := fmt.Sprintf("/sys/fs/bpf/tc/globals/cilium_policy_%s", endpointID)
			vm.Exec(fmt.Sprintf("test -f %s", epPolicyMap)).ExpectSuccess(fmt.Sprintf("Endpoint policy map %s does not exist", epPolicyMap))
		}

		vm.SampleContainersActions(helpers.Delete, helpers.CiliumDockerNetwork)

		areEndpointsDeleted := vm.WaitEndpointsDeleted()
		Expect(areEndpointsDeleted).To(BeTrue())

		By("Getting ID of cilium-health endpoint")
		res := vm.Exec(`cilium endpoint list -o jsonpath="{[?(@.labels.orchestration-identity[0]=='reserved:health')].id}"`)
		Expect(res).Should(Not(BeNil()), "Unable to get cilium-health ID")

		healthID := strings.TrimSpace(res.GetStdOut())

		expected := "/sys/fs/bpf/tc/globals/cilium_policy"

		policyMapsInVM := vm.Exec(fmt.Sprintf("find /sys/fs/bpf/tc/globals/cilium_policy* | grep -v reserved | grep -v %s", healthID))

		By("Checking that all policy maps for endpoints have been deleted")
		Expect(strings.TrimSpace(policyMapsInVM.GetStdOut())).To(Equal(expected), "Only %s PolicyMap should be present", expected)

	})

	It("checks policy trace output", func() {

		httpd2Label := "id.httpd2"
		httpd1Label := "id.httpd1"
		allowedVerdict := "Final verdict: ALLOWED"

		By("Checking policy trace by labels")

		By(fmt.Sprintf("Importing policy that allows ingress to %s from the host and %s", httpd1Label, httpd2Label))

		allowHttpd1IngressHostHttpd2 := fmt.Sprintf(`
			[{
    			"endpointSelector": {"matchLabels":{"id.httpd1":""}},
    			"ingress": [{
        			"fromEndpoints": [
            			{"matchLabels":{"reserved:host":""}},
            			{"matchLabels":{"id.httpd2":""}}
					]
    			}]
			}]`)

		_, err := vm.PolicyRenderAndImport(allowHttpd1IngressHostHttpd2)
		Expect(err).Should(BeNil(), "Error importing policy: %s", err)

		By(fmt.Sprintf("Verifying that trace says that %s can reach %s", httpd2Label, httpd1Label))

		res := vm.Exec(fmt.Sprintf(`cilium policy trace -s %s -d %s`, httpd2Label, httpd1Label))
		Expect(res.Output().String()).Should(ContainSubstring(allowedVerdict), "Policy trace did not contain %s", allowedVerdict)

		endpointIDS, err := vm.GetEndpointsIds()
		Expect(err).To(BeNil(), "Unable to get IDs of endpoints")

		httpd2EndpointID, exists := endpointIDS[helpers.Httpd2]
		Expect(exists).To(BeTrue(), "Expected endpoint ID to exist for %s", helpers.Httpd2)

		httpd1EndpointID, exists := endpointIDS[helpers.Httpd1]
		Expect(exists).To(BeTrue(), "Expected endpoint ID to exist for %s", helpers.Httpd1)

		By("Getting models of endpoints to access policy-related metadata")
		httpd2EndpointModel := vm.EndpointGet(httpd2EndpointID)
		Expect(httpd2EndpointModel).To(Not(BeNil()), "Expected non-nil model for endpoint %s", helpers.Httpd2)
		Expect(httpd2EndpointModel.Identity).To(Not(BeNil()), "Expected non-nil identity for endpoint %s", helpers.Httpd2)

		httpd1EndpointModel := vm.EndpointGet(httpd1EndpointID)
		Expect(httpd1EndpointModel).To(Not(BeNil()), "Expected non-nil model for endpoint %s", helpers.Httpd1)
		Expect(httpd1EndpointModel.Identity).To(Not(BeNil()), "Expected non-nil identity for endpoint %s", helpers.Httpd1)
		Expect(httpd1EndpointModel.Policy).To(Not(BeNil()), "Expected non-nil policy for endpoint %s", helpers.Httpd1)

		httpd1SecurityIdentity := httpd1EndpointModel.Identity.ID
		httpd2SecurityIdentity := httpd2EndpointModel.Identity.ID

		// TODO - remove hardcoding of host identity.
		By(fmt.Sprintf("Verifying allowed identities for ingress traffic to %s", helpers.Httpd1))
		expectedIngressIdentitiesHttpd1 := []int64{1, httpd2SecurityIdentity}

		actualIngressIdentitiesHttpd1 := httpd1EndpointModel.Policy.AllowedIngressIdentities

		// Sort to ensure that equality check of slice doesn't fail due to ordering being different.
		sort.Slice(actualIngressIdentitiesHttpd1, func(i, j int) bool { return actualIngressIdentitiesHttpd1[i] < actualIngressIdentitiesHttpd1[j] })

		Expect(expectedIngressIdentitiesHttpd1).Should(Equal(actualIngressIdentitiesHttpd1), "Expected allowed identities %v, but instead got %v", expectedIngressIdentitiesHttpd1, actualIngressIdentitiesHttpd1)

		By("Deleting all policies and adding a new policy to ensure that endpoint policy is updated accordingly")
		res = vm.PolicyDelAll()
		res.ExpectSuccess("Unable to delete all policies")

		allowHttpd1IngressHttpd2 := fmt.Sprintf(`
			[{
    			"endpointSelector": {"matchLabels":{"id.httpd1":""}},
    			"ingress": [{
        			"fromEndpoints": [
            			{"matchLabels":{"id.httpd2":""}}
					]
    			}]
			}]`)

		_, err = vm.PolicyRenderAndImport(allowHttpd1IngressHttpd2)
		Expect(err).Should(BeNil(), "Error importing policy: %s", err)

		By("Verifying verbose trace for expected output using security identities")
		res = vm.Exec(fmt.Sprintf(`cilium policy trace --src-identity %d --dst-identity %d`, httpd2SecurityIdentity, httpd1SecurityIdentity))
		Expect(res.Output().String()).Should(ContainSubstring(allowedVerdict), "Policy trace did not contain %s", allowedVerdict)

		By("Verifying verbose trace for expected output using endpoint IDs")
		res = vm.Exec(fmt.Sprintf(`cilium policy trace --src-endpoint %s --dst-endpoint %s`, httpd2EndpointID, httpd1EndpointID))
		Expect(res.Output().String()).Should(ContainSubstring(allowedVerdict), "Policy trace did not contain %s", allowedVerdict)

		// Have to get models of endpoints again because policy has been updated.

		By("Getting models of endpoints to access policy-related metadata")
		httpd2EndpointModel = vm.EndpointGet(httpd2EndpointID)
		Expect(httpd2EndpointModel).To(Not(BeNil()), "Expected non-nil model for endpoint %s", helpers.Httpd2)
		Expect(httpd2EndpointModel.Identity).To(Not(BeNil()), "Expected non-nil identity for endpoint %s", helpers.Httpd2)

		httpd1EndpointModel = vm.EndpointGet(httpd1EndpointID)
		Expect(httpd1EndpointModel).To(Not(BeNil()), "Expected non-nil model for endpoint %s", helpers.Httpd1)
		Expect(httpd1EndpointModel.Identity).To(Not(BeNil()), "Expected non-nil identity for endpoint %s", helpers.Httpd1)
		Expect(httpd1EndpointModel.Policy).To(Not(BeNil()), "Expected non-nil policy for endpoint %s", helpers.Httpd1)

		httpd1SecurityIdentity = httpd1EndpointModel.Identity.ID
		httpd2SecurityIdentity = httpd2EndpointModel.Identity.ID

		By(fmt.Sprintf("Verifying allowed identities for ingress traffic to %s", helpers.Httpd1))
		expectedIngressIdentitiesHttpd1 = []int64{httpd2SecurityIdentity}
		actualIngressIdentitiesHttpd1 = httpd1EndpointModel.Policy.AllowedIngressIdentities
		Expect(expectedIngressIdentitiesHttpd1).Should(Equal(actualIngressIdentitiesHttpd1), "Expected allowed identities %v, but instead got %v", expectedIngressIdentitiesHttpd1, actualIngressIdentitiesHttpd1)

		res = vm.PolicyDelAll()
		res.ExpectSuccess("Unable to delete all policies")

		res = vm.SetPolicyEnforcement(helpers.PolicyEnforcementDefault)
		res.ExpectSuccess("Unable to change PolicyEnforcement configuration")

		areEndpointsReady := vm.WaitEndpointsReady()
		Expect(areEndpointsReady).Should(BeTrue())

		By("Checking that policy trace returns allowed verdict without any policies imported")
		res = vm.Exec(fmt.Sprintf(`cilium policy trace --src-endpoint %s --dst-endpoint %s`, httpd2EndpointID, httpd1EndpointID))
		Expect(res.Output().String()).Should(ContainSubstring(allowedVerdict), "Policy trace did not contain %s", allowedVerdict)
	})
})
