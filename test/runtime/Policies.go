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
	"fmt"
	"os"

	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
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

var _ = Describe("RuntimePolicyEnforcement", func() {

	var initialized bool
	var logger *logrus.Entry
	var docker *helpers.Docker
	var cilium *helpers.Cilium

	initialize := func() {
		if initialized == true {
			return
		}
		logger = log.WithFields(log.Fields{"testName": "RuntimePolicyEnforcement"})
		logger.Info("Starting")
		docker, cilium = helpers.CreateNewRuntimeHelper(helpers.Runtime, logger)
		cilium.WaitUntilReady(100)
		docker.NetworkCreate(helpers.CiliumDockerNetwork, "")

		res := cilium.SetPolicyEnforcement(helpers.PolicyEnforcementDefault, false)
		res.ExpectSuccess()

		initialized = true
	}

	BeforeEach(func() {
		initialize()
		cilium.PolicyDelAll()
		docker.ContainerCreate("app", "cilium/demo-httpd", helpers.CiliumDockerNetwork, "-l id.app")
		cilium.WaitEndpointsReady()
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			cilium.ReportFailed()
		}

		docker.ContainerRm("app")
	})

	Context("Policy Enforcement Default", func() {

		BeforeEach(func() {
			initialize()
			res := cilium.SetPolicyEnforcement(helpers.PolicyEnforcementDefault)
			res.ExpectSuccess()
		})

		It("Default values", func() {

			By("Policy Enforcement should be disabled for containers", func() {
				endPoints, err := cilium.PolicyEndpointsSummary()
				Expect(err).Should(BeNil())
				Expect(endPoints[helpers.Disabled]).To(Equal(1))
			})

			By("Apply a new sample policy")
			_, err := cilium.PolicyImport(cilium.GetFullPath(sampleJSON), helpers.HelperTimeout)
			Expect(err).Should(BeNil())

			endPoints, err := cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(1))
		})

		It("Handles missing required fields", func() {
			By("Apply a policy with no endpointSelector without crashing")
			_, err := cilium.PolicyImport(cilium.GetFullPath("no_endpointselector_policy.json"), helpers.HelperTimeout)
			Expect(err).ShouldNot(BeNil())
		})

		It("Default to Always without policy", func() {
			By("Check no policy enforcement")
			endPoints, err := cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Disabled]).To(Equal(1))

			By("Setting to Always")

			res := cilium.SetPolicyEnforcement(helpers.PolicyEnforcementAlways, true)
			res.ExpectSuccess()

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(1))

			By("Setting to default from Always")
			res = cilium.SetPolicyEnforcement(helpers.PolicyEnforcementDefault, true)
			res.ExpectSuccess()

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Disabled]).To(Equal(1))
		})

		It("Default to Always with policy", func() {
			_, err := cilium.PolicyImport(cilium.GetFullPath(sampleJSON), helpers.HelperTimeout)
			Expect(err).Should(BeNil())

			endPoints, err := cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(1))
			//DEfault =APP with PolicyEnforcement

			res := cilium.SetPolicyEnforcement(helpers.PolicyEnforcementAlways, true)
			res.ExpectSuccess()

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(1))

			res = cilium.SetPolicyEnforcement(helpers.PolicyEnforcementDefault, true)
			res.ExpectSuccess()

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(1))
		})

		It("Default to Never without policy", func() {
			endPoints, err := cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Disabled]).To(Equal(1))

			res := cilium.SetPolicyEnforcement(helpers.PolicyEnforcementNever, true)
			res.ExpectSuccess()

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Disabled]).To(Equal(1))

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Disabled]).To(Equal(1))
		})

		It("Default to Never with policy", func() {

			_, err := cilium.PolicyImport(cilium.GetFullPath(sampleJSON), helpers.HelperTimeout)
			Expect(err).Should(BeNil())

			endPoints, err := cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(1))

			res := cilium.SetPolicyEnforcement(helpers.PolicyEnforcementNever, true)
			res.ExpectSuccess()

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(0))

			res = cilium.SetPolicyEnforcement(helpers.PolicyEnforcementDefault, true)
			res.ExpectSuccess()

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(1))
		})
	})

	Context("Policy Enforcement Always", func() {
		//The test Always to Default is already tested in from default-always
		BeforeEach(func() {
			initialize()

			res := cilium.SetPolicyEnforcement(helpers.PolicyEnforcementAlways, true)
			res.ExpectSuccess()
		})

		It("Container creation", func() {
			//Check default containers are in place.
			endPoints, err := cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(1))
			Expect(endPoints[helpers.Disabled]).To(Equal(0))

			By("Create a new container")
			docker.ContainerCreate("new", "cilium/demo-httpd", helpers.CiliumDockerNetwork, "-l id.new")
			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(2))
			Expect(endPoints[helpers.Disabled]).To(Equal(0))
			docker.ContainerRm("new")
		}, 300)

		It("Always to Never with policy", func() {
			endPoints, err := cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(1))
			Expect(endPoints[helpers.Disabled]).To(Equal(0))

			_, err = cilium.PolicyImport(cilium.GetFullPath(sampleJSON), helpers.HelperTimeout)
			Expect(err).Should(BeNil())

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(1))
			Expect(endPoints[helpers.Disabled]).To(Equal(0))

			res := cilium.SetPolicyEnforcement(helpers.PolicyEnforcementNever, true)
			res.ExpectSuccess()

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(0))

			res = cilium.SetPolicyEnforcement(helpers.PolicyEnforcementAlways, true)
			res.ExpectSuccess()

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(1))
		})

		It("Always to Never without policy", func() {
			endPoints, err := cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(1))
			Expect(endPoints[helpers.Disabled]).To(Equal(0))

			res := cilium.SetPolicyEnforcement(helpers.PolicyEnforcementNever, true)
			res.ExpectSuccess()

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(0))
			Expect(endPoints[helpers.Disabled]).To(Equal(1))

			res = cilium.SetPolicyEnforcement(helpers.PolicyEnforcementAlways, true)
			res.ExpectSuccess()

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(1))
		})

	})

	Context("Policy Enforcement Never", func() {
		//The test Always to Default is already tested in from default-always
		BeforeEach(func() {
			initialize()

			res := cilium.SetPolicyEnforcement(helpers.PolicyEnforcementNever)
			res.ExpectSuccess()
		})

		It("Container creation", func() {
			//Check default containers are in place.
			endPoints, err := cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(0))
			Expect(endPoints[helpers.Disabled]).To(Equal(1))

			docker.ContainerCreate("new", "cilium/demo-httpd", helpers.CiliumDockerNetwork, "-l id.new")
			cilium.WaitEndpointsReady()
			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(0))
			Expect(endPoints[helpers.Disabled]).To(Equal(2))
			docker.ContainerRm("new")
		}, 300)

		It("Never to default with policy", func() {
			endPoints, err := cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(0))
			Expect(endPoints[helpers.Disabled]).To(Equal(1))

			_, err = cilium.PolicyImport(cilium.GetFullPath(sampleJSON), helpers.HelperTimeout)
			Expect(err).Should(BeNil())

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(0))
			Expect(endPoints[helpers.Disabled]).To(Equal(1))

			res := cilium.SetPolicyEnforcement(helpers.PolicyEnforcementDefault, true)
			res.ExpectSuccess()

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(1))
			Expect(endPoints[helpers.Disabled]).To(Equal(0))

			res = cilium.SetPolicyEnforcement(helpers.PolicyEnforcementNever, true)
			res.ExpectSuccess()

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(0))
			Expect(endPoints[helpers.Disabled]).To(Equal(1))
		})

		It("Never to default without policy", func() {
			endPoints, err := cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(0))
			Expect(endPoints[helpers.Disabled]).To(Equal(1))

			res := cilium.SetPolicyEnforcement(helpers.PolicyEnforcementDefault, true)
			res.ExpectSuccess()

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(0))
			Expect(endPoints[helpers.Disabled]).To(Equal(1))

			res = cilium.SetPolicyEnforcement(helpers.PolicyEnforcementNever, true)
			res.ExpectSuccess()

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints[helpers.Enabled]).To(Equal(0))
			Expect(endPoints[helpers.Disabled]).To(Equal(1))
		})
	})
})

var _ = Describe("RuntimePolicies", func() {

	var initialized bool
	var logger *logrus.Entry
	var docker *helpers.Docker
	var cilium *helpers.Cilium

	initialize := func() {
		if initialized == true {
			return
		}
		logger = log.WithFields(log.Fields{"test": "RunPolicies"})
		logger.Info("Starting")
		docker, cilium = helpers.CreateNewRuntimeHelper(helpers.Runtime, logger)
		docker.NetworkCreate(helpers.CiliumDockerNetwork, "")

		cilium.WaitUntilReady(100)
		res := cilium.SetPolicyEnforcement(helpers.PolicyEnforcementDefault, false)
		res.ExpectSuccess()
		initialized = true

	}

	BeforeEach(func() {
		initialize()
		cilium.PolicyDelAll()
		docker.SampleContainersActions(helpers.Create, helpers.CiliumDockerNetwork)
		cilium.WaitEndpointsReady()
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			cilium.ReportFailed()
		}
		docker.SampleContainersActions(helpers.Delete, helpers.CiliumDockerNetwork)
	})

	pingRequests := []string{ping, ping6}
	httpRequestsPublic := []string{http, http6}
	httpRequestsPrivate := []string{httpPrivate, http6Private}
	httpRequests := append(httpRequestsPublic, httpRequestsPrivate...)
	allRequests := append(pingRequests, httpRequests...)
	connectivityTest := func(tests []string, client, server string, assertFn func() types.GomegaMatcher) {
		title := func(title string) string {
			return fmt.Sprintf(title, client, server)
		}
		_, err := docker.ContainerInspectNet(client)
		Expect(err).Should(BeNil(), fmt.Sprintf(
			"could not get container %q (client) meta", client))

		srvIP, err := docker.ContainerInspectNet(server)
		Expect(err).Should(BeNil(), fmt.Sprintf(
			"could not get container %q (server) meta", server))
		for _, test := range tests {
			switch test {
			case ping:
				By(title("Client %q pinging server %q IPv4"))
				res := docker.ContainerExec(client, helpers.Ping(srvIP[helpers.IPv4]))
				ExpectWithOffset(1, res.WasSuccessful()).Should(assertFn(), fmt.Sprintf(
					"Client %q can't ping to server %q", client, srvIP[helpers.IPv4]))
			case ping6:

				By(title("Client %q pinging server %q IPv6"))
				res := docker.ContainerExec(client, helpers.Ping6(srvIP[helpers.IPv6]))
				ExpectWithOffset(1, res.WasSuccessful()).Should(assertFn(), fmt.Sprintf(
					"Client %q can't ping to server %q", client, srvIP[helpers.IPv6]))
			case http:
				By(title("Client '%s' HttpReq to server '%s' Ipv4"))
				res := docker.ContainerExec(client, helpers.CurlFail(fmt.Sprintf(
					"http://%s:80/public", srvIP[helpers.IPv4])))
				ExpectWithOffset(1, res.WasSuccessful()).Should(assertFn(), fmt.Sprintf(
					"Client %q can't curl to server %q", client, srvIP[helpers.IPv4]))
			case http6:
				By(title("Client %q HttpReq to server %q IPv6"))
				res := docker.ContainerExec(client, helpers.CurlFail(fmt.Sprintf(
					"http://[%s]:80/public", srvIP[helpers.IPv6])))
				ExpectWithOffset(1, res.WasSuccessful()).Should(assertFn(), fmt.Sprintf(
					"Client %q can't curl to server %q", client, srvIP[helpers.IPv6]))
			case httpPrivate:
				By(title("Client %q HttpReq to server %q private Ipv4"))
				res := docker.ContainerExec(client, helpers.CurlFail(fmt.Sprintf(
					"http://%s:80/private", srvIP[helpers.IPv4])))
				ExpectWithOffset(1, res.WasSuccessful()).Should(assertFn(), fmt.Sprintf(
					"Client %q can't curl to server %q private", client, srvIP[helpers.IPv4]))
			case http6Private:
				By(title("Client %q HttpReq to server %q private Ipv6"))
				res := docker.ContainerExec(client, helpers.CurlFail(fmt.Sprintf(
					"http://[%s]:80/private", srvIP[helpers.IPv6])))
				ExpectWithOffset(1, res.WasSuccessful()).Should(assertFn(), fmt.Sprintf(
					"Client %q can't curl to server %q private", client, srvIP[helpers.IPv6]))
			}
		}
	}

	It("L3/L4 Checks", func() {
		_, err := cilium.PolicyImport(cilium.GetFullPath(policiesL3JSON), helpers.HelperTimeout)
		Expect(err).Should(BeNil())

		//APP1 can connect to all Httpd1
		connectivityTest(allRequests, helpers.App1, helpers.Httpd1, BeTrue)

		//APP2 can't connect to Httpd1
		connectivityTest([]string{http}, helpers.App2, helpers.Httpd1, BeFalse)

		// APP1 can reach using TCP HTTP2
		connectivityTest(httpRequestsPublic, helpers.App1, helpers.Httpd2, BeTrue)

		// APP2 can't reach using TCP to HTTP2
		connectivityTest(httpRequestsPublic, helpers.App2, helpers.Httpd2, BeFalse)

		// APP3 can reach using TCP HTTP3, but can't ping EGRESS
		connectivityTest(httpRequestsPublic, helpers.App3, helpers.Httpd3, BeTrue)

		By("Disabling all the policies. All should work")

		status := cilium.PolicyDelAll()
		status.ExpectSuccess()

		cilium.WaitEndpointsReady()

		connectivityTest(allRequests, helpers.App1, helpers.Httpd1, BeTrue)
		connectivityTest(allRequests, helpers.App2, helpers.Httpd1, BeTrue)

		By("Ingress CIDR")

		app1, err := docker.ContainerInspectNet(helpers.App1)
		Expect(err).Should(BeNil())

		script := fmt.Sprintf(`
		[{
			"endpointSelector": {
				"matchLabels":{"id.httpd1":""}
			},
			"ingress": [
				{"fromEndpoints": [
					{ "matchLabels": {"id.app1": ""}}
				]},
				{"fromCIDR":
					[ "%s/32", "%s" ]}
			]
		}]`, app1[helpers.IPv4], app1[helpers.IPv6])

		err = helpers.RenderTemplateToFile(ingressJSON, script, 0777)
		Expect(err).Should(BeNil())

		path := helpers.GetFilePath(ingressJSON)
		_, err = cilium.PolicyImport(path, helpers.HelperTimeout)
		Expect(err).Should(BeNil())
		defer os.Remove(ingressJSON)

		connectivityTest(httpRequestsPublic, helpers.App1, helpers.Httpd1, BeTrue)
		connectivityTest(httpRequestsPublic, helpers.App2, helpers.Httpd1, BeFalse)

		By("Egress CIDR")

		httpd1, err := docker.ContainerInspectNet(helpers.Httpd1)
		Expect(err).Should(BeNil())

		script = fmt.Sprintf(`
		[{
			"endpointSelector": {
				"matchLabels":{"id.httpd1":""}
			},
			"ingress": [{
				"fromEndpoints": [{"matchLabels":{"id.app1":""}}]
			}]
		},
		{
			 "endpointSelector":
				{"matchLabels":{"id.%s":""}},
			 "egress": [{
				"toCIDR": [ "%s/32", "%s" ]
			 }]
		}]`, helpers.App1, httpd1[helpers.IPv4], httpd1[helpers.IPv6])
		err = helpers.RenderTemplateToFile(egressJSON, script, 0777)
		Expect(err).Should(BeNil())
		path = helpers.GetFilePath(egressJSON)
		defer os.Remove(egressJSON)
		_, err = cilium.PolicyImport(path, helpers.HelperTimeout)
		Expect(err).Should(BeNil())

		connectivityTest(httpRequestsPublic, helpers.App1, helpers.Httpd1, BeTrue)
		connectivityTest(httpRequestsPublic, helpers.App2, helpers.Httpd1, BeFalse)
	})

	It("L4Policy Checks", func() {
		_, err := cilium.PolicyImport(cilium.GetFullPath("Policies-l4-policy.json"), helpers.HelperTimeout)
		Expect(err).Should(BeNil())

		for _, app := range []string{helpers.App1, helpers.App2} {
			connectivityTest(allRequests, app, helpers.Httpd1, BeFalse)
			connectivityTest(pingRequests, app, helpers.Httpd2, BeFalse)
			connectivityTest(httpRequestsPublic, app, helpers.Httpd2, BeTrue)
		}

		By("Disabling all the policies. All should work")

		status := cilium.PolicyDelAll()
		Expect(status.WasSuccessful()).Should(BeTrue())
		cilium.WaitEndpointsReady()

		for _, app := range []string{helpers.App1, helpers.App2} {
			connectivityTest(allRequests, app, helpers.Httpd1, BeTrue)
			connectivityTest(allRequests, app, helpers.Httpd2, BeTrue)
		}
	})

	It("L7 Checks", func() {

		_, err := cilium.PolicyImport(cilium.GetFullPath(policiesL7JSON), helpers.HelperTimeout)
		Expect(err).Should(BeNil())

		By("Simple Ingress")
		//APP1 can connect to public, but no to private
		connectivityTest(httpRequestsPublic, helpers.App1, helpers.Httpd1, BeTrue)
		connectivityTest(httpRequestsPrivate, helpers.App1, helpers.Httpd1, BeFalse)

		//App2 can't connect
		connectivityTest(httpRequestsPublic, helpers.App2, helpers.Httpd1, BeFalse)

		By("Simple Egress")

		//APP2 can connnect to public, but no to private
		connectivityTest(httpRequestsPublic, helpers.App2, helpers.Httpd2, BeTrue)
		connectivityTest(httpRequestsPrivate, helpers.App2, helpers.Httpd2, BeFalse)

		By("Disabling all the policies. All should work")

		status := cilium.PolicyDelAll()
		status.ExpectSuccess()
		cilium.WaitEndpointsReady()

		connectivityTest(allRequests, helpers.App1, helpers.Httpd1, BeTrue)
		connectivityTest(allRequests, helpers.App2, helpers.Httpd1, BeTrue)

		By("Multiple Ingress")

		cilium.PolicyDelAll()
		_, err = cilium.PolicyImport(cilium.GetFullPath(multL7PoliciesJSON), helpers.HelperTimeout)
		Expect(err).Should(BeNil())

		//APP1 can connnect to public, but no to private

		connectivityTest(httpRequestsPublic, helpers.App1, helpers.Httpd1, BeTrue)
		connectivityTest(httpRequestsPrivate, helpers.App1, helpers.Httpd1, BeFalse)

		//App2 can't connect
		connectivityTest(httpRequestsPublic, helpers.App2, helpers.Httpd1, BeFalse)

		By("Multiple Egress")
		// app2 can connect to /public, but not to /private
		connectivityTest(httpRequestsPublic, helpers.App2, helpers.Httpd2, BeTrue)
		connectivityTest(httpRequestsPrivate, helpers.App2, helpers.Httpd2, BeFalse)

		By("Disabling all the policies. All should work")

		status = cilium.PolicyDelAll()
		status.ExpectSuccess()
		cilium.WaitEndpointsReady()

		connectivityTest(allRequests, helpers.App1, helpers.Httpd1, BeTrue)
		connectivityTest(allRequests, helpers.App2, helpers.Httpd1, BeTrue)
	})

	It("Invalid Policies", func() {

		testInvalidPolicy := func(data string) {
			err := helpers.RenderTemplateToFile(invalidJSON, data, 0777)
			Expect(err).Should(BeNil())

			path := helpers.GetFilePath(invalidJSON)
			_, err = cilium.PolicyImport(path, helpers.HelperTimeout)
			Expect(err).Should(HaveOccurred())
			defer os.Remove(invalidJSON)
		}
		By("Invalid Json")

		script := fmt.Sprintf(`
		[{
			"endpointSelector": {
				"matchLabels":{"id.httpd1":""}
			},`)
		testInvalidPolicy(script)

		By("Test maximum tcp ports")
		var ports string
		for i := 0; i < 50; i++ {
			ports += fmt.Sprintf(`{"port": "%d", "protocol": "tcp"}`, i)
		}
		script = fmt.Sprintf(`[{
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
		testInvalidPolicy(script)
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
		_, err = cilium.PolicyImport(path, helpers.HelperTimeout)
		Expect(err).Should(BeNil())
		defer os.Remove(policyJSON)
		for _, v := range []string{"key1", "key2", "key3"} {
			res := cilium.PolicyGet(v)
			res.ExpectSuccess(fmt.Sprintf("cannot get key %q", v))
		}

		res := cilium.PolicyDel("key2")
		res.ExpectSuccess()

		res = cilium.PolicyGet("key2")
		res.ExpectFail()

		//Key1 and key3 should still exist. Test to delete it
		for _, v := range []string{"key1", "key3"} {
			res := cilium.PolicyGet(v)
			res.ExpectSuccess(fmt.Sprintf("Key %s can't get get", v))

			res = cilium.PolicyDel(v)
			res.ExpectSuccess()
		}

		res = cilium.PolicyGetAll()
		res.ExpectSuccess()

		res = cilium.PolicyDelAll()
		res.ExpectSuccess()

	})
})
