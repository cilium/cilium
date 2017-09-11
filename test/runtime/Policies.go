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
	log "github.com/sirupsen/logrus"
)

var _ = Describe("RuntimePolicyEnforcement", func() {

	var initialized bool
	var networkName string = "cilium-net"
	var logger *log.Entry
	var docker *helpers.Docker
	var cilium *helpers.Cilium

	initialize := func() {
		if initialized == true {
			return
		}
		logger = log.WithFields(log.Fields{"testName": "RuntimePolicyEnforcement"})
		logger.Info("Starting")
		docker, cilium = helpers.CreateNewRuntimeHelper("runtime", logger)
		cilium.WaitUntilReady(100)
		docker.NetworkCreate(networkName, "")

		res := cilium.PolicyEnforcementSet("default", false)
		Expect(res.WasSuccessful()).Should(BeTrue())

		initialized = true
	}

	BeforeEach(func() {
		initialize()
		docker.ContainerCreate("app", "cilium/demo-httpd", networkName, "-l id.app")
		cilium.Exec("policy delete --all")
		cilium.EndpointWaitUntilReady()
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
			res := cilium.PolicyEnforcementSet("default")
			Expect(res.WasSuccessful()).Should(BeTrue())
		})

		It("Default values", func() {

			By("Policy Enforcement should be disabled for containers", func() {
				endPoints, err := cilium.PolicyEndpointsSummary()
				Expect(err).Should(BeNil())
				Expect(endPoints["disabled"]).To(Equal(1))
			})

			By("Apply a new sample policy")
			_, err := cilium.PolicyImport(cilium.GetFullPath("sample_policy.json"), 300)
			Expect(err).Should(BeNil())

			endPoints, err := cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["enabled"]).To(Equal(1))
		})

		It("Default to Always without policy", func() {
			By("Check no policy enforcement")
			endPoints, err := cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["disabled"]).To(Equal(1))

			By("Setting to Always")

			res := cilium.PolicyEnforcementSet("always", true)
			Expect(res.WasSuccessful()).Should(BeTrue())

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["enabled"]).To(Equal(1))

			By("Setting to default from Always")
			res = cilium.PolicyEnforcementSet("default", true)
			Expect(res.WasSuccessful()).Should(BeTrue())

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["disabled"]).To(Equal(1))
		})

		It("Default to Always with policy", func() {
			_, err := cilium.PolicyImport(cilium.GetFullPath("sample_policy.json"), 300)
			Expect(err).Should(BeNil())

			endPoints, err := cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["enabled"]).To(Equal(1))
			//DEfault =APP with PolicyEnforcement

			res := cilium.PolicyEnforcementSet("always", true)
			Expect(res.WasSuccessful()).Should(BeTrue())

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["enabled"]).To(Equal(1))

			res = cilium.PolicyEnforcementSet("default", true)
			Expect(res.WasSuccessful()).Should(BeTrue())

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["enabled"]).To(Equal(1))
		})

		It("Default to Never without policy", func() {
			endPoints, err := cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["disabled"]).To(Equal(1))

			res := cilium.PolicyEnforcementSet("never", true)
			Expect(res.WasSuccessful()).Should(BeTrue())

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["disabled"]).To(Equal(1))

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["disabled"]).To(Equal(1))
		})

		It("Default to Never with policy", func() {

			_, err := cilium.PolicyImport(cilium.GetFullPath("sample_policy.json"), 300)
			Expect(err).Should(BeNil())

			endPoints, err := cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["enabled"]).To(Equal(1))

			res := cilium.PolicyEnforcementSet("never", true)
			Expect(res.WasSuccessful()).Should(BeTrue())

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["enabled"]).To(Equal(0))

			res = cilium.PolicyEnforcementSet("default", true)
			Expect(res.WasSuccessful()).Should(BeTrue())

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["enabled"]).To(Equal(1))
		})
	})

	Context("Policy Enforcement Always", func() {
		//The test Always to Default is already tested in from default-always
		BeforeEach(func() {
			initialize()
			res := cilium.PolicyEnforcementSet("always", true)
			Expect(res.WasSuccessful()).Should(BeTrue())
		})

		It("Container creation", func() {
			//Check default containers are in place.
			endPoints, err := cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["enabled"]).To(Equal(1))
			Expect(endPoints["disabled"]).To(Equal(0))

			By("Create a new container")
			docker.ContainerCreate("new", "cilium/demo-httpd", networkName, "-l id.new")
			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["enabled"]).To(Equal(2))
			Expect(endPoints["disabled"]).To(Equal(0))
			docker.ContainerRm("new")
		}, 300)

		It("Always to Never with policy", func() {
			endPoints, err := cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["enabled"]).To(Equal(1))
			Expect(endPoints["disabled"]).To(Equal(0))

			_, err = cilium.PolicyImport(cilium.GetFullPath("sample_policy.json"), 300)
			Expect(err).Should(BeNil())

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["enabled"]).To(Equal(1))
			Expect(endPoints["disabled"]).To(Equal(0))

			res := cilium.PolicyEnforcementSet("never", true)
			Expect(res.WasSuccessful()).Should(BeTrue())

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["enabled"]).To(Equal(0))

			res = cilium.PolicyEnforcementSet("always", true)
			Expect(res.WasSuccessful()).Should(BeTrue())

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["enabled"]).To(Equal(1))
		})

		It("Always to Never without policy", func() {
			endPoints, err := cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["enabled"]).To(Equal(1))
			Expect(endPoints["disabled"]).To(Equal(0))

			res := cilium.PolicyEnforcementSet("never", true)
			Expect(res.WasSuccessful()).Should(BeTrue())

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["enabled"]).To(Equal(0))
			Expect(endPoints["disabled"]).To(Equal(1))

			res = cilium.PolicyEnforcementSet("always", true)
			Expect(res.WasSuccessful()).Should(BeTrue())

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["enabled"]).To(Equal(1))
		})

	})

	Context("Policy Enforcement Never", func() {
		//The test Always to Default is already tested in from default-always
		BeforeEach(func() {
			initialize()
			res := cilium.PolicyEnforcementSet("never")
			Expect(res.WasSuccessful()).Should(BeTrue())
		})

		It("Container creation", func() {
			//Check default containers are in place.
			endPoints, err := cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["enabled"]).To(Equal(0))
			Expect(endPoints["disabled"]).To(Equal(1))

			docker.ContainerCreate("new", "cilium/demo-httpd", networkName, "-l id.new")
			cilium.EndpointWaitUntilReady()
			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["enabled"]).To(Equal(0))
			Expect(endPoints["disabled"]).To(Equal(2))
			docker.ContainerRm("new")
		}, 300)

		It("Never to default with policy", func() {
			endPoints, err := cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["enabled"]).To(Equal(0))
			Expect(endPoints["disabled"]).To(Equal(1))

			_, err = cilium.PolicyImport(cilium.GetFullPath("sample_policy.json"), 300)
			Expect(err).Should(BeNil())

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["enabled"]).To(Equal(0))
			Expect(endPoints["disabled"]).To(Equal(1))

			res := cilium.PolicyEnforcementSet("default", true)
			Expect(res.WasSuccessful()).Should(BeTrue())

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["enabled"]).To(Equal(1))
			Expect(endPoints["disabled"]).To(Equal(0))

			res = cilium.PolicyEnforcementSet("never", true)
			Expect(res.WasSuccessful()).Should(BeTrue())

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["enabled"]).To(Equal(0))
			Expect(endPoints["disabled"]).To(Equal(1))
		})

		It("Never to default without policy", func() {
			endPoints, err := cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["enabled"]).To(Equal(0))
			Expect(endPoints["disabled"]).To(Equal(1))

			res := cilium.PolicyEnforcementSet("default", true)
			Expect(res.WasSuccessful()).Should(BeTrue())

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["enabled"]).To(Equal(0))
			Expect(endPoints["disabled"]).To(Equal(1))

			res = cilium.PolicyEnforcementSet("never", true)
			Expect(res.WasSuccessful()).Should(BeTrue())

			endPoints, err = cilium.PolicyEndpointsSummary()
			Expect(err).Should(BeNil())
			Expect(endPoints["enabled"]).To(Equal(0))
			Expect(endPoints["disabled"]).To(Equal(1))
		})
	})
})

var _ = Describe("RunPolicies", func() {

	var initialized bool
	var networkName string = "cilium-net"
	var logger *log.Entry
	var docker *helpers.Docker
	var cilium *helpers.Cilium

	initialize := func() {
		if initialized == true {
			return
		}
		logger = log.WithFields(log.Fields{"test": "RunPolicies"})
		logger.Info("Starting")
		docker, cilium = helpers.CreateNewRuntimeHelper("runtime", logger)
		docker.NetworkCreate(networkName, "")

		cilium.WaitUntilReady(100)
		res := cilium.PolicyEnforcementSet("default", false)
		Expect(res.WasSuccessful()).Should(BeTrue())
		initialized = true

	}

	BeforeEach(func() {
		initialize()
		cilium.Exec("policy delete --all")
		docker.SampleContainersActions("create", networkName)
		cilium.EndpointWaitUntilReady()
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			cilium.ReportFailed()
		}
		docker.SampleContainersActions("delete", networkName)
	})

	connectivityTest := func(tests []string, client, server string, assertFn func() types.GomegaMatcher) {
		title := func(title string) string {
			return fmt.Sprintf(title, client, server)
		}
		_, err := docker.ContainerInspectNet(client)
		Expect(err).Should(BeNil(), fmt.Sprintf(
			"Couldn't get container '%s' client meta", client))

		srvIP, err := docker.ContainerInspectNet(server)
		Expect(err).Should(BeNil(), fmt.Sprintf(
			"Couldn't get container '%s' server meta", server))
		for _, test := range tests {
			switch test {
			case "ping":
				By(title("Client '%s' pinging server '%s' IPv4"))
				res := docker.ContainerExec(client, fmt.Sprintf("ping -c 4 %s", srvIP["IPv4"]))
				ExpectWithOffset(1, res.WasSuccessful()).Should(assertFn(), fmt.Sprintf(
					"Client '%s' can't ping to server '%s'", client, srvIP["IPv4"]))
			case "ping6":
				By(title("Client '%s' pinging server '%s' IPv6"))
				res := docker.ContainerExec(client, fmt.Sprintf("ping6 -c 4 %s", srvIP["IPv6"]))
				ExpectWithOffset(1, res.WasSuccessful()).Should(assertFn(), fmt.Sprintf(
					"Client '%s' can't ping to server '%s'", client, srvIP["IPv6"]))
			case "http":
				By(title("Client '%s' HttpReq to server '%s' Ipv4"))
				res := docker.ContainerExec(client, fmt.Sprintf(
					"curl -s --fail --connect-timeout 3 http://%s:80/public", srvIP["IPv4"]))
				ExpectWithOffset(1, res.WasSuccessful()).Should(assertFn(), fmt.Sprintf(
					"Client '%s' can't curl to server '%s'", client, srvIP["IPv4"]))
			case "http6":
				By(title("Client '%s' HttpReq to server '%s' IPv6"))
				res := docker.ContainerExec(client, fmt.Sprintf(
					"curl -s --fail --connect-timeout 3 http://[%s]:80/public", srvIP["IPv6"]))
				ExpectWithOffset(1, res.WasSuccessful()).Should(assertFn(), fmt.Sprintf(
					"Client '%s' can't curl to server '%s'", client, srvIP["IPv6"]))
			case "http_private":
				By(title("Client '%s' HttpReq to server '%s' private Ipv4"))
				res := docker.ContainerExec(client, fmt.Sprintf(
					"curl -s --fail --connect-timeout 3 http://%s:80/private", srvIP["IPv4"]))
				ExpectWithOffset(1, res.WasSuccessful()).Should(assertFn(), fmt.Sprintf(
					"Client '%s' can't curl to server '%s' private", client, srvIP["IPv4"]))
			case "http6_private":
				By(title("Client '%s' HttpReq to server '%s' private Ipv6"))
				res := docker.ContainerExec(client, fmt.Sprintf(
					"curl -s --fail --connect-timeout 3 http://%s:80/private", srvIP["IPv6"]))
				ExpectWithOffset(1, res.WasSuccessful()).Should(assertFn(), fmt.Sprintf(
					"Client '%s' can't curl to server '%s' private", client, srvIP["IPv6"]))
			}
		}
	}

	It("L3/L4 Checks", func() {
		_, err := cilium.PolicyImport(cilium.GetFullPath("Policies-l3-policy.json"), 300)
		Expect(err).Should(BeNil())

		//APP1 can connect to all Httpd1
		connectivityTest([]string{"ping", "ping6", "http", "http6"}, "app1", "httpd1", BeTrue)

		//APP2 can't connect to Httpd1
		connectivityTest([]string{"http"}, "app2", "httpd1", BeFalse)

		// APP1 can reach using TCP HTTP2
		connectivityTest([]string{"http", "http6"}, "app1", "httpd2", BeTrue)

		// APP2 can't reach using TCP to HTTP2
		connectivityTest([]string{"http", "http6"}, "app2", "httpd2", BeFalse)

		// APP3 can reach using TCP HTTP2, but can't ping EGRESS
		connectivityTest([]string{"http", "http6"}, "app3", "httpd3", BeTrue)

		By("Disabling all the policies. All should work")

		status := cilium.Exec("policy delete --all")
		Expect(status.WasSuccessful()).Should(BeTrue())
		cilium.EndpointWaitUntilReady()

		connectivityTest([]string{"ping", "ping6", "http", "http6"}, "app1", "httpd1", BeTrue)
		connectivityTest([]string{"ping", "ping6", "http", "http6"}, "app2", "httpd1", BeTrue)

		By("Ingress CIDR")

		app1, err := docker.ContainerInspectNet("app1")
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
		}]`, app1["IPv4"], app1["IPv6"])

		err = helpers.RenderTemplateToFile("ingress.json", script, 0777)
		Expect(err).Should(BeNil())

		path := helpers.GetFilePath("ingress.json")
		_, err = cilium.PolicyImport(path, 300)
		Expect(err).Should(BeNil())
		defer os.Remove("ingress.json")

		connectivityTest([]string{"http", "http6"}, "app1", "httpd1", BeTrue)
		connectivityTest([]string{"http", "http6"}, "app2", "httpd1", BeFalse)

		By("Egress CIDR")

		httpd1, err := docker.ContainerInspectNet("httpd1")
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
		}]`, "app1", httpd1["IPv4"], httpd1["IPv6"])
		err = helpers.RenderTemplateToFile("egress.json", script, 0777)
		Expect(err).Should(BeNil())
		path = helpers.GetFilePath("egress.json")
		defer os.Remove("egress.json")
		_, err = cilium.PolicyImport(path, 300)
		Expect(err).Should(BeNil())

		connectivityTest([]string{"http", "http6"}, "app1", "httpd1", BeTrue)
		connectivityTest([]string{"http", "http6"}, "app2", "httpd1", BeFalse)
	})

	It("L7 Checks", func() {

		_, err := cilium.PolicyImport(cilium.GetFullPath("Policies-l7-simple.json"), 300)
		Expect(err).Should(BeNil())

		By("Simple Ingress")
		//APP1 can connnect to public, but no to private
		connectivityTest([]string{"http", "http6"}, "app1", "httpd1", BeTrue)
		connectivityTest([]string{"http_private", "http6_private"}, "app1", "httpd1", BeFalse)

		//App2 can't connect
		connectivityTest([]string{"http", "http6"}, "app2", "httpd1", BeFalse)

		By("Simple Egress")

		//APP2 can connnect to public, but no to private
		connectivityTest([]string{"http", "http6"}, "app2", "httpd2", BeTrue)
		connectivityTest([]string{"http_private", "http6_private"}, "app2", "httpd2", BeFalse)

		By("Disabling all the policies. All should work")
		status := cilium.Exec("policy delete --all")
		Expect(status.WasSuccessful()).Should(BeTrue())
		cilium.EndpointWaitUntilReady()

		connectivityTest([]string{"ping", "ping6", "http", "http6"}, "app1", "httpd1", BeTrue)
		connectivityTest([]string{"ping", "ping6", "http", "http6"}, "app2", "httpd1", BeTrue)

		By("Multiple Ingress")

		cilium.Exec("policy delete --all")
		_, err = cilium.PolicyImport(cilium.GetFullPath("Policies-l7-multiple.json"), 300)
		Expect(err).Should(BeNil())

		//APP1 can connnect to public, but no to private
		connectivityTest([]string{"http", "http6"}, "app1", "httpd1", BeTrue)
		connectivityTest([]string{"http_private", "http6_private"}, "app1", "httpd1", BeFalse)

		//App2 can't connect
		connectivityTest([]string{"http", "http6"}, "app2", "httpd1", BeFalse)

		By("Multiple Egress")
		//APP2 can connnect to public, but no to private
		connectivityTest([]string{"http", "http6"}, "app2", "httpd2", BeTrue)
		connectivityTest([]string{"http_private", "http6_private"}, "app2", "httpd2", BeFalse)

		By("Disabling all the policies. All should work")

		status = cilium.Exec("policy delete --all")
		Expect(status.WasSuccessful()).Should(BeTrue())
		cilium.EndpointWaitUntilReady()

		connectivityTest([]string{"ping", "ping6", "http", "http6"}, "app1", "httpd1", BeTrue)
		connectivityTest([]string{"ping", "ping6", "http", "http6"}, "app2", "httpd1", BeTrue)
	})

	It("Invalid Policies", func() {

		testInvalidPolicy := func(data string) {
			err := helpers.RenderTemplateToFile("invalid.json", data, 0777)
			Expect(err).Should(BeNil())

			path := helpers.GetFilePath("invalid.json")
			_, err = cilium.PolicyImport(path, 300)
			Expect(err).Should(HaveOccurred())
			defer os.Remove("invalid.json")
		}
		By("Invalid Json")

		script := fmt.Sprintf(`
		[{
			"endpointSelector": {
				"matchLabels":{"id.httpd1":""}
			},`)
		testInvalidPolicy(script)

		By("Test maximun tcp ports")
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

		err := helpers.RenderTemplateToFile("policy.json", policy, 0777)
		Expect(err).Should(BeNil())

		path := helpers.GetFilePath("policy.json")
		_, err = cilium.PolicyImport(path, 300)
		Expect(err).Should(BeNil())
		defer os.Remove("policy.json")
		for _, v := range []string{"key1", "key2", "key3"} {
			res := cilium.PolicyGet(v)
			Expect(res.WasSuccessful()).Should(BeTrue(), fmt.Sprintf("Key %s can't get get", v))
		}

		res := cilium.PolicyDel("key2")
		Expect(res.WasSuccessful()).Should(BeTrue())

		res = cilium.PolicyGet("key2")
		Expect(res.WasSuccessful()).Should(BeFalse())

		//Key1 and key3 should still exist. Test to delete it
		for _, v := range []string{"key1", "key3"} {
			res := cilium.PolicyGet(v)
			Expect(res.WasSuccessful()).Should(BeTrue(), fmt.Sprintf(
				"Key %s can't get get", v))

			res = cilium.PolicyDel(v)
			Expect(res.WasSuccessful()).Should(BeTrue())
		}
		res = cilium.Exec("policy get")
		Expect(res.WasSuccessful()).Should(BeTrue())

		res = cilium.Exec("policy delete --all")
		Expect(res.WasSuccessful()).Should(BeTrue())

	})
})
