// Copyright 2018 Authors of Cilium
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
	"net"
	"strings"
	"sync"

	"github.com/cilium/cilium/test/helpers"

	"github.com/asaskevich/govalidator"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	"github.com/sirupsen/logrus"
)

const (
	serverImage = "httpd"
	ctCleanUpNC = "ct-clean-up-nc.py"

	// Change to "<=" if the pkg/endpointmanager/conntrack.go:GcInterval is 10
	// Change to "==" if it is set to a large number
	comparator = "<="
)

type connTest struct {
	src         map[string]string
	destination map[string]string
	dstPort     string
	kind        string
	mode        string
}

func (c connTest) String() string {
	return fmt.Sprintf("%s-%s-%s", c.src[helpers.Name], c.destination[helpers.Name], c.kind)
}

var _ = Describe("RuntimeValidatedConntrackTable", func() {

	var (
		logger *logrus.Entry
		vm     *helpers.SSHMeta
		once   sync.Once

		HTTPPrivate   = "private"
		HTTPPublic    = "public"
		HTTPDummy     = "dummy"
		netcatPrivate = "ncPrivate"
		netcatPublic  = "ncPublic"
		netcatDummy   = "ncDummy"
		netcat        = "netcat"
		server        = "server"
		server2       = "server-2"
		server3       = "server-3"
		client2       = "client-2"
		client        = "client"
		netcatPort    = 11111
	)

	containersNames := []string{server, server2, server3, client, client2, netcat}

	containers := func(mode string) {
		images := map[string]string{
			server:  serverImage,
			server2: serverImage,
			server3: helpers.HttpdImage,
		}

		switch mode {
		case helpers.Create:
			for k, v := range images {
				res := vm.ContainerCreate(k, v, helpers.CiliumDockerNetwork, fmt.Sprintf("-l id.%s", k))
				res.ExpectSuccess(fmt.Sprintf("Creating container %q. Error: %s", k, res.CombineOutput().String()))
			}
			cmdStr := "docker run -dt --name netcat --net %s -l id.server-4 busybox:1.28.0 sleep 30000s"
			vm.Exec(fmt.Sprintf(cmdStr, helpers.CiliumDockerNetwork)).ExpectSuccess()

			cmdStr = "docker run -dt -v %s:/nc.py --net=%s --name client -l id.client python:2.7.14"
			res := vm.Exec(fmt.Sprintf(cmdStr, vm.GetFullPath(ctCleanUpNC), helpers.CiliumDockerNetwork))
			res.ExpectSuccess(fmt.Sprintf("Creating container %q. Error: %s", client, res.CombineOutput().String()))

			res = vm.ContainerCreate(client2, helpers.NetperfImage, helpers.CiliumDockerNetwork, "-l id.client")
			res.ExpectSuccess(fmt.Sprintf("Creating container %q. Error: %s", client2, res.CombineOutput().String()))

		case helpers.Delete:
			for _, x := range containersNames {
				vm.ContainerRm(x).ExpectSuccess()
			}
		}
	}

	initialize := func() {
		logger = log.WithFields(logrus.Fields{"testName": "RuntimeConntrack"})
		logger.Info("Starting")
		vm = helpers.CreateNewRuntimeHelper(helpers.Runtime, logger)
		err := vm.WaitUntilReady(100)
		Expect(err).To(BeNil())
		vm.NetworkCreate(helpers.CiliumDockerNetwork, "")
	}

	BeforeEach(func() {
		once.Do(initialize)

		res := vm.SetPolicyEnforcement(helpers.PolicyEnforcementAlways)
		res.ExpectSuccess("Setting policy enforcement as always")

		res = vm.PolicyDelAll()
		res.ExpectSuccess("Deleting all policies")

		containers(helpers.Create)
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			vm.ReportFailed(
				"sudo cilium bpf ct list global",
				"sudo cilium endpoint list")
		}
		vm.PolicyDelAll()
		netcatPort = 11111
		containers(helpers.Delete)
		res := vm.SetPolicyEnforcement(helpers.PolicyEnforcementDefault)
		res.ExpectSuccess("Setting policyEnforcement to default")
	})

	// containersMeta returns a map where the key is the container name and the
	// value is the result of `ContainerInspectNet` (All the net information
	// related with the container)
	containersMeta := func() map[string]map[string]string {
		result := map[string]map[string]string{}
		for _, x := range containersNames {
			data, err := vm.ContainerInspectNet(x)
			Expect(err).To(BeNil())
			result[x] = data
		}
		return result
	}

	countCTINEntriesOf := func(dst, dstPort, from, identityID string) (int, error) {
		// It counts the number of connection
		if govalidator.IsIPv6(from) {
			from = fmt.Sprintf(`[%s`, from)
		}

		cmd := fmt.Sprintf(`bpf ct list global | grep -F "IN %s" | grep -F " -> %s" | grep "sec_id=%s" | wc -l`,
			net.JoinHostPort(dst, dstPort), from, identityID)
		return vm.ExecCilium(cmd).IntOutput()
	}

	testReach := func(src, dest, destPort, mode string, assertFn func() types.GomegaMatcher) {
		switch mode {
		case http:
			cmd := fmt.Sprintf("http://%s/", net.JoinHostPort(dest, destPort))
			res := vm.ContainerExec(src, helpers.CurlFail(cmd))
			ExpectWithOffset(1, res.WasSuccessful()).Should(assertFn(),
				"Failed to curl '%s': %s (%d)", res.GetCmd(), res.CombineOutput().String(), res.GetExitCode())

		case HTTPDummy:
			cmd := fmt.Sprintf("curl -s --fail -o /dev/null -w %%{http_code} --connect-timeout 5 http://%s/dummy", net.JoinHostPort(dest, destPort))
			res := vm.ContainerExec(src, cmd)
			valid := false
			if res.SingleOut() == "404" {
				valid = true
			}
			ExpectWithOffset(1, valid).Should(assertFn(),
				"Failed to curl '%s' from %s to %s: %s", res.GetCmd(), src, dest, res.CombineOutput().String())

		case HTTPPrivate:
			cmd := fmt.Sprintf("http://%s/private", net.JoinHostPort(dest, destPort))
			res := vm.ContainerExec(src, helpers.CurlFail(cmd))
			ExpectWithOffset(1, res.WasSuccessful()).Should(assertFn(),
				"Failed to curl '%s' from %s to %s: %s", res.GetCmd(), src, dest, res.CombineOutput().String())

		case HTTPPublic:
			cmd := fmt.Sprintf("http://%s/public", net.JoinHostPort(dest, destPort))
			res := vm.ContainerExec(src, helpers.CurlFail(cmd))
			ExpectWithOffset(1, res.WasSuccessful()).Should(assertFn(),
				"Failed to curl '%s' from %s to %s: %s", res.GetCmd(), src, dest, res.CombineOutput().String())

		case netcatPrivate:
			cmd := fmt.Sprintf(`bash -c "python ./nc.py %d 5 %s %s \"/private\" | head -n 1 | grep \"HTTP/1.*200 OK\""`, netcatPort, dest, destPort)
			res := vm.ContainerExec(src, cmd)
			ExpectWithOffset(1, res.WasSuccessful()).Should(assertFn(),
				"Failed to httpRequest '%s' from %s to %s: %s", res.GetCmd(), src, dest, res.CombineOutput().String())

		case netcatPublic:
			cmd := fmt.Sprintf(`bash -c "python ./nc.py %d 5 %s %s \"/public\" | head -n 1 | grep \"HTTP/1.*200 OK\""`, netcatPort, dest, destPort)
			res := vm.ContainerExec(src, cmd)
			ExpectWithOffset(1, res.WasSuccessful()).Should(assertFn(),
				"Failed to httpRequest '%s' from %s to %s: %s", res.GetCmd(), src, dest, res.CombineOutput().String())

		case netcatDummy:
			cmd := fmt.Sprintf(`bash -c "python ./nc.py %d 5 %s %s \"/dummy\" | head -n 1 | grep \"HTTP/1.*200 OK\""`, netcatPort, dest, destPort)
			res := vm.ContainerExec(src, cmd)
			ExpectWithOffset(1, res.WasSuccessful()).Should(assertFn(),
				"Failed to httpRequest '%s' from %s to %s: %s", res.GetCmd(), src, dest, res.CombineOutput().String())

		default:
			Expect(true).To(BeFalse(), "Mode %s is not defined", mode)
		}
	}

	It("testing conntrack entries clean up with L3-only policy", func() {
		By("Installing L3-only policy")

		policy := `[{
	        "endpointSelector": {"matchLabels":{"id.server":""}},
	        "ingress": [{
	            "fromEndpoints": [{
	               "matchLabels":{"id.client":""}
	            }]
	        }],
	        "labels": ["l3-only-policy-server"]
	    },{
	        "endpointSelector": {"matchLabels":{"id.server-2":""}},
	        "ingress": [{
	            "fromEndpoints": [{
	               "matchLabels":{"id.client":""}
	            }]
	        }],
	        "labels": ["l3-only-policy-server-2"]
	    }]
	`

		_, err := vm.PolicyRenderAndImport(policy)
		Expect(err).To(BeNil(), "Installing L3-only policy")

		meta := containersMeta()
		testCombinations := []connTest{
			{meta[client], meta[server], "80", helpers.IPv6, http},
			{meta[client], meta[server], "80", helpers.IPv4, http},
			{meta[client2], meta[server], "80", helpers.IPv6, http},
			{meta[client2], meta[server], "80", helpers.IPv4, http},
			{meta[client], meta[server2], "80", helpers.IPv6, http},
			{meta[client], meta[server2], "80", helpers.IPv4, http},
			{meta[client2], meta[server2], "80", helpers.IPv6, http},
			{meta[client2], meta[server2], "80", helpers.IPv4, http},
		}

		By("Testing if client and client-2 can talk with server and server-2")
		for _, testCase := range testCombinations {
			testReach(testCase.src[helpers.Name], testCase.destination[testCase.kind], testCase.dstPort, testCase.mode, BeTrue)
		}

		epIdentities, err := vm.GetEndpointsIdentityIds()
		Expect(err).To(BeNil(), "Getting endpoint identities")

		By("Counting number of CT Entries")

		for _, testCase := range testCombinations {
			dstIP := testCase.destination[testCase.kind]
			dstPort := testCase.dstPort
			srcIP := testCase.src[testCase.kind]
			srcSecID := epIdentities[testCase.src[helpers.Name]]

			data, err := countCTINEntriesOf(dstIP, dstPort, srcIP, srcSecID)
			Expect(err).To(BeNil(), "Trying to count CT entries of %s and %s", dstIP, srcIP)

			des := fmt.Sprintf("Checking CT entries between %s and %s", dstIP, srcIP)
			Expect(data).To(BeNumerically(comparator, 1), des)
		}

		res := vm.PolicyDel("l3-only-policy-server-2")
		res.ExpectSuccess("Deleting policy `l3-only-policy-server-2`")

		areEndpointsReady := vm.WaitEndpointsReady()
		Expect(areEndpointsReady).Should(BeTrue(), "Endpoints are not in ready state after deleting policy `l3-only-policy-server-2`")

		By("Checking if all server-2 CT IN entries are gone after deleting policy `l3-only-policy-server-2`")
		for _, testCase := range testCombinations {
			dstIP := testCase.destination[testCase.kind]
			dstPort := testCase.dstPort
			srcIP := testCase.src[testCase.kind]
			srcSecID := epIdentities[testCase.src[helpers.Name]]

			data, err := countCTINEntriesOf(dstIP, dstPort, srcIP, srcSecID)
			Expect(err).To(BeNil(), "Trying to count CT entries of %s and %s", dstIP, srcIP)

			wantCTEntries := 0
			if dstIP != meta[server2][testCase.kind] {
				wantCTEntries = 1
			}

			des := fmt.Sprintf("Checking CT entries between %s and %s", dstIP, srcIP)
			Expect(data).To(BeNumerically(comparator, wantCTEntries), des)
		}

		By("Checking if server is reachable and server-2 is unreachable")
		for _, testCase := range testCombinations {
			//Test policies are still applied correctly
			assertfn := BeTrue
			if testCase.destination[helpers.Name] == server2 {
				assertfn = BeFalse
			}
			testReach(testCase.src[helpers.Name], testCase.destination[testCase.kind], testCase.dstPort, testCase.mode, assertfn)
		}
	})

	It("testing conntrack entries clean up with L3-L4 policy", func() {

		By("Installing L3-L4 policy")

		policy := `
		[{
		    "endpointSelector": {"matchLabels":{"id.server":""}},
		    "ingress": [{
		        "fromEndpoints": [
		           {"matchLabels":{"id.client":""}}
		        ],
		        "toPorts": [{
		            "ports": [{"port": "80", "protocol": "tcp"}]
		        }]
		    }],
		    "labels": ["l3-l4-policy-server"]
		},{
		    "endpointSelector": {"matchLabels":{"id.server-2":""}},
		    "ingress": [{
		        "fromEndpoints": [
		           {"matchLabels":{"id.client":""}}
		        ],
		        "toPorts": [{
		            "ports": [{"port": "80", "protocol": "tcp"}]
		        }]
		    }],
		    "labels": ["l3-l4-policy-server-2"]
		}]
	`

		_, err := vm.PolicyRenderAndImport(policy)
		Expect(err).To(BeNil(), "Installing L3-L4 policy")

		meta := containersMeta()

		testCombinations := []connTest{
			{meta[client], meta[server], "80", helpers.IPv6, http},
			{meta[client], meta[server], "80", helpers.IPv4, http},
			{meta[client2], meta[server], "80", helpers.IPv6, http},
			{meta[client2], meta[server], "80", helpers.IPv4, http},
			{meta[client], meta[server2], "80", helpers.IPv6, http},
			{meta[client], meta[server2], "80", helpers.IPv4, http},
			{meta[client2], meta[server2], "80", helpers.IPv6, http},
			{meta[client2], meta[server2], "80", helpers.IPv4, http},
		}

		By("Testing if client and client-2 can talk with server and server-2")
		for _, testCase := range testCombinations {
			testReach(testCase.src[helpers.Name], testCase.destination[testCase.kind], testCase.dstPort, testCase.mode, BeTrue)
		}

		epIdentities, err := vm.GetEndpointsIdentityIds()
		Expect(err).To(BeNil(), "Getting endpoint identities")

		By("Counting the number of CT Entries")

		for _, testCase := range testCombinations {
			dstIP := testCase.destination[testCase.kind]
			dstPort := testCase.dstPort
			srcIP := testCase.src[testCase.kind]
			srcSecID := epIdentities[testCase.src[helpers.Name]]

			data, err := countCTINEntriesOf(dstIP, dstPort, srcIP, srcSecID)
			Expect(err).To(BeNil(), "Trying to count CT entries of %s and %s", dstIP, srcIP)

			des := fmt.Sprintf("Checking CT entries between %s and %s", dstIP, srcIP)
			Expect(data).To(BeNumerically(comparator, 1), des)
		}

		By("Deleting policy `l3-l4-policy-server-2`")
		res := vm.PolicyDel("l3-l4-policy-server-2")
		res.ExpectSuccess("Deleting policy `l3-l4-policy-server-2`")

		areEndpointsReady := vm.WaitEndpointsReady()
		Expect(areEndpointsReady).Should(BeTrue(), "Endpoints are not in ready state after deleting policy `l3-l4-policy-server-2`")

		By("Checking if all server-2 CT IN entries are gone after deleting policy `l3-l4-policy-server-2`")
		for _, testCase := range testCombinations {
			dstIP := testCase.destination[testCase.kind]
			dstPort := testCase.dstPort
			srcIP := testCase.src[testCase.kind]
			srcSecID := epIdentities[testCase.src[helpers.Name]]

			data, err := countCTINEntriesOf(dstIP, dstPort, srcIP, srcSecID)
			Expect(err).To(BeNil(), "Trying to count CT entries of %s and %s", dstIP, srcIP)

			wantCTEntries := 0
			// Since we removed all policies related with server-2
			// then all other endpoints should have at least one entry
			if dstIP != meta[server2][testCase.kind] {
				wantCTEntries = 1
			}

			des := fmt.Sprintf("Checking CT entries between %s and %s", dstIP, srcIP)
			Expect(data).To(BeNumerically(comparator, wantCTEntries), des)
		}

		By("Checking if server is reachable and server-2 is unreachable")
		for _, testCase := range testCombinations {
			//Test policies are still applied correctly
			assertfn := BeTrue
			if testCase.destination[helpers.Name] == server2 {
				assertfn = BeFalse
			}
			testReach(testCase.src[helpers.Name], testCase.destination[testCase.kind], testCase.dstPort, testCase.mode, assertfn)
		}
	})

	It("testing conntrack entries clean up with L7 policy after a L3-L4 connectivity", func() {

		meta := containersMeta()

		By("Installing L3-L4 policy")

		policy := `
		[{
			"endpointSelector": {"matchLabels":{"id.server-3":""}},
			"ingress": [{
				"fromEndpoints": [{
				   "matchLabels":{"id.client":""}
				}],
				"toPorts": [{
					"ports": [{"port": "80", "protocol": "tcp"}]
				}]
			}],
			"labels": ["l3-l4-policy-server-3"]
		}]
		`
		_, err := vm.PolicyRenderAndImport(policy)
		Expect(err).To(BeNil())

		testCombinations := []connTest{
			{meta[client], meta[server3], "80", helpers.IPv6, HTTPPrivate},
			{meta[client], meta[server3], "80", helpers.IPv4, HTTPPrivate},
			{meta[client], meta[server3], "80", helpers.IPv6, HTTPPublic},
			{meta[client], meta[server3], "80", helpers.IPv4, HTTPPublic},
			{meta[client], meta[server3], "80", helpers.IPv6, netcatPrivate},
			{meta[client], meta[server3], "80", helpers.IPv4, netcatPrivate},
			{meta[client], meta[server3], "80", helpers.IPv6, netcatPublic},
			{meta[client], meta[server3], "80", helpers.IPv4, netcatPublic},
		}

		By("Testing connectivity between client and server 3")
		for _, testCase := range testCombinations {
			testReach(testCase.src[helpers.Name], testCase.destination[testCase.kind], testCase.dstPort, testCase.mode, BeTrue)
		}

		res := vm.PolicyDel("l3-l4-policy-server-3")
		res.WasSuccessful()

		By("Installing L3-L4-L7 policy")

		policy2 := `
		[{
			"endpointSelector": {"matchLabels":{"id.server-3":""}},
			"ingress": [{
				"fromEndpoints": [{
				   "matchLabels":{"id.client":""}
				}],
				"toPorts": [{
					"ports": [{"port": "80", "protocol": "tcp"}],
					"rules": {"http": [{
						  "path": "/public",
						  "method": "GET"
					}]}
				}]
			}],
			"labels": ["l3-l4-policy-server-3"]
		}]`

		_, err = vm.PolicyRenderAndImport(policy2)
		Expect(err).To(BeNil(), "Installing an L3-L4-L7 policy")

		By("Testing connectivity between client and server 3 only on /public")
		for _, testCase := range testCombinations {
			assertfn := BeTrue
			if strings.Contains(strings.ToLower(testCase.mode), "private") {
				assertfn = BeFalse
			}
			testReach(testCase.src[helpers.Name], testCase.destination[testCase.kind], testCase.dstPort, testCase.mode, assertfn)
		}

		By("Removing policy `l3-l4-policy-server-3`")
		res = vm.PolicyDel("l3-l4-policy-server-3")
		res.WasSuccessful()

		By("Installing other L7 rule after testing L7. The previous rule shouldn't work!")

		policyL7Dummy := `
			[{
				"endpointSelector": {"matchLabels":{"id.server-3":""}},
				"ingress": [{
					"fromEndpoints": [{
					   "matchLabels":{"id.client":""}
					}],
					"toPorts": [{
						"ports": [{"port": "80", "protocol": "tcp"}],
						"rules": {"http": [{
							  "path": "/dummy",
							  "method": "GET"
						}]}
					}]
				}],
				"labels": ["l3-l4-l7-policy-server-3"]
			}]`

		_, err = vm.PolicyRenderAndImport(policyL7Dummy)
		Expect(err).To(BeNil())

		By("Testing connectivity to HTTP endpoint /dummy")
		testReach(client, meta[server3][helpers.IPv4], "80", HTTPDummy, BeTrue)
		testReach(client, meta[server3][helpers.IPv6], "80", HTTPDummy, BeTrue)

		By("Testing non-connectivity on remaining HTTP endpoints")
		for _, testCase := range testCombinations {
			testReach(testCase.src[helpers.Name], testCase.destination[testCase.kind], "80", testCase.mode, BeFalse)
		}

	})

	It("Testing proxy redirect after installing L3-L4-L7 policy over an existing L3-L4 policy", func() {
		meta := containersMeta()

		By("Installing L3-L4 policy")
		policy := `
		[{
			"endpointSelector": {"matchLabels":{"id.server-3":""}},
			"ingress": [{
				"fromEndpoints": [{
				   "matchLabels":{"id.client":""}
				}],
				"toPorts": [{
					"ports": [{"port": "80", "protocol": "tcp"}]
				}]
			}],
			"labels": ["l3-l4-policy-server-3"]
		}]
		`
		_, err := vm.PolicyRenderAndImport(policy)
		Expect(err).To(BeNil(), "Installing an L3-L4 policy")

		testCombinations := []connTest{
			{meta[client], meta[server3], "80", helpers.IPv6, netcatPrivate},
			{meta[client], meta[server3], "80", helpers.IPv4, netcatPrivate},
			{meta[client], meta[server3], "80", helpers.IPv6, netcatPublic},
			{meta[client], meta[server3], "80", helpers.IPv4, netcatPublic},
		}

		for _, testCase := range testCombinations {
			testReach(testCase.src[helpers.Name], testCase.destination[testCase.kind], testCase.dstPort, testCase.mode, BeTrue)
		}

		By("Installing L3-L4-L7 policy")

		policyL7 := `
		[{
			"endpointSelector": {"matchLabels":{"id.server-3":""}},
			"ingress": [{
				"fromEndpoints": [{
				   "matchLabels":{"id.client":""}
				}],
				"toPorts": [{
					"ports": [{"port": "80", "protocol": "tcp"}],
					"rules": {"http": [{
						  "path": "/public",
						  "method": "GET"
					}]}
				}]
			}],
			"labels": ["l3-l4-l7-policy-server-3"]
		}]`

		_, err = vm.PolicyRenderAndImport(policyL7)
		Expect(err).To(BeNil(), "Installing an L3-L4-L7 policy")

		By("Testing connectivity to /public and non-connectivity to /private")
		for _, testCase := range testCombinations {
			assertfn := BeTrue
			if strings.Contains(strings.ToLower(testCase.mode), "private") {
				assertfn = BeFalse
			}
			testReach(testCase.src[helpers.Name], testCase.destination[testCase.kind], testCase.dstPort, testCase.mode, assertfn)
		}

		By("Removing policy with labels `l3-l4-l7-policy-server-3`")
		res := vm.PolicyDel("l3-l4-l7-policy-server-3")
		res.ExpectSuccess("Deleting policy `l3-l4-l7-policy-server-3`: %s", res.CombineOutput())

		By("Testing connectivity to confirm policy enforcement without going through the proxy")
		for _, testCase := range testCombinations {
			testReach(testCase.src[helpers.Name], testCase.destination[testCase.kind], testCase.dstPort, testCase.mode, BeTrue)
		}

		vm.PolicyDelAll().ExpectSuccess("Deleting all policies")
		Expect(vm.WaitEndpointsReady()).To(BeTrue(), "Endpoints are not ready after deleting all policies")

		By("Testing non-connectivity between all endpoints")
		for _, testCase := range testCombinations {
			testReach(testCase.src[helpers.Name], testCase.destination[testCase.kind], testCase.dstPort, testCase.mode, BeFalse)
		}

	})

	It("Testing L3-L4-L7 policy while the L3-L4 connection was previously made to confirm L3-L4-L7 policy enforcement over the proxy with the same source port", func() {
		By("Setting policyEnforcement default")
		res := vm.SetPolicyEnforcement(helpers.PolicyEnforcementDefault)
		res.ExpectSuccess("Setting policy enforcement as default")

		// #FIXME remove these 6 lines once GH-2496 is fixed
		epIDs, err := vm.GetEndpointsIds()
		Expect(err).To(BeNil(), "Getting endpoints identity IDs")
		for _, v := range epIDs {
			vm.ExecCilium(fmt.Sprintf("endpoint config %s IngressPolicy=false", v)).ExpectSuccess("Setting %s endpoint's IngressPolicy as false", v)
			vm.ExecCilium(fmt.Sprintf("endpoint config %s EgressPolicy=false", v)).ExpectSuccess("Setting %s endpoint's EgressPolicy as false", v)
		}

		areEndpointsReady := vm.WaitEndpointsReady()
		Expect(areEndpointsReady).Should(BeTrue(), "Endpoints not ready after timeout")

		meta := containersMeta()

		testCombinations := []connTest{
			{meta[client], meta[server3], "80", helpers.IPv6, HTTPPublic},
			{meta[client], meta[server3], "80", helpers.IPv6, HTTPPublic},
			{meta[client], meta[server3], "80", helpers.IPv4, HTTPPrivate},
			{meta[client], meta[server3], "80", helpers.IPv4, HTTPPrivate},
			{meta[client], meta[server3], "80", helpers.IPv6, netcatPrivate},
			{meta[client], meta[server3], "80", helpers.IPv4, netcatPrivate},
			{meta[client], meta[server3], "80", helpers.IPv6, netcatPublic},
			{meta[client], meta[server3], "80", helpers.IPv4, netcatPublic},
		}

		By("Testing connectivity between client and server-3 on all HTTP endpoints")
		for _, testCase := range testCombinations {
			testReach(testCase.src[helpers.Name], testCase.destination[testCase.kind], testCase.dstPort, testCase.mode, BeTrue)
		}

		// Using a different netcat source port
		netcatPort = 11112
		testReach(client, meta[server3][helpers.IPv4], "80", netcatPrivate, BeTrue)
		testReach(client, meta[server3][helpers.IPv6], "80", netcatPrivate, BeTrue)
		netcatPort = 11111

		epIdentities, err := vm.GetEndpointsIdentityIds()
		Expect(err).To(BeNil(), "Getting endpoint identities")

		By("Checking if CT entries from server-3 to client is the number of connections made")
		data, err := countCTINEntriesOf(meta[server3][helpers.IPv6], "80", meta[client][helpers.IPv6], epIdentities[client])
		Expect(err).To(BeNil())
		Expect(data).To(BeNumerically(comparator, 4), "CT map should have exactly 4 entries or less between server-3 and client")

		data, err = countCTINEntriesOf(meta[server3][helpers.IPv4], "80", meta[client][helpers.IPv4], epIdentities[client])
		Expect(err).To(BeNil())
		Expect(data).To(BeNumerically(comparator, 4), "CT map should have exactly 4 entries or less between server-3 and client")

		policyL7 := `[{
	    "endpointSelector": {"matchLabels":{"id.server-3":""}},
	    "ingress": [{
	        "fromEndpoints": [{
	           "matchLabels":{"id.client":""}
	        }],
	        "toPorts": [{
	            "ports": [{"port": "80", "protocol": "tcp"}],
	            "rules": {"http": [{
	                  "path": "/public",
	                  "method": "GET"
	            }]}
	        }]
	    }],
	    "labels": ["l3-l4-l7-policy-server-3"]
	}]`

		By("Installing L3-L4-L7 policy")
		_, err = vm.PolicyRenderAndImport(policyL7)
		Expect(err).To(BeNil(), "Installing an L3-L4 policy")

		By("Testing connectivity between client and server-3 on all HTTP endpoints")
		for _, testCase := range testCombinations {
			assertfn := BeTrue
			if strings.Contains(strings.ToLower(testCase.mode), "private") {
				assertfn = BeFalse
			}
			testReach(testCase.src[helpers.Name], testCase.destination[testCase.kind], testCase.dstPort, testCase.mode, assertfn)
		}
		netcatPort = 11112
		testReach(client, meta[server3][helpers.IPv4], "80", netcatPrivate, BeFalse)
		testReach(client, meta[server3][helpers.IPv6], "80", netcatPrivate, BeFalse)
		netcatPort = 11111

	})

	It("Testing L7 proxy redirection after a L3 connection is made with the exact 5 tuple", func() {
		vm.SetPolicyEnforcement(helpers.PolicyEnforcementDefault)
		vm.WaitEndpointsReady()
		epIdentities, err := vm.GetEndpointsIdentityIds()
		Expect(err).To(BeNil(), "Getting endpoints identity IDs")

		res := vm.PolicyDelAll()
		res.ExpectSuccess("Deleting all policies")

		policy := `
		[{
		    "endpointSelector": {"matchLabels":{"id.server-4":""}},
		    "ingress": [{
		      "fromEndpoints": [{
		        "matchLabels":{"id.client":""}
		      }]
		    }],
		    "labels": ["l3-policy-server-4"]
		}]
        `

		By("Installing L3-only policy")
		_, err = vm.PolicyRenderAndImport(policy)
		Expect(err).To(BeNil(), "Installing an L3-only policy")

		areEndpointsReady := vm.WaitEndpointsReady()
		Expect(areEndpointsReady).Should(BeTrue(), "Endpoints not ready after timeout")

		meta := containersMeta()

		testCombinations := []connTest{
			{meta[client], meta[netcat], "80", helpers.IPv4, netcatDummy},
			{meta[client], meta[netcat], "80", helpers.IPv6, netcatDummy},
			{meta[client], meta[netcat], "81", helpers.IPv4, netcatDummy},
			{meta[client], meta[netcat], "82", helpers.IPv6, netcatDummy},
			{meta[client], meta[netcat], "83", helpers.IPv4, netcatDummy},
			{meta[client], meta[netcat], "84", helpers.IPv6, netcatDummy},
			{meta[client], meta[netcat], "85", helpers.IPv4, netcatDummy},
			{meta[client], meta[netcat], "86", helpers.IPv6, netcatDummy},
		}

		By("Testing connectivity to any HTTP endpoint")
		for _, testCase := range testCombinations {
			ip := ""
			switch testCase.kind {
			case helpers.IPv4:
				ip = "0.0.0.0"
			case helpers.IPv6:
				ip = "[::]"
			}

			ncCmd := fmt.Sprintf(`docker exec -d netcat sh -c "echo -n \"HTTP/1.1 200 OK\nContent-Length: 0\n\r\r\" | nc -l -s %s -p %s"`, ip, testCase.dstPort)
			des := fmt.Sprintf("Unable to start listening for requests on container netcat on port %s", net.JoinHostPort(ip, testCase.dstPort))
			vm.Exec(ncCmd).ExpectSuccess(des)

			testReach(testCase.src[helpers.Name], testCase.destination[testCase.kind], testCase.dstPort, testCase.mode, BeTrue)
		}

		countNCwithClientCTEntries := func(kind string, nEntries int, dstPort string) {
			data, err := countCTINEntriesOf(meta[netcat][kind], dstPort, meta[client][kind], epIdentities[client])
			ExpectWithOffset(1, err).To(BeNil(),
				"Trying to count CT entries of %s:%s and %s",
				meta[netcat][kind], dstPort, meta[client][kind])

			ExpectWithOffset(1, data).To(BeNumerically(comparator, nEntries),
				"Checking CT entries between %s:%s and %s",
				meta[netcat][kind], dstPort, meta[client][kind])
		}

		By("Counting if the number of CT entries are the exact number of different ports used in the connectivity tests")

		countNCwithClientCTEntries(helpers.IPv4, 5, "")
		countNCwithClientCTEntries(helpers.IPv6, 5, "")

		policyP3 := `[{
    "endpointSelector": {"matchLabels":{"id.server-4":""}},
    "ingress": [{
        "fromEndpoints": [{
           "matchLabels":{"id.client":""}
        }],
        "toPorts": [{
            "ports": [{"port": "80", "protocol": "tcp"}],
            "rules": {"http": [{
                  "path": "/public",
                  "method": "GET"
            }]}
        }]
    },{
        "fromEndpoints": [{
           "matchLabels":{"id.client":""}
        }],
        "toPorts": [{
            "ports": [{"port": "81", "protocol": "tcp"},{"port": "82", "protocol": "tcp"}]
        }]
    }],
    "labels": ["l3-l4-l7-policy-server-4"]
}]`

		By("Installing L3-L4-L7-only policy")
		_, err = vm.PolicyRenderAndImport(policyP3)
		Expect(err).To(BeNil(), "Installing an L3-only policy")

		By("Checking if only port 80, 81 and port 82 are open in the CT table since they are specified on an imported rule")

		countNCwithClientCTEntries(helpers.IPv4, 1, "80")
		countNCwithClientCTEntries(helpers.IPv6, 1, "80")
		countNCwithClientCTEntries(helpers.IPv4, 1, "81")
		countNCwithClientCTEntries(helpers.IPv6, 1, "82")
		countNCwithClientCTEntries(helpers.IPv4, 0, "83")
		countNCwithClientCTEntries(helpers.IPv6, 0, "84")
		countNCwithClientCTEntries(helpers.IPv4, 0, "85")
		countNCwithClientCTEntries(helpers.IPv6, 0, "86")

	})

})
