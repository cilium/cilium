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
	"os"
	"sync"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/policy/api"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	"github.com/cilium/cilium/test/helpers/constants"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	"github.com/sirupsen/logrus"
)

const (
	// Commands
	ping              = "ping"
	ping6             = "ping6"
	http              = "http"
	http6             = "http6"
	httpPrivate       = "http_private"
	http6Private      = "http6_private"
	httpPrivateToken  = "http_private_token"
	http6PrivateToken = "http6_private_token"
	httpPathRewrite   = "http_path_rewrite"
	http6PathRewrite  = "http6_path_rewrite"

	// Policy files
	policyJSON                      = "policy.json"
	invalidJSON                     = "invalid.json"
	multL7PoliciesJSON              = "Policies-l7-multiple.json"
	policiesL7JSON                  = "Policies-l7-simple.json"
	imposePoliciesL7JSON            = "Policies-l7-impose.json"
	policiesL3JSON                  = "Policies-l3-policy.json"
	policiesL4Json                  = "Policies-l4-policy.json"
	policiesL3DependentL7EgressJSON = "Policies-l3-dependent-l7-egress.json"
	policiesReservedInitJSON        = "Policies-reserved-init.json"
)

var _ = Describe("RuntimePolicies", func() {

	var (
		vm            *helpers.SSHMeta
		monitorStop   = func() error { return nil }
		initContainer string
		testStartTime time.Time
	)

	BeforeAll(func() {
		vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)

		// We need to stop and start Cilium separately (vs. doing a restart) to
		// allow us to validate only the logs of the startup. The stop may
		// contain "bad" log messages but they are expected (abrupt stop during
		// endpoint regeneration).
		vm.ExecWithSudo("systemctl stop cilium").ExpectSuccess("Failed trying to stop cilium via systemctl")
		ExpectCiliumNotRunning(vm)
		testStartTime = time.Now()

		// Make sure that Cilium is started with appropriate CLI options
		// (specifically to exclude the local addresses that are populated for
		// CIDR policy tests).
		Expect(vm.SetUpCiliumWithHubble()).To(BeNil())
		ExpectCiliumReady(vm)
		vm.SampleContainersActions(helpers.Create, helpers.CiliumDockerNetwork)
		vm.PolicyDelAll()

		initContainer = "initContainer"

		Expect(vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")

		vm.ValidateNoErrorsInLogs(time.Since(testStartTime))
	})

	BeforeEach(func() {
		ExpectPolicyEnforcementUpdated(vm, helpers.PolicyEnforcementDefault)
	})

	AfterEach(func() {
		vm.PolicyDelAll().ExpectSuccess("Unable to delete all policies")
	})

	JustBeforeEach(func() {
		_, monitorStop = vm.MonitorStart()
		testStartTime = time.Now()
	})

	JustAfterEach(func() {
		vm.ValidateNoErrorsInLogs(time.Since(testStartTime))
		Expect(monitorStop()).To(BeNil(), "cannot stop monitor command")
	})

	AfterFailed(func() {
		vm.ReportFailed()
	})

	AfterAll(func() {
		vm.PolicyDelAll().ExpectSuccess("Unable to delete all policies")
		vm.SampleContainersActions(helpers.Delete, helpers.CiliumDockerNetwork)
		vm.CloseSSHClient()
	})

	pingRequests := []string{ping, ping6}
	httpRequestsPublic := []string{http, http6}
	httpRequestsPrivate := []string{httpPrivate, http6Private}
	httpRequestsPrivateToken := []string{httpPrivateToken, http6PrivateToken}
	httpRequestsPathRewrite := []string{httpPathRewrite, http6PathRewrite}
	httpRequests := append(httpRequestsPublic, httpRequestsPrivate...)
	httpRequests = append(httpRequests, httpRequestsPathRewrite...)
	allRequests := append(pingRequests, httpRequests...)
	connectivityTest := func(tests []string, client, server string, expectsSuccess bool) {
		var assertFn func() types.GomegaMatcher
		if expectsSuccess {
			assertFn = BeTrue
		} else {
			assertFn = BeFalse
		}

		if client != helpers.Host {
			_, err := vm.ContainerInspectNet(client)
			ExpectWithOffset(1, err).Should(BeNil(), fmt.Sprintf(
				"could not get container %q (client) meta", client))
		}

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
			case http, httpPrivate, httpPrivateToken, httpPathRewrite:
				dst = srvIP[helpers.IPv4]
			case http6, http6Private, http6PrivateToken, http6PathRewrite:
				dst = fmt.Sprintf("[%s]", srvIP[helpers.IPv6])
			}
			switch test {
			case ping:
				commandName = "ping"
			case ping6:
				commandName = "ping6"
			case http:
				commandName = "curl public IPv4 URL on"
				command = helpers.CurlFail("http://%s:80/public", dst)
			case http6:
				commandName = "curl public IPv6 URL on"
				command = helpers.CurlFail("http://%s:80/public", dst)
			case httpPrivate:
				commandName = "curl private IPv4 URL on"
				command = helpers.CurlFail("http://%s:80/private", dst)
			case http6Private:
				commandName = "curl private IPv6 URL on"
				command = helpers.CurlFail("http://%s:80/private", dst)
			case httpPrivateToken:
				commandName = "curl private IPv4 URL with an access-token 1234-09AB-5678-CDEF on"
				command = helpers.CurlFail(`--header "Access-Token: 1234-09AB-5678-CDEF" http://%s:80/private`, dst)
			case http6PrivateToken:
				commandName = "curl private IPv6 URL with an access-token 1234-09AB-5678-CDEF on"
				command = helpers.CurlFail(`--header "Access-Token: 1234-09AB-5678-CDEF" http://%s:80/private`, dst)
			case httpPathRewrite:
				commandName = "curl path rewrite IPv4 URL on"
				command = helpers.CurlFail("http://%s:80/public/../private", dst)
			case http6PathRewrite:
				commandName = "curl path rewrite IPv6 URL on"
				command = helpers.CurlFail("http://%s:80/public/../private", dst)
			}
			if expectsSuccess {
				resultName = "succeed"
			} else {
				resultName = "fail"
			}
			By("%q attempting to %q %q", client, commandName, server)
			var res *helpers.CmdRes
			if client != helpers.Host {
				res = vm.ContainerExec(client, command)
			} else {
				res = vm.Exec(command)
			}
			ExpectWithOffset(1, res.WasSuccessful()).Should(assertFn(),
				fmt.Sprintf("%q expects %s %s (%s) to %s", client, commandName, server, dst, resultName))
		}
	}

	checkProxyStatistics := func(epID string, reqsFwd, reqsReceived, reqsDenied, respFwd, respReceived int) {
		epModel := vm.EndpointGet(epID)
		Expect(epModel).To(Not(BeNil()), "nil model returned for endpoint %s", epID)
		for _, epProxyStatistics := range epModel.Status.Policy.ProxyStatistics {
			if epProxyStatistics.Location == models.ProxyStatisticsLocationEgress {
				ExpectWithOffset(1, epProxyStatistics.Statistics.Requests.Forwarded).To(BeEquivalentTo(reqsFwd), "Unexpected number of forwarded requests to proxy")
				ExpectWithOffset(1, epProxyStatistics.Statistics.Requests.Received).To(BeEquivalentTo(reqsReceived), "Unexpected number of received requests to proxy")
				ExpectWithOffset(1, epProxyStatistics.Statistics.Requests.Denied).To(BeEquivalentTo(reqsDenied), "Unexpected number of denied requests to proxy")
				ExpectWithOffset(1, epProxyStatistics.Statistics.Responses.Forwarded).To(BeEquivalentTo(respFwd), "Unexpected number of forwarded responses from proxy")
				ExpectWithOffset(1, epProxyStatistics.Statistics.Responses.Received).To(BeEquivalentTo(respReceived), "Unexpected number of received responses from proxy")
			}
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
		Expect(vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")

		connectivityTest(allRequests, helpers.App1, helpers.Httpd1, true)
		connectivityTest(allRequests, helpers.App2, helpers.Httpd1, true)
	})

	It("L4Policy Checks", func() {
		_, err := vm.PolicyImportAndWait(vm.GetFullPath(policiesL4Json), helpers.HelperTimeout)
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

		vm.PolicyDelAll().ExpectSuccess("cannot delete the policy")
		Expect(vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")

		for _, app := range []string{helpers.App1, helpers.App2} {
			connectivityTest(allRequests, app, helpers.Httpd1, true)
			connectivityTest(allRequests, app, helpers.Httpd2, true)
		}
	})

	It("Checks that traffic is not dropped when L4 policy is installed and deleted", func() {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		srvIP, err := vm.ContainerInspectNet(helpers.Httpd1)
		Expect(err).Should(BeNil(), "Cannot get httpd1 server address")
		type BackgroundTestAsserts struct {
			res  *helpers.CmdRes
			time time.Time
		}
		backgroundChecks := []*BackgroundTestAsserts{}
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			for {
				select {
				default:
					res := vm.ContainerExec(
						helpers.App1,
						helpers.CurlFail("http://%s/", srvIP[helpers.IPv4]))
					assert := &BackgroundTestAsserts{
						res:  res,
						time: time.Now(),
					}
					backgroundChecks = append(backgroundChecks, assert)
				case <-ctx.Done():
					wg.Done()
					return
				}
			}
		}()
		// Sleep a bit to make sure that the goroutine starts.
		time.Sleep(50 * time.Millisecond)

		_, err = vm.PolicyImportAndWait(vm.GetFullPath(policiesL4Json), helpers.HelperTimeout)
		Expect(err).Should(BeNil(), "Cannot install L4 policy")

		By("Uninstalling policy")
		vm.PolicyDelAll().ExpectSuccess("Cannot delete all policies")
		Expect(vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")

		By("Canceling background connections from app2 to httpd1")
		cancel()
		wg.Wait()
		GinkgoPrint("Made %d connections in total", len(backgroundChecks))
		Expect(backgroundChecks).ShouldNot(BeEmpty(), "No background connections were made")
		for _, check := range backgroundChecks {
			check.res.ExpectSuccess("Curl from app2 to httpd1 should work but it failed at %s", check.time)
		}
	})

	It("L7 Checks", func() {

		_, err := vm.PolicyImportAndWait(vm.GetFullPath(policiesL7JSON), helpers.HelperTimeout)
		Expect(err).Should(BeNil())

		By("Simple Ingress")
		// app1 can connect to /public, but not to /private.
		connectivityTest(httpRequestsPublic, helpers.App1, helpers.Httpd1, true)
		connectivityTest(httpRequestsPrivate, helpers.App1, helpers.Httpd1, false)

		// app1 can't exploit path rewrite
		connectivityTest(httpRequestsPathRewrite, helpers.App1, helpers.Httpd1, false)

		// Host can connect to /public, but not to /private.
		connectivityTest(httpRequestsPublic, helpers.Host, helpers.Httpd1, true)
		connectivityTest(httpRequestsPrivate, helpers.Host, helpers.Httpd1, false)

		// Host can't exploit path rewrite
		connectivityTest(httpRequestsPathRewrite, helpers.Host, helpers.Httpd1, false)

		// app cannot connect to httpd1 because httpd1 only allows ingress from app1.
		connectivityTest(httpRequestsPublic, helpers.App2, helpers.Httpd1, false)

		By("Simple Egress")

		// app2 can connect to public, but no to private
		connectivityTest(httpRequestsPublic, helpers.App2, helpers.Httpd2, true)
		connectivityTest(httpRequestsPrivate, helpers.App2, helpers.Httpd2, false)

		// app2 can't exploit path rewrite
		connectivityTest(httpRequestsPathRewrite, helpers.App2, helpers.Httpd2, false)

		// TODO (1488) - uncomment when l3-dependent-l7 is merged for egress.
		//connectivityTest(httpRequestsPublic, helpers.App3, helpers.Httpd3, true)
		//connectivityTest(httpRequestsPrivate, helpers.App3, helpers.Httpd3, false)
		//connectivityTest(allRequests, helpers.App3, helpers.Httpd2, false)

		By("Disabling all the policies. All should work")

		status := vm.PolicyDelAll()
		status.ExpectSuccess()
		Expect(vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")

		connectivityTest(allRequests, helpers.App1, helpers.Httpd1, true)
		connectivityTest(allRequests, helpers.App2, helpers.Httpd1, true)

		By("Impose header on Egress, verify on ingress")

		vm.PolicyDelAll()
		_, err = vm.PolicyImportAndWait(vm.GetFullPath(imposePoliciesL7JSON), helpers.HelperTimeout)
		Expect(err).Should(BeNil())

		// app1 can connect to public, but not to private
		connectivityTest(httpRequestsPublic, helpers.App1, helpers.Httpd1, true)
		connectivityTest(httpRequestsPrivate, helpers.App1, helpers.Httpd1, false)

		// app1 succeeds if the right access token is used
		connectivityTest(httpRequestsPrivateToken, helpers.App1, helpers.Httpd1, true)

		// app2 can connect to public, and to private due to access token being inserted at egress
		connectivityTest(httpRequestsPublic, helpers.App2, helpers.Httpd2, true)
		connectivityTest(httpRequestsPrivate, helpers.App2, helpers.Httpd2, true)

		By("Multiple Ingress")

		vm.PolicyDelAll()
		_, err = vm.PolicyImportAndWait(vm.GetFullPath(multL7PoliciesJSON), helpers.HelperTimeout)
		Expect(err).Should(BeNil())

		//APP1 can connect to public, but no to private

		connectivityTest(httpRequestsPublic, helpers.App1, helpers.Httpd1, true)
		connectivityTest(httpRequestsPrivate, helpers.App1, helpers.Httpd1, false)

		//App2 can't connect
		connectivityTest(httpRequestsPublic, helpers.App2, helpers.Httpd1, false)

		By("Multiple Ingress rules on same port")
		// app1 can connect to /public on httpd2
		connectivityTest(httpRequestsPublic, helpers.App1, helpers.Httpd2, true)

		By("Multiple Egress")
		// app2 can connect to /public, but not to /private
		connectivityTest(httpRequestsPublic, helpers.App2, helpers.Httpd2, true)
		connectivityTest(httpRequestsPrivate, helpers.App2, helpers.Httpd2, false)

		By("Disabling all the policies. All should work")

		status = vm.PolicyDelAll()
		status.ExpectSuccess()
		Expect(vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")

		connectivityTest(allRequests, helpers.App1, helpers.Httpd1, true)
		connectivityTest(allRequests, helpers.App2, helpers.Httpd1, true)
	})

	It("Tests Endpoint Connectivity Functions After Daemon Configuration Is Updated", func() {
		httpd1DockerNetworking, err := vm.ContainerInspectNet(helpers.Httpd1)
		Expect(err).ToNot(HaveOccurred(), "unable to get container networking metadata for %s", helpers.Httpd1)

		// Importing a policy to ensure that not only does endpoint connectivity
		// work after updating daemon configuration, but that policy works as well.
		By("Importing policy and waiting for revision to increase for endpoints")
		_, err = vm.PolicyImportAndWait(vm.GetFullPath(policiesL7JSON), helpers.HelperTimeout)
		Expect(err).ToNot(HaveOccurred(), "unable to import policy after timeout")

		By("Trying to access %s:80/public from %s before daemon configuration is updated (should be allowed by policy)", helpers.Httpd1, helpers.App1)
		res := vm.ContainerExec(helpers.App1, helpers.CurlFail("http://%s:80/public", httpd1DockerNetworking[helpers.IPv4]))
		res.ExpectSuccess("unable to access %s:80/public from %s (should have worked)", helpers.Httpd1, helpers.App1)

		By("Trying to access %s:80/private from %s before daemon configuration is updated (should not be allowed by policy)", helpers.Httpd1, helpers.App1)
		res = vm.ContainerExec(helpers.App1, helpers.CurlFail("http://%s:80/private", httpd1DockerNetworking[helpers.IPv4]))
		res.ExpectFail("unable to access %s:80/private from %s (should not have worked)", helpers.Httpd1, helpers.App1)

		By("Getting configuration for daemon")
		daemonDebugConfig, err := vm.ExecCilium("config -o json").Filter("{.Debug}")
		Expect(err).ToNot(HaveOccurred(), "Unable to get configuration for daemon")

		daemonDebugConfigString := daemonDebugConfig.String()

		var daemonDebugConfigSwitched string

		switch daemonDebugConfigString {
		case "Disabled":
			daemonDebugConfigSwitched = "Enabled"
		case "Enabled":
			daemonDebugConfigSwitched = "Disabled"
		default:
			Fail(fmt.Sprintf("invalid configuration value for daemon: Debug=%s", daemonDebugConfigString))
		}

		currentRev, err := vm.PolicyGetRevision()
		Expect(err).ToNot(HaveOccurred(), "unable to get policy revision")

		// TODO: would be a good idea to factor out daemon configuration updates
		// into a function in the future.
		By("Changing daemon configuration from Debug=%s to Debug=%s to induce policy recalculation for endpoints", daemonDebugConfigString, daemonDebugConfigSwitched)
		res = vm.ExecCilium(fmt.Sprintf("config Debug=%s", daemonDebugConfigSwitched))
		res.ExpectSuccess("unable to change daemon configuration")

		By("Getting policy revision after daemon configuration change")
		revAfterConfig, err := vm.PolicyGetRevision()
		Expect(err).ToNot(HaveOccurred(), "unable to get policy revision")
		Expect(revAfterConfig).To(BeNumerically(">=", currentRev+1))

		By("Waiting for policy revision to increase after daemon configuration change")
		res = vm.PolicyWait(revAfterConfig)
		res.ExpectSuccess("policy revision was not bumped after daemon configuration changes")

		By("Changing daemon configuration back from Debug=%s to Debug=%s", daemonDebugConfigSwitched, daemonDebugConfigString)
		res = vm.ExecCilium(fmt.Sprintf("config Debug=%s", daemonDebugConfigString))
		res.ExpectSuccess("unable to change daemon configuration")

		By("Getting policy revision after daemon configuration change")
		revAfterSecondConfig, err := vm.PolicyGetRevision()
		Expect(err).To(BeNil())
		Expect(revAfterSecondConfig).To(BeNumerically(">=", revAfterConfig+1))

		By("Waiting for policy revision to increase after daemon configuration change")
		res = vm.PolicyWait(revAfterSecondConfig)
		res.ExpectSuccess("policy revision was not bumped after daemon configuration changes")

		By("Trying to access %s:80/public from %s after daemon configuration was updated (should be allowed by policy)", helpers.Httpd1, helpers.App1)
		res = vm.ContainerExec(helpers.App1, helpers.CurlFail("http://%s:80/public", httpd1DockerNetworking[helpers.IPv4]))
		res.ExpectSuccess("unable to access %s:80/public from %s (should have worked)", helpers.Httpd1, helpers.App1)

		By("Trying to access %s:80/private from %s after daemon configuration is updated (should not be allowed by policy)", helpers.Httpd1, helpers.App1)
		res = vm.ContainerExec(helpers.App1, helpers.CurlFail("http://%s:80/private", httpd1DockerNetworking[helpers.IPv4]))
		res.ExpectFail("unable to access %s:80/private from %s (should not have worked)", helpers.Httpd1, helpers.App1)
	})

	It("L3-Dependent L7 Egress", func() {
		_, err := vm.PolicyImportAndWait(vm.GetFullPath(policiesL3DependentL7EgressJSON), helpers.HelperTimeout)
		Expect(err).Should(BeNil(), "unable to import %s", policiesL3DependentL7EgressJSON)

		Expect(vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")

		endpointIDS, err := vm.GetEndpointsIds()
		Expect(err).To(BeNil(), "Unable to get IDs of endpoints")

		app3EndpointID, exists := endpointIDS[helpers.App3]
		Expect(exists).To(BeTrue(), "Expected endpoint ID to exist for %s", helpers.App3)

		connectivityTest(httpRequestsPublic, helpers.Host, helpers.Httpd2, true)

		connectivityTest(httpRequestsPublic, helpers.App3, helpers.Httpd1, true)

		// Since policy allows connectivity on /public to httpd1 from app3, we
		// expect:
		// * two requests to get received by the proxy because connectivityTest
		// connects via http / http6.
		// * two requests to get forwarded by the proxy because policy allows
		// connectivity via http / http6.
		// * two corresponding responses forwarded / received to the aforementioned
		// requests due to policy allowing connectivity via http / http6.
		checkProxyStatistics(app3EndpointID, 2, 2, 0, 2, 2)

		connectivityTest(httpRequestsPrivate, helpers.App3, helpers.Httpd1, false)

		// Since policy does not allow connectivity on /private to httpd1 from app3, we expect:
		// * two requests denied due to connectivity not being allowed via http / http6
		// * the count for requests forwarded, and responses forwarded / received to be the same
		// as from the prior test since the requests were denied, and thus no new requests
		// were forwarded, and no new responses forwarded nor received.
		checkProxyStatistics(app3EndpointID, 2, 4, 2, 2, 2)

		connectivityTest(httpRequestsPublic, helpers.App3, helpers.Httpd2, true)

		// Since policy allows connectivity on L3 from app3 to httpd2, and such
		// packets are not forwarded to the proxy, we expect no changes in proxy
		// stats.
		checkProxyStatistics(app3EndpointID, 2, 4, 2, 2, 2)

		connectivityTest(httpRequestsPrivate, helpers.App3, helpers.Httpd2, true)

		// Since policy allows connectivity on L3 from app3 to httpd2, and such
		// packets are not forwarded to the proxy, we expect no changes in proxy
		// stats.
		checkProxyStatistics(app3EndpointID, 2, 4, 2, 2, 2)
	})

	Context("CIDR L3 Policy", func() {
		var (
			httpd1DockerNetworking        map[string]string
			ipv4Prefix, ipv6Prefix        string
			ipv4Address, ipv4PrefixExcept string
			worldIP                       string
		)

		const (
			ipv4OtherHost = "192.168.254.111"
			ipv4OtherNet  = "99.11.0.0/16"
			httpd2Label   = "id.httpd2"
			httpd1Label   = "id.httpd1"
			app3Label     = "id.app3"
			worldPrefix   = "192.168.2.0/24"
		)

		// Delete the pseudo-host IPs that we added to localhost after test
		// finishes. Don't care about success; this is best-effort.
		cleanup := func() {
			_ = vm.ContainerRm(helpers.WorldHttpd1)
			_ = vm.NetworkDelete(helpers.WorldDockerNetwork)
			_ = vm.RemoveIPFromLoopbackDevice(fmt.Sprintf("%s/32", helpers.FakeIPv4WorldAddress))
			_ = vm.RemoveIPFromLoopbackDevice(fmt.Sprintf("%s/128", helpers.FakeIPv6WorldAddress))
		}

		BeforeAll(func() {
			var err error

			httpd1DockerNetworking, err = vm.ContainerInspectNet(helpers.Httpd1)
			Expect(err).Should(BeNil(), fmt.Sprintf(
				"could not get container %s Docker networking", helpers.Httpd1))

			ipv6Prefix = fmt.Sprintf("%s/112", httpd1DockerNetworking["IPv6Gateway"])
			ipv4Address = httpd1DockerNetworking[helpers.IPv4]

			// Get prefix of node-local endpoints.
			By("Getting IPv4 and IPv6 prefixes of node-local endpoints")
			getIpv4Prefix := vm.Exec(fmt.Sprintf(`expr %s : '\([0-9]*\.[0-9]*\.\)'`, ipv4Address)).SingleOut()
			ipv4Prefix = fmt.Sprintf("%s0.0/16", getIpv4Prefix)
			getIpv4PrefixExcept := vm.Exec(fmt.Sprintf(`expr %s : '\([0-9]*\.[0-9]*\.\)'`, ipv4Address)).SingleOut()
			ipv4PrefixExcept = fmt.Sprintf(`%s0.0/18`, getIpv4PrefixExcept)

			By("Adding Pseudo-Host IPs to localhost")
			cleanup()
			vm.AddIPToLoopbackDevice(fmt.Sprintf("%s/32", helpers.FakeIPv4WorldAddress)).ExpectSuccess("Unable to add %s to pseudo-host IP to localhost", helpers.FakeIPv4WorldAddress)
			vm.AddIPToLoopbackDevice(fmt.Sprintf("%s/128", helpers.FakeIPv6WorldAddress)).ExpectSuccess("Unable to add %s to pseudo-host IP to localhost", helpers.FakeIPv6WorldAddress)

			netOptions := "-o com.docker.network.bridge.enable_ip_masquerade=false"
			res := vm.NetworkCreateWithOptions(helpers.WorldDockerNetwork, worldPrefix, false, netOptions)
			res.ExpectSuccess("Docker network for world containers could not be created")
			res = vm.NetworkGet(helpers.WorldDockerNetwork)
			res.ExpectSuccess("Docker network for world containers is unavailable")

			vm.ContainerCreate(helpers.WorldHttpd1, constants.HttpdImage, helpers.WorldDockerNetwork, fmt.Sprintf("-l id.%s", helpers.WorldHttpd1))
			res = vm.ContainerInspect(helpers.WorldHttpd1)
			res.ExpectSuccess("World container is not ready")

			worldNet, err := vm.ContainerInspectOtherNet(helpers.WorldHttpd1, helpers.WorldDockerNetwork)
			Expect(err).Should(BeNil(), fmt.Sprintf(
				"could not get container %s Docker networking", helpers.WorldHttpd1))
			worldIP = worldNet[helpers.IPv4]
		})

		AfterAll(func() {
			cleanup()
		})

		BeforeEach(func() {
			logger.WithFields(logrus.Fields{
				"IPv4_host":       helpers.FakeIPv4WorldAddress,
				"IPv4_other_host": ipv4OtherHost,
				"IPv4_other_net":  ipv4OtherNet,
				"IPv6_host":       helpers.FakeIPv6WorldAddress}).
				Info("VM IP address configuration")

			// If the pseudo host IPs have not been removed since the last run but
			// Cilium was restarted, the IPs may have been picked up as valid host
			// IPs. Remove them from the list so they are not regarded as localhost
			// entries.
			// Don't care about success or failure as the BPF endpoint may not even be
			// present; this is best-effort.
			_ = vm.ExecCilium(fmt.Sprintf("bpf endpoint delete %s", helpers.FakeIPv4WorldAddress))
			_ = vm.ExecCilium(fmt.Sprintf("bpf endpoint delete %s", helpers.FakeIPv6WorldAddress))

			By("IPV6 Prefix: %q", ipv6Prefix)
			By("IPV4 Address Endpoint: %q", ipv4Address)
			By("IPV4 Prefix: %q", ipv4Prefix)
			By("IPV4 Prefix Except: %q", ipv4PrefixExcept)

			By("Setting PolicyEnforcement to always enforce (default-deny)")
			ExpectPolicyEnforcementUpdated(vm, helpers.PolicyEnforcementAlways)
		})

		It("validates toCIDR", func() {
			By("Pinging host IPv4 from httpd2 (should NOT work due to default-deny PolicyEnforcement mode)")

			res := vm.ContainerExec(helpers.Httpd2, helpers.Ping(helpers.FakeIPv4WorldAddress))
			res.ExpectFail("Unexpected success pinging host (%s) from %s", helpers.FakeIPv4WorldAddress, helpers.Httpd2)

			By("Importing L3 CIDR Policy for IPv4 Egress Allowing Egress to %q, %q from %q", ipv4OtherHost, ipv4OtherHost, httpd2Label)
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
			_, err := vm.PolicyRenderAndImport(script)
			Expect(err).To(BeNil(), "Unable to import policy: %s", err)

			res = vm.ContainerExec(helpers.Httpd2, helpers.Ping(helpers.FakeIPv4WorldAddress))
			res.ExpectSuccess("Unexpected failure pinging host (%s) from %s", helpers.FakeIPv4WorldAddress, helpers.Httpd2)
			vm.PolicyDelAll().ExpectSuccess("Unable to delete all policies")

			By("Pinging host IPv6 from httpd2 (should NOT work because we did not specify IPv6 CIDR of host as part of previously imported policy)")
			res = vm.ContainerExec(helpers.Httpd2, helpers.Ping6(helpers.FakeIPv6WorldAddress))
			res.ExpectFail("Unexpected success pinging host (%s) from %s", helpers.FakeIPv6WorldAddress, helpers.Httpd2)

			By("Importing L3 CIDR Policy for IPv6 Egress")
			script = fmt.Sprintf(`
		[{
			"endpointSelector": {"matchLabels":{"%s":""}},
			"egress": [{
				"toCIDR": [
					"%s"
				]
			}]
		}]`, httpd2Label, helpers.FakeIPv6WorldAddress)
			_, err = vm.PolicyRenderAndImport(script)
			Expect(err).To(BeNil(), "Unable to import policy: %s", err)

			By("Pinging host IPv6 from httpd2 (should work because policy allows IPv6 CIDR %q)", helpers.FakeIPv6WorldAddress)
			res = vm.ContainerExec(helpers.Httpd2, helpers.Ping6(helpers.FakeIPv6WorldAddress))
			res.ExpectSuccess("Unexpected failure pinging host (%s) from %s", helpers.FakeIPv6WorldAddress, helpers.Httpd2)
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
			res.ExpectSuccess("Unexpected failure pinging %s (%s) from %s", helpers.Httpd1, httpd1DockerNetworking[helpers.IPv4], helpers.Httpd2)
			By("Pinging httpd1 IPv6 from httpd2 (should work because we allowed traffic to httpd1 labels from httpd2 labels)")
			res = vm.ContainerExec(helpers.Httpd2, helpers.Ping6(httpd1DockerNetworking[helpers.IPv6]))
			res.ExpectSuccess("Unexpected failure pinging %s (%s) from %s", helpers.Httpd1, httpd1DockerNetworking[helpers.IPv6], helpers.Httpd2)
			By("Pinging httpd1 IPv4 from app3 (should NOT work because app3 hasn't been whitelisted to communicate with httpd1)")
			res = vm.ContainerExec(helpers.App3, helpers.Ping(helpers.Httpd1))
			res.ExpectFail("Unexpected success pinging %s IPv4 from %s", helpers.Httpd1, helpers.App3)
			By("Pinging httpd1 IPv6 from app3 (should NOT work because app3 hasn't been whitelisted to communicate with httpd1)")
			res = vm.ContainerExec(helpers.App3, helpers.Ping6(helpers.Httpd1))
			res.ExpectFail("Unexpected success pinging %s IPv6 from %s", helpers.Httpd1, helpers.App3)
			vm.PolicyDelAll().ExpectSuccess("Unable to delete all policies")
		})

		It("validates fromCIDR", func() {
			// Checking combined policy allowing traffic from IPv4 and IPv6 CIDR ranges.
			By("Importing Policy Allowing Ingress From %q --> %q And From CIDRs %q, %q, %q", helpers.Httpd2, helpers.Httpd1, ipv4Prefix, ipv6Prefix, worldPrefix)
			policy := fmt.Sprintf(`
		[{
			"endpointSelector": {"matchLabels":{"%[1]s":""}},
			"ingress": [{
				"fromEndpoints":  [
					{"matchLabels":{"%[2]s":""}}
				]
			}, {
				"fromCIDR": [
					"%s",
					"%s",
					"%s"
				]
			}]
		},
		{
			"endpointSelector": {"matchLabels":{"%[2]s":""}},
			"egress": [{
				"toEndpoints":  [
					{"matchLabels":{"%[1]s":""}}
				]
			}]
		}]`, httpd1Label, httpd2Label, ipv4Prefix, ipv6Prefix, worldPrefix)

			_, err := vm.PolicyRenderAndImport(policy)
			Expect(err).To(BeNil(), "Unable to import policy: %s", err)

			// Checks from a Cilium endpoint
			By("Pinging httpd1 IPV4 from httpd2 (should work because we allowed traffic to httpd1 labels from httpd2 labels)")
			res := vm.ContainerExec(helpers.Httpd2, helpers.Ping(httpd1DockerNetworking[helpers.IPv4]))
			res.ExpectSuccess("Unexpected failure pinging %s (%s) from %s", helpers.Httpd1, httpd1DockerNetworking[helpers.IPv4], helpers.Httpd2)

			By("Pinging httpd1 IPv6 from httpd2 (should work because we allowed traffic to httpd1 labels from httpd2 labels)")
			res = vm.ContainerExec(helpers.Httpd2, helpers.Ping6(httpd1DockerNetworking[helpers.IPv6]))
			res.ExpectSuccess("Unexpected failure pinging %s (%s) from %s", helpers.Httpd1, httpd1DockerNetworking[helpers.IPv6], helpers.Httpd2)

			By("Pinging httpd1 IPv4 %q from app3 (shouldn't work because CIDR policies don't apply to endpoint-endpoint communication)", ipv4Prefix)
			res = vm.ContainerExec(helpers.App3, helpers.Ping(helpers.Httpd1))
			res.ExpectFail("Unexpected success pinging %s IPv4 from %s", helpers.Httpd1, helpers.App3)

			By("Pinging httpd1 IPv6 %q from app3 (shouldn't work because CIDR policies don't apply to endpoint-endpoint communication)", ipv6Prefix)
			res = vm.ContainerExec(helpers.App3, helpers.Ping6(helpers.Httpd1))
			res.ExpectFail("Unexpected success pinging %s IPv6 from %s", helpers.Httpd1, helpers.App3)

			// Ping from a source outside Cilium control
			By(fmt.Sprintf("Pinging httpd1 IPV4 from world container (should work because we allowed traffic to httpd1 labels from prefix %s)", worldPrefix))
			res = vm.ContainerExec(helpers.WorldHttpd1, helpers.Ping(httpd1DockerNetworking[helpers.IPv4]))
			res.ExpectSuccess("Unexpected failure pinging %s (%s) from %s", helpers.Httpd1, httpd1DockerNetworking[helpers.IPv4], helpers.WorldHttpd1)

			vm.PolicyDelAll().ExpectSuccess("Unable to delete all policies")

			// Make sure that combined label-based and CIDR-based policy works.
			By("Importing Policy Allowing Ingress From %s --> %s And From CIDRs %s", helpers.Httpd2, helpers.Httpd1, ipv4OtherNet)
			policy = fmt.Sprintf(`
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
			_, err = vm.PolicyRenderAndImport(policy)
			Expect(err).To(BeNil(), "Unable to import policy: %s", err)

			By("Pinging httpd1 IPv4 from app3 (should NOT work because we only allow traffic from %q to %q)", httpd2Label, httpd1Label)
			res = vm.ContainerExec(helpers.App3, helpers.Ping(helpers.Httpd1))
			res.ExpectFail("Unexpected success pinging %s IPv4 from %s", helpers.Httpd1, helpers.App3)

			By("Pinging httpd1 IPv6 from app3 (should NOT work because we only allow traffic from %q to %q)", httpd2Label, httpd1Label)
			res = vm.ContainerExec(helpers.App3, helpers.Ping6(helpers.Httpd1))
			res.ExpectFail("Unexpected success pinging %s IPv6 from %s", helpers.Httpd1, helpers.App3)

			vm.PolicyDelAll().ExpectSuccess("Unable to delete all policies")

			By("Testing CIDR Exceptions in Cilium Policy")
			By("Importing Policy Allowing Ingress From %q --> %q And From CIDRs %q Except %q", helpers.Httpd2, helpers.Httpd1, worldPrefix, worldIP)
			policy = fmt.Sprintf(`
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
		}]`, httpd1Label, httpd2Label, worldPrefix, fmt.Sprintf("%s/32", worldIP))
			_, err = vm.PolicyRenderAndImport(policy)
			Expect(err).To(BeNil(), "Unable to import policy: %s", err)

			By(fmt.Sprintf("Pinging httpd1 IPV4 from world container (should not work because the IP %s falls within the CIDR exception range)", worldIP))
			res = vm.ContainerExec(helpers.WorldHttpd1, helpers.Ping(httpd1DockerNetworking[helpers.IPv4]))
			res.ExpectFail("Unexpected success pinging %s IPv4 from %s", httpd1DockerNetworking[helpers.IPv4], helpers.WorldHttpd1)
		})
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
			By("Testing method %q", method)
			TestMethodPolicy(method)
		}
	})

	It("Tests Egress To World", func() {
		googleDNS := "8.8.8.8"
		googleHTTP := "google.com"
		numberOfTries := 5
		maxNumberOffFailures := 1

		checkEgressToWorld := func() {

			res := vm.ContainerExec(helpers.App1, helpers.Ping(helpers.App2))
			ExpectWithOffset(2, res).ShouldNot(helpers.CMDSuccess(),
				"unexpectedly able to ping %q", helpers.App2)

			By("Testing egress access to the world from %s", helpers.App1)
			pingFailures := 0
			curlFailures := 0

			for i := 0; i < numberOfTries; i++ {
				res := vm.ContainerExec(helpers.App1, helpers.Ping(googleDNS))
				if !res.WasSuccessful() {
					pingFailures++
				}
				res = vm.ContainerExec(helpers.App1, helpers.CurlFail("-4 http://%s", googleHTTP))
				if !res.WasSuccessful() {
					curlFailures++
				}
				// If no failures, let's skip the next ones.
				if (curlFailures + pingFailures) == 0 {
					break
				}
			}

			ExpectWithOffset(2, pingFailures).To(BeNumerically("<=", maxNumberOffFailures),
				"%d of %d  pings to %q failed", pingFailures, maxNumberOffFailures, googleDNS)

			ExpectWithOffset(2, curlFailures).To(BeNumerically("<=", maxNumberOffFailures),
				"%d of %d  HTTP request to %q failed",
				pingFailures, maxNumberOffFailures, googleHTTP)
		}

		setupPolicyAndTestEgressToWorld := func(policy string) {
			_, err := vm.PolicyRenderAndImport(policy)
			ExpectWithOffset(1, err).To(BeNil(), "Unable to import policy: %s\n%s", err, policy)

			ExpectWithOffset(1, vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")

			checkEgressToWorld()
		}

		// Set policy enforcement to default deny so that we can do negative tests
		// before importing policy
		ExpectPolicyEnforcementUpdated(vm, helpers.PolicyEnforcementAlways)

		failedPing := vm.ContainerExec(helpers.App1, helpers.Ping(googleDNS))
		failedPing.ExpectFail("unexpectedly able to ping %s", googleDNS)

		By("testing basic egress to world")
		app1Label := fmt.Sprintf("id.%s", helpers.App1)
		policy := fmt.Sprintf(`
		[{
			"endpointSelector": {"matchLabels":{"%s":""}},
			"egress": [{
				"toEntities": [
					"%s"
				]
			}]
		}]`, app1Label, api.EntityWorld)
		setupPolicyAndTestEgressToWorld(policy)

		vm.PolicyDelAll().ExpectSuccess("Unable to delete all policies")

		By("testing egress to world with all entity")
		policy = fmt.Sprintf(`
		[{
			"endpointSelector": {"matchLabels":{"%s":""}},
			"egress": [{
				"toEntities": [
					"%s"
				]
			}]
		}]`, app1Label, api.EntityAll)
		setupPolicyAndTestEgressToWorld(policy)

		vm.PolicyDelAll().ExpectSuccess("Unable to delete all policies")

		By("testing basic egress to 0.0.0.0/0")
		policy = fmt.Sprintf(`
		[{
			"endpointSelector": {"matchLabels":{"%s":""}},
			"egress": [{
				"toCIDR": [
					"0.0.0.0/0"
				]
			}]
		}]`, app1Label)
		setupPolicyAndTestEgressToWorld(policy)

		vm.PolicyDelAll().ExpectSuccess("Unable to delete all policies")

		By("testing that in-cluster L7 doesn't affect egress L3")
		app2Label := fmt.Sprintf("id.%s", helpers.App2)
		policy = fmt.Sprintf(`
		[{
			"endpointSelector": {"matchLabels":{"%s":""}},
			"egress": [{
				"toEntities": [
					"%s"
				]
			}, {
				"toEndpoints": [{"matchLabels": {"%s": ""}}],
				"toPorts": [{
					"ports": [{"port": "80", "protocol": "tcp"}],
					"rules": {
						"HTTP": [{
						  "method": "GET",
						  "path": "/nowhere"
						}]
					}
				}]
			}]
		}]`, app1Label, api.EntityWorld, app2Label)

		setupPolicyAndTestEgressToWorld(policy)

		vm.PolicyDelAll().ExpectSuccess("Unable to delete all policies")
	})

	It("Test egress with L7 policy to outside cluster", func() {
		target := "http://cilium.io"

		res := vm.ContainerExec(helpers.App1, helpers.CurlFail(target))
		res.ExpectSuccess("Cannot connect without policy")

		policy := `
		[
		  {
			"endpointSelector": {
			  "matchLabels": {"container:id.app1": ""}
			},
			"egress": [
				{
					"toPorts": [{
						"ports":[{"port": "53", "protocol": "ANY"}],
						"rules": {
							"dns": [
								{"matchPattern": "*"}
							]
						}
					}]
				},
				{
					"toFQDNs": [
					  {"matchPattern": "*.cilium.io"}
					]
				},
				{
					"toPorts": [{
						"ports": [
							{"port": "80", "protocol": "tcp"},
							{"port": "443", "protocol": "tcp"}
						],
						"rules": {
							"HTTP": [{
							  "method": "GET"
							}]
						}
					}]
				}
			]
		  }
		]`

		_, err := vm.PolicyRenderAndImport(policy)
		Expect(err).To(BeNil(), "Cannot import policy")

		res = vm.ContainerExec(helpers.App1, helpers.CurlFail(target))
		res.ExpectSuccess("Cannot connect with policy")

		res = vm.ContainerExec(helpers.App1, helpers.CurlWithHTTPCode(
			fmt.Sprintf(`%s -d ""`, target)))
		res.ExpectSuccess("403", "Post method is allowed when it should not work")
	})

	It("Tests EntityNone as a deny-all", func() {
		worldIP := "1.1.1.1"

		httpd1Label := "id.httpd1"
		http1IP, err := vm.ContainerInspectNet(helpers.Httpd1)
		Expect(err).Should(BeNil(), "Cannot get httpd1 server address")

		setupPolicy := func(policy string) {
			_, err := vm.PolicyRenderAndImport(policy)
			ExpectWithOffset(1, err).To(BeNil(), "Unable to import policy: %s\n%s", err, policy)

			ExpectWithOffset(1, vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")
		}

		// curlWithRetry retries the curl, to make sure that allowed curls don't
		// flake on bad connectivity
		curlWithRetry := func(name string, cmd string, optionalArgs ...interface{}) (res *helpers.CmdRes) {
			for try := 0; try < 5; try++ {
				res = vm.ContainerExec(name, helpers.CurlFail(cmd, optionalArgs...))
				if res.WasSuccessful() {
					return res
				}
			}
			return res
		}

		By("setting policy enforcement to default so that EntityNone is the source of deny-all")
		ExpectPolicyEnforcementUpdated(vm, helpers.PolicyEnforcementDefault)
		app1Label := fmt.Sprintf("id.%s", helpers.App1)
		policy := fmt.Sprintf(`
		[{
			"endpointSelector": {"matchLabels":{"%s":""}},
			"egress": [{
				"toEntities": [
					"%s"
				]
			}]
		}]`, app1Label, api.EntityNone)
		setupPolicy(policy)

		app2Label := fmt.Sprintf("id.%s", helpers.App2)
		policy = fmt.Sprintf(`
		[{
			"endpointSelector": {"matchLabels":{"%s":""}},
			"egress": [{
				"toEntities": [
					"%s"
				]
			}]
		}]`, app2Label, api.EntityNone)
		setupPolicy(policy)

		By("testing that EntityNone is denying all egress for app1 and app2")
		vm.ContainerExec(helpers.App1, helpers.CurlFail("http://%s/public", http1IP[helpers.IPv4])).ExpectFail("%q can make http request to pod", helpers.App1)
		vm.ContainerExec(helpers.App1, helpers.CurlFail("-4 http://%s", worldIP)).ExpectFail("%q can make http request to %s", helpers.App1, worldIP)
		vm.ContainerExec(helpers.App2, helpers.CurlFail("http://%s/public", http1IP[helpers.IPv4])).ExpectFail("%q can make http request to pod", helpers.App1)
		vm.ContainerExec(helpers.App2, helpers.CurlFail("-4 http://%s", worldIP)).ExpectFail("%q can make http request to %s", helpers.App1, worldIP)

		By("testing basic egress between endpoints (app1->app2)")
		policy = fmt.Sprintf(`
		[{
			"endpointSelector": {"matchLabels":{"%s":""}},
			"egress": [{
				"toEndpoints": [{"matchLabels": {"%s": ""}}]
			}]
		}]`, app1Label, httpd1Label)
		setupPolicy(policy)
		curlWithRetry(helpers.App1, "http://%s/public", http1IP[helpers.IPv4]).ExpectSuccess("%q cannot make http request to pod", helpers.App1)
		vm.ContainerExec(helpers.App1, helpers.CurlFail("-4 http://%s", worldIP)).ExpectFail("%q can make http request to %s", helpers.App1, worldIP)

		By("testing basic egress to 1.1.1.1/32")
		policy = fmt.Sprintf(`
		[{
			"endpointSelector": {"matchLabels":{"%s":""}},
			"egress": [{
				"toCIDR": [
					"1.1.1.1/32"
				]
			}]
		}]`, app1Label)
		setupPolicy(policy)
		curlWithRetry(helpers.App1, "http://%s/public", http1IP[helpers.IPv4]).ExpectSuccess("%q cannot make http request to pod", helpers.App1)
		curlWithRetry(helpers.App1, "-4 http://%s", worldIP).ExpectSuccess("%q cannot make http request to pod", helpers.App1)

		By("testing egress toEntity: world in combination with previous rules (app1)")
		policy = fmt.Sprintf(`
		[{
			"endpointSelector": {"matchLabels":{"%s":""}},
			"egress": [{
				"toEntities": [
					"%s"
				]
			}]
		}]`, app1Label, api.EntityAll)
		setupPolicy(policy)
		curlWithRetry(helpers.App1, "http://%s/public", http1IP[helpers.IPv4]).ExpectSuccess("%q cannot make http request to pod", helpers.App1)
		curlWithRetry(helpers.App1, "-4 http://%s", worldIP).ExpectSuccess("%q cannot make http request to pod", helpers.App1)

		By("testing egress toEntity: world alone with EntityNone")
		policy = fmt.Sprintf(`
		[{
			"endpointSelector": {"matchLabels":{"%s":""}},
			"egress": [{
				"toEntities": [
					"%s"
				]
			}]
		}]`, app2Label, api.EntityAll)
		setupPolicy(policy)
		curlWithRetry(helpers.App2, "http://%s/public", http1IP[helpers.IPv4]).ExpectSuccess("%q cannot make http request to pod", helpers.App2)
		curlWithRetry(helpers.App2, "-4 http://%s", worldIP).ExpectSuccess("%q cannot make http request to pod", helpers.App2)

		vm.PolicyDelAll().ExpectSuccess("Unable to delete all policies")
	})

	Context("TestsEgressToHost", func() {
		hostDockerContainer := "hostDockerContainer"
		hostIP := "10.0.2.15"
		otherHostIP := ""

		BeforeAll(func() {
			By("Starting httpd server using host networking")
			res := vm.ContainerCreate(hostDockerContainer, constants.HttpdImage, helpers.HostDockerNetwork, "-l id.hostDockerContainer")
			res.ExpectSuccess("unable to start Docker container with host networking")

			By("Detecting host IP in world CIDR")

			// docker network inspect bridge | jq -r '.[0]."IPAM"."Config"[0]."Gateway"'
			res = vm.NetworkGet("bridge")
			res.ExpectSuccess("No docker bridge available for testing egress CIDR within host")
			filter := `{ [0].IPAM.Config[0].Gateway }`
			obj, err := res.FindResults(filter)
			Expect(err).NotTo(HaveOccurred(), "Error occurred while finding docker bridge IP")
			Expect(obj).To(HaveLen(1), "Unexpectedly found more than one IPAM config element for docker bridge")
			otherHostIP = obj[0].Interface().(string)
			Expect(otherHostIP).To(Equal(helpers.DockerBridgeIP), "Please adjust value of DockerBridgeIP")
			By("Using %q for world CIDR IP", otherHostIP)
		})

		AfterAll(func() {
			vm.ContainerRm(hostDockerContainer)
		})

		BeforeEach(func() {
			By("Pinging %q from %q before importing policy (should work)", hostIP, helpers.App1)
			failedPing := vm.ContainerExec(helpers.App1, helpers.Ping(hostIP))
			failedPing.ExpectSuccess("unable able to ping %q", hostIP)

			By("Pinging %q from %q before importing policy (should work)", otherHostIP, helpers.App1)
			failedPing = vm.ContainerExec(helpers.App1, helpers.Ping(otherHostIP))
			failedPing.ExpectSuccess("unable able to ping %q", otherHostIP)

			// Flush global conntrack table to be safe because egress conntrack cleanup
			// is still to be completed (GH-3393).
			By("Flushing global connection tracking table before importing policy")
			vm.FlushGlobalConntrackTable().ExpectSuccess("Unable to flush global conntrack table")
		})

		AfterEach(func() {
			vm.PolicyDelAll().ExpectSuccess("Failed to clear policy after egress test")
		})

		It("Tests Egress To Host", func() {
			By("Importing policy which allows egress to %q entity from %q", api.EntityHost, helpers.App1)
			policy := fmt.Sprintf(`
			[{
				"endpointSelector": {"matchLabels":{"id.%s":""}},
				"egress": [{
					"toEntities": [
						"%s"
					]
				}]
			}]`, helpers.App1, api.EntityHost)

			_, err := vm.PolicyRenderAndImport(policy)
			Expect(err).To(BeNil(), "Unable to import policy: %s", err)

			By("Pinging %s from %s (should work)", api.EntityHost, helpers.App1)
			successPing := vm.ContainerExec(helpers.App1, helpers.Ping(hostIP))
			successPing.ExpectSuccess("not able to ping %s", hostIP)

			// Docker container running with host networking is accessible via
			// the host's IP address. See https://docs.docker.com/network/host/.
			By("Accessing /public using Docker container using host networking from %q (should work)", helpers.App1)
			successCurl := vm.ContainerExec(helpers.App1, helpers.CurlFail("http://%s/public", hostIP))
			successCurl.ExpectSuccess("Expected to be able to access /public in host Docker container")

			By("Pinging %s from %s (shouldn't work)", helpers.App2, helpers.App1)
			failPing := vm.ContainerExec(helpers.App1, helpers.Ping(helpers.App2))
			failPing.ExpectFail("not able to ping %s", helpers.App2)

			httpd2, err := vm.ContainerInspectNet(helpers.Httpd2)
			Expect(err).Should(BeNil(), "Unable to get networking information for container %q", helpers.Httpd2)

			By("Accessing /public in %q from %q (shouldn't work)", helpers.App2, helpers.App1)
			failCurl := vm.ContainerExec(helpers.App1, helpers.CurlFail("http://%s/public", httpd2[helpers.IPv4]))
			failCurl.ExpectFail("unexpectedly able to access %s when access should only be allowed to host", helpers.Httpd2)
		})

		// In this test we rely on the hostDockerContainer serving on a
		// secondary IP, which is otherwise not bound to an identity to
		// begin with; it would otherwise be part of the cluster. When
		// we define CIDR policy on it, Cilium allocates an identity
		// for it.
		testCIDRL4Policy := func(policy, dstIP, proto string) {
			_, err := vm.PolicyRenderAndImport(policy)
			ExpectWithOffset(1, err).To(BeNil(), "Unable to import policy")

			By("Pinging %q from %q (should not work)", api.EntityHost, helpers.App1)
			res := vm.ContainerExec(helpers.App1, helpers.Ping(dstIP))
			ExpectWithOffset(1, res).ShouldNot(helpers.CMDSuccess(),
				"expected ping to %q to fail", dstIP)

			// Docker container running with host networking is accessible via
			// the docker bridge's IP address. See https://docs.docker.com/network/host/.
			By("Accessing index.html using Docker container using host networking from %q (should work)", helpers.App1)
			res = vm.ContainerExec(helpers.App1, helpers.CurlFail("%s://%s/index.html", proto, dstIP))
			ExpectWithOffset(1, res).To(helpers.CMDSuccess(),
				"Expected to be able to access /public in host Docker container")

			By("Accessing %q on wrong port from %q should fail", dstIP, helpers.App1)
			res = vm.ContainerExec(helpers.App1, helpers.CurlFail("http://%s:8080/public", dstIP))
			ExpectWithOffset(1, res).ShouldNot(helpers.CMDSuccess(),
				"unexpectedly able to access %q when access should only be allowed to CIDR", dstIP)

			By("Accessing port 80 on wrong destination from %q should fail", helpers.App1)
			res = vm.ContainerExec(helpers.App1, helpers.CurlFail("%s://%s/public", proto, hostIP))
			ExpectWithOffset(1, res).ShouldNot(helpers.CMDSuccess(),
				"unexpectedly able to access %q when access should only be allowed to CIDR", hostIP)

			By("Pinging %q from %q (shouldn't work)", helpers.App2, helpers.App1)
			res = vm.ContainerExec(helpers.App1, helpers.Ping(helpers.App2))
			ExpectWithOffset(1, res).ShouldNot(helpers.CMDSuccess(),
				"expected ping to %q to fail", helpers.App2)

			httpd2, err := vm.ContainerInspectNet(helpers.Httpd2)
			ExpectWithOffset(1, err).Should(BeNil(),
				"Unable to get networking information for container %q", helpers.Httpd2)

			By("Accessing /index.html in %q from %q (shouldn't work)", helpers.App2, helpers.App1)
			res = vm.ContainerExec(helpers.App1, helpers.CurlFail("%s://%s/index.html", proto, httpd2[helpers.IPv4]))
			ExpectWithOffset(1, res).ShouldNot(helpers.CMDSuccess(),
				"unexpectedly able to access %q when access should only be allowed to CIDR", helpers.Httpd2)
		}

		It("Tests egress with CIDR+L4 policy", func() {
			By("Importing policy which allows egress to %q from %q", otherHostIP, helpers.App1)
			policy := fmt.Sprintf(`
			[{
				"endpointSelector": {"matchLabels":{"id.%s":""}},
				"egress": [{
					"toCIDR": [
						"%s"
					],
					"toPorts": [
						{"ports":[{"port": "80", "protocol": "TCP"}]}
					]
				}]
			}]`, helpers.App1, otherHostIP)

			testCIDRL4Policy(policy, otherHostIP, "http")
		})

		It("Tests egress with CIDR+L4 policy to external https service", func() {
			cloudFlare := "1.1.1.1"
			proto := "https"
			retries := 5

			By("Checking connectivity to %q without policy", cloudFlare)
			res := vm.ContainerExec(helpers.App1, helpers.Ping(cloudFlare))
			res.ExpectSuccess("Expected to be able to connect to cloudflare (%q); external connectivity not available", cloudFlare)

			By("Importing policy which allows egress to %q from %q", otherHostIP, helpers.App1)
			policy := fmt.Sprintf(`
			[{
				"endpointSelector": {"matchLabels":{"id.%s":""}},
				"egress": [{
					"toCIDR": [
						"%s/30"
					],
					"toPorts": [
						{"ports":[{"port": "443", "protocol": "TCP"}]}
					]
				}]
			}]`, helpers.App1, cloudFlare)

			_, err := vm.PolicyRenderAndImport(policy)
			Expect(err).To(BeNil(), "Unable to import policy")

			httpd2, err := vm.ContainerInspectNet(helpers.Httpd2)
			Expect(err).Should(BeNil(),
				"Unable to get networking information for container %q", helpers.Httpd2)

			By("Accessing /index.html in %q from %q (shouldn't work)", helpers.App2, helpers.App1)
			res = vm.ContainerExec(helpers.App1, helpers.CurlFail("%s://%s/index.html", proto, httpd2[helpers.IPv4]))
			res.ExpectFail("unexpectedly able to access %q when access should only be allowed to CIDR", helpers.Httpd2)

			By("Testing egress access to the world")
			curlFailures := 0
			for i := 0; i < retries; i++ {
				By("Accessing index.html using Docker container using host networking from %q (should work)", helpers.App1)
				res = vm.ContainerExec(helpers.App1, helpers.CurlFail("%s://%s/index.html", proto, cloudFlare))
				if !res.WasSuccessful() {
					curlFailures++
				}
			}
			Expect(curlFailures).To(BeNumerically("<=", 1), "Curl to %q have failed more than once", cloudFlare)

			By("Pinging %q from %q (should not work)", api.EntityHost, helpers.App1)
			res = vm.ContainerExec(helpers.App1, helpers.Ping(cloudFlare))
			res.ExpectFail("expected ping to %q to fail", cloudFlare)

			By("Accessing %q on wrong port from %q should fail", cloudFlare, helpers.App1)
			res = vm.ContainerExec(helpers.App1, helpers.CurlFail("http://%s:8080/public", cloudFlare))
			res.ExpectFail("unexpectedly able to access %q when access should only be allowed to CIDR", cloudFlare)

			By("Accessing port 80 on wrong destination from %q should fail", helpers.App1)
			res = vm.ContainerExec(helpers.App1, helpers.CurlFail("%s://%s/public", proto, hostIP))
			res.ExpectFail("unexpectedly able to access %q when access should only be allowed to CIDR", hostIP)

			By("Pinging %q from %q (shouldn't work)", helpers.App2, helpers.App1)
			res = vm.ContainerExec(helpers.App1, helpers.Ping(helpers.App2))
			res.ExpectFail("expected ping to %q to fail", helpers.App2)
		})

		It("Tests egress with CIDR+L7 policy", func() {
			By("Importing policy which allows egress to %q from %q", otherHostIP, helpers.App1)
			policy := fmt.Sprintf(`
			[{
				"endpointSelector": {"matchLabels":{"id.%s":""}},
				"egress": [{
					"toCIDR": [
						"%s/32"
					],
					"toPorts": [{
						"ports":[{"port": "80", "protocol": "TCP"}],
						"rules": {
							"HTTP": [{
							  "method": "GET",
							  "path": "/index.html"
							}]
						}
					}]
				}]
			}]`, helpers.App1, otherHostIP)

			testCIDRL4Policy(policy, otherHostIP, "http")

			By("Accessing /private on %q from %q should fail", otherHostIP, helpers.App1)
			res := vm.ContainerExec(helpers.App1, helpers.CurlWithHTTPCode("http://%s/private", otherHostIP))
			res.ExpectContains("403", "unexpectedly able to access http://%q:80/private when access should only be allowed to /index.html", otherHostIP)
		})
	})
	Context("Init Policy Default Drop Test", func() {
		BeforeEach(func() {
			vm.ContainerRm(initContainer)
			ExpectPolicyEnforcementUpdated(vm, helpers.PolicyEnforcementAlways)
		})

		AfterEach(func() {
			vm.ContainerRm(initContainer).ExpectSuccess("Container initContainer cannot be deleted")
		})

		createEndpoint := func(cmdArgs ...string) (endpointID string, endpointIP *models.AddressPair) {
			res := vm.ContainerCreate(initContainer, constants.NetperfImage, helpers.CiliumDockerNetwork, "-l somelabel", cmdArgs...)
			res.ExpectSuccess("Failed to create container")

			endpoints, err := vm.GetAllEndpointsIds()
			Expect(err).Should(BeNil(), "Unable to get IDs of endpoints")
			var exists bool
			endpointID, exists = endpoints[initContainer]
			Expect(exists).To(BeTrue(), "Expected endpoint ID to exist for %s", initContainer)
			ingressEpModel := vm.EndpointGet(endpointID)
			Expect(ingressEpModel).NotTo(BeNil(), "nil model returned for endpoint %s", endpointID)

			endpointIP = ingressEpModel.Status.Networking.Addressing[0]
			return
		}

		It("tests ingress", func() {
			By("Starting hubble observe in background")
			ctx, cancel := context.WithCancel(context.Background())
			hubbleRes := vm.HubbleObserveFollow(ctx, "--type", "drop", "--type", "trace:to-endpoint", "--protocol", "ICMPv4")
			defer cancel()

			By("Creating an endpoint")
			endpointID, endpointIP := createEndpoint()

			// Normally, we start pinging fast enough that the endpoint still has identity "init" / 5,
			// and we continue pinging as the endpoint changes its identity for label "somelabel".
			// So these pings will be dropped by the policies for both identity 5 and the new identity
			// for label "somelabel".
			By("Testing ingress with ping from host to endpoint")
			res := vm.Exec(helpers.Ping(endpointIP.IPV4))
			res.ExpectFail("Unexpectedly able to ping endpoint with no ingress policy")

			By("Testing hubble observe output")
			err := hubbleRes.WaitUntilMatchFilterLine(
				`{.source.labels} -> {.destination.ID} {.destination.labels} {.IP.destination} : {.verdict} {.event_type.type}`,
				fmt.Sprintf(`["reserved:host"] -> %s ["container:somelabel"] %s : DROPPED 1`, endpointID, endpointIP.IPV4))
			Expect(err).To(BeNil(), "Default drop on ingress failed")
			hubbleRes.ExpectDoesNotContainFilterLine(
				`{.source.labels} -> {.destination.ID} {.destination.labels} {.IP.destination} : {.verdict} {.event_type.type}`,
				fmt.Sprintf(`["reserved:host"] -> %s ["container:somelabel"] %s : FORWARDED 4`, endpointID, endpointIP.IPV4),
				"Unexpected ingress traffic to endpoint")
		})

		It("tests egress", func() {
			hostIP := "10.0.2.15"

			By("Starting hubble observe in background")
			ctx, cancel := context.WithCancel(context.Background())
			hubbleRes := vm.HubbleObserveFollow(ctx, "--type", "drop", "--type", "trace:to-endpoint", "--protocol", "ICMPv4")
			defer cancel()

			By("Creating an endpoint")
			endpointID, _ := createEndpoint("ping", hostIP)

			By("Testing hubble observe output")
			err := hubbleRes.WaitUntilMatchFilterLine(
				`{.source.ID} {.source.labels} -> {.destination.labels} {.IP.destination} : {.verdict} {.event_type.type}`,
				fmt.Sprintf(`%s ["container:somelabel"] -> ["reserved:host"] %s : DROPPED 1`, endpointID, hostIP))
			Expect(err).To(BeNil(), "Default drop on egress failed")

			hubbleRes.ExpectDoesNotContainFilterLine(
				`{.source.labels} {.IP.source} -> {.destination.ID} : {.verdict} {.reply} {.event_type.type}`,
				fmt.Sprintf(`["reserved:host"] %s -> %s : FORWARDED true 4`, hostIP, endpointID),
				"Unexpected reply traffic to endpoint")
		})

		Context("With PolicyAuditMode", func() {
			BeforeEach(func() {
				vm.ExecCilium("config PolicyAuditMode=Enabled").ExpectSuccess("unable to change daemon configuration")
			})

			AfterAll(func() {
				vm.ExecCilium("config PolicyAuditMode=Disabled").ExpectSuccess("unable to change daemon configuration")
			})

			It("tests ingress", func() {
				By("Starting hubble observe in background")
				ctx, cancel := context.WithCancel(context.Background())
				hubbleRes := vm.HubbleObserveFollow(ctx, "--type", "policy-verdict", "--type", "trace:to-endpoint", "--protocol", "ICMPv4")
				defer cancel()

				By("Starting cilium monitor in background")
				monitorRes := vm.ExecInBackground(ctx, "cilium monitor --type policy-verdict")

				By("Creating an endpoint")
				endpointID, endpointIP := createEndpoint()

				By("Testing ingress with ping from host to endpoint")
				res := vm.Exec(helpers.Ping(endpointIP.IPV4))
				res.ExpectSuccess("Not able to ping endpoint with no ingress policy")

				// We might start pinging fast enough that the endpoint still has identity "init" / 5.
				// In PolicyAuditMode, this means that the ping will succeed. Therefore we don't
				// check for the source labels in the output (they can by either [reserved:init]
				// or [container:somelabel]), only the endpoint ID.
				By("Testing hubble observe output")
				// Checks for a ingress policy verdict event (type 5)
				err := hubbleRes.WaitUntilMatchFilterLine(
					`{.source.labels} -> {.IP.destination} : {.verdict} {.event_type.type}`,
					fmt.Sprintf(`["reserved:host"] -> %s : AUDIT 5`, endpointIP.IPV4))
				Expect(err).To(BeNil(), "Default policy verdict on ingress failed")
				// Checks for the subsequent trace:to-endpoint event (type 4)
				hubbleRes.ExpectContainsFilterLine(
					`{.source.labels} -> {.destination.ID} {.destination.labels} {.IP.destination} : {.verdict} {.event_type.type}`,
					fmt.Sprintf(`["reserved:host"] -> %s ["container:somelabel"] %s : FORWARDED 4`, endpointID, endpointIP.IPV4),
					"No ingress traffic to endpoint")

				By("Testing cilium monitor output")
				auditVerdict := fmt.Sprintf("local EP ID %s, remote ID host, proto 1, ingress, action audit", endpointID)
				monitorRes.WaitUntilMatch(auditVerdict)
				monitorRes.ExpectContains(auditVerdict, "No ingress policy log record")

				By("Testing cilium endpoint list output")
				res = vm.Exec("cilium endpoint list")
				res.ExpectMatchesRegexp(endpointID+"\\s*Disabled \\(Audit\\)\\s*Disabled \\(Audit\\)", "Endpoint is not in audit mode")
			})

			It("tests egress", func() {
				hostIP := "10.0.2.15"

				By("Starting hubble observe in background")
				ctx, cancel := context.WithCancel(context.Background())
				hubbleRes := vm.HubbleObserveFollow(ctx, "--type", "policy-verdict", "--type", "trace:to-endpoint", "--protocol", "ICMPv4")
				defer cancel()

				By("Starting cilium monitor in background")
				monitorRes := vm.ExecInBackground(ctx, "cilium monitor --type policy-verdict")

				By("Creating an endpoint")
				endpointID, _ := createEndpoint("ping", hostIP)

				// We start pinging fast enough that the endpoint still has identity "init" / 5.
				// In PolicyAuditMode, this means that the ping will succeed. Therefore we don't
				// check for the source labels in the output (they can by either [reserved:init]
				// or [container:somelabel]), only the endpoint ID.
				By("Testing hubble observe output")
				// Checks for the subsequent trace:to-endpoint event (type 4)
				err := hubbleRes.WaitUntilMatchFilterLine(
					`{.source.labels} {.IP.source} -> {.destination.ID} : {.verdict} {.reply} {.event_type.type}`,
					fmt.Sprintf(`["reserved:host"] %s -> %s : FORWARDED true 4`, hostIP, endpointID))
				Expect(err).To(BeNil(), "No ingress traffic to endpoint")
				// Checks for a ingress policy verdict event (type 5)
				hubbleRes.ExpectContainsFilterLine(
					`{.source.ID} -> {.destination.labels} {.IP.destination} : {.verdict} {.event_type.type}`,
					fmt.Sprintf(`%s -> ["reserved:host"] %s : AUDIT 5`, endpointID, hostIP),
					"Default policy verdict on egress failed")

				By("Testing cilium monitor output")
				auditVerdict := fmt.Sprintf("ID %s, remote ID host, proto 1, egress, action audit", endpointID)
				monitorRes.WaitUntilMatch(auditVerdict)
				monitorRes.ExpectContains(auditVerdict, "No egress policy log record")

				By("Testing cilium endpoint list output")
				res := vm.Exec("cilium endpoint list")
				res.ExpectMatchesRegexp(endpointID+"\\s*Disabled \\(Audit\\)\\s*Disabled \\(Audit\\)", "Endpoint is not in audit mode")
			})
		})
	})
	Context("Init Policy Test", func() {
		BeforeEach(func() {
			vm.ContainerRm(initContainer)
			ExpectPolicyEnforcementUpdated(vm, helpers.PolicyEnforcementAlways)

			_, err := vm.PolicyImportAndWait(vm.GetFullPath(policiesReservedInitJSON), helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Init policy import failed")
		})

		AfterEach(func() {
			vm.ContainerRm(initContainer).ExpectSuccess("Container initContainer cannot be deleted")
		})

		It("Init Ingress Policy Test", func() {
			By("Starting hubble observe in background")
			ctx, cancel := context.WithCancel(context.Background())
			hubbleRes := vm.HubbleObserveFollow(ctx, "--type", "drop", "--type", "trace", "--protocol", "ICMPv4")
			defer cancel()

			By("Creating an endpoint")
			res := vm.ContainerCreate(initContainer, constants.NetperfImage, helpers.CiliumDockerNetwork, "-l somelabel")
			res.ExpectSuccess("Failed to create container")

			endpoints, err := vm.GetAllEndpointsIds()
			Expect(err).Should(BeNil(), "Unable to get IDs of endpoints")
			endpointID, exists := endpoints[initContainer]
			Expect(exists).To(BeTrue(), "Expected endpoint ID to exist for %s", initContainer)
			ingressEpModel := vm.EndpointGet(endpointID)
			Expect(ingressEpModel).NotTo(BeNil(), "nil model returned for endpoint %s", endpointID)

			endpointIP := ingressEpModel.Status.Networking.Addressing[0]

			// Normally, we start pinging fast enough that the endpoint still has identity "init" / 5,
			// and we continue pinging as the endpoint changes its identity for label "somelabel".
			// So these pings will be allowed by the policies for both identity 5 and the new identity
			// for label "somelabel".
			By("Testing ingress with ping from host to endpoint")
			res = vm.Exec(helpers.Ping(endpointIP.IPV4))
			res.ExpectSuccess("Cannot ping endpoint with init policy")

			By("Testing hubble observe output")
			err = hubbleRes.WaitUntilMatchFilterLineTimeout(
				`{.source.labels} -> {.destination.ID} {.IP.destination} : {.verdict}`,
				fmt.Sprintf(`["reserved:host"] -> %s %s : FORWARDED`, endpointID, endpointIP.IPV4), 10*time.Second)
			Expect(err).To(BeNil(), "Allow on ingress failed")

			// Drop Reason 133 is "Policy denied"
			hubbleRes.ExpectDoesNotContainFilterLine(
				`{.source.labels} -> {.destination.ID} {.IP.destination} : {.verdict} {.drop_reason}`,
				fmt.Sprintf(`["reserved:host"] -> %s %s : DROPPED 133`, endpointID, endpointIP.IPV4),
				"Unexpected drop")
		})

		It("Init Egress Policy Test", func() {
			hostIP := "10.0.2.15"

			By("Starting hubble observe in background")
			ctx, cancel := context.WithCancel(context.Background())
			hubbleRes := vm.HubbleObserveFollow(ctx, "--type", "drop", "--type", "trace", "--protocol", "ICMPv4")
			defer cancel()

			By("Creating an endpoint")
			res := vm.ContainerCreate(initContainer, constants.NetperfImage, helpers.CiliumDockerNetwork, "-l somelabel", "ping", hostIP)
			res.ExpectSuccess("Failed to create container")

			endpoints, err := vm.GetAllEndpointsIds()
			Expect(err).To(BeNil(), "Unable to get IDs of endpoints")
			endpointID, exists := endpoints[initContainer]
			Expect(exists).To(BeTrue(), "Expected endpoint ID to exist for %s", initContainer)
			egressEpModel := vm.EndpointGet(endpointID)
			Expect(egressEpModel).NotTo(BeNil(), "nil model returned for endpoint %s", endpointID)

			By("Testing hubble observe output")
			err = hubbleRes.WaitUntilMatchFilterLineTimeout(
				`{.source.ID} {.source.labels} -> {.destination.labels} {.IP.destination} : {.verdict}`,
				fmt.Sprintf(`%s ["container:somelabel"] -> ["reserved:host"] %s : FORWARDED`, endpointID, hostIP),
				10*time.Second)
			Expect(err).To(BeNil(), "Allow on ingress failed")

			// Drop Reason 133 is "Policy denied"
			hubbleRes.ExpectDoesNotContainFilterLine(
				`{.source.ID} {.source.labels} -> {.destination.labels} {.IP.destination} : {.verdict} {.drop_reason}`,
				fmt.Sprintf(`%s ["container:somelabel"] -> ["reserved:host"] %s : DROPPED 133`, endpointID, hostIP),
				"Unexpected drop")
		})
	})

	Context("Tests for Already-Allocated Identities", func() {
		var (
			newContainerName = fmt.Sprintf("%s-already-allocated-id", helpers.Httpd1)
		)

		// Apply L3-L4 policy, which will select the already-running containers
		// that have been created outside of this Context.
		BeforeEach(func() {
			By("Importing policy which selects all endpoints with label id.httpd1 to allow ingress traffic on port 80")
			_, err := vm.PolicyImportAndWait(vm.GetFullPath("Policies-l4-policy.json"), helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "unable to apply L3-L4 policy")
		})

		AfterEach(func() {
			vm.ContainerRm(newContainerName)
		})

		It("Tests L4 policy is generated for endpoint with already-allocated identity", func() {
			// Create a new container which has labels which have already been
			// allocated an identity from the key-value store.
			By("Creating new container with label id.httpd1, which has already " +
				"been allocated an identity from the key-value store")
			vm.ContainerCreate(newContainerName, constants.HttpdImage, helpers.CiliumDockerNetwork, fmt.Sprintf("-l id.%s", helpers.Httpd1))

			By("Waiting for newly added endpoint to be ready")
			Expect(vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")

			// All endpoints should be able to connect to this container on port
			// 80, but should not be able to ping because ICMP does not use
			// port 80.

			By("Checking that datapath behavior matches policy which selects this new endpoint")
			for _, app := range []string{helpers.App1, helpers.App2} {
				connectivityTest(pingRequests, app, newContainerName, false)
				connectivityTest(httpRequests, app, newContainerName, true)
			}

		})
	})
})

var _ = Describe("RuntimePolicyImportTests", func() {
	var (
		vm            *helpers.SSHMeta
		testStartTime time.Time
	)

	BeforeAll(func() {
		vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)
		ExpectCiliumReady(vm)

		vm.SampleContainersActions(helpers.Create, helpers.CiliumDockerNetwork)

		Expect(vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")
	})

	BeforeEach(func() {
		ExpectPolicyEnforcementUpdated(vm, helpers.PolicyEnforcementDefault)
	})

	AfterEach(func() {
		_ = vm.PolicyDelAll()
	})

	JustBeforeEach(func() {
		testStartTime = time.Now()
	})

	JustAfterEach(func() {
		vm.ValidateNoErrorsInLogs(time.Since(testStartTime))
	})

	AfterFailed(func() {
		vm.ReportFailed("cilium policy get")
	})

	AfterAll(func() {
		vm.PolicyDelAll().ExpectSuccess("Unable to delete all policies")
		vm.SampleContainersActions(helpers.Delete, helpers.CiliumDockerNetwork)
	})

	It("Invalid Policies", func() {

		testInvalidPolicy := func(data string) {
			err := vm.RenderTemplateToFile(invalidJSON, data, 0777)
			Expect(err).Should(BeNil())

			path := vm.GetFilePath(invalidJSON)
			_, err = vm.PolicyImportAndWait(path, helpers.HelperTimeout)
			Expect(err).Should(HaveOccurred())
			defer os.Remove(invalidJSON)
		}
		By("Invalid Json")

		invalidJSON := `
		[{
			"endpointSelector": {
				"matchLabels":{"id.httpd1":""}
			},`
		testInvalidPolicy(invalidJSON)
	})

	Context("Policy command", func() {
		var (
			policy = `[{
			"endpointSelector": {"matchLabels":{"role":"frontend"}},
				"labels": ["key1"]
			},{
			"endpointSelector": {"matchLabels":{"role":"frontend"}},
				"labels": ["key2"]
			},{
			"endpointSelector": {"matchLabels":{"role":"frontend"}},
				"labels": ["key3"]
			}]`
		)

		BeforeEach(func() {
			err := vm.RenderTemplateToFile(policyJSON, policy, 0777)
			Expect(err).Should(BeNil())

			path := vm.GetFilePath(policyJSON)
			_, err = vm.PolicyImportAndWait(path, helpers.HelperTimeout)
			Expect(err).Should(BeNil())
		})

		AfterEach(func() {
			_ = vm.PolicyDelAll()
			_ = os.Remove(policyJSON)
		})

		It("Tests getting policy by labels", func() {
			for _, v := range []string{"key1", "key2", "key3"} {
				res := vm.PolicyGet(v)
				res.ExpectSuccess(fmt.Sprintf("cannot get key %q", v))
			}
		})

		It("Tests deleting policy key", func() {
			res := vm.PolicyDel("key2")
			res.ExpectSuccess("Unable to delete policy rule with label key2 despite rule having been imported with that label")

			res = vm.PolicyGet("key2")
			res.ExpectFail("Was able to retrieve policy rule with label key2 despite having deleted it")

			//Key1 and key3 should still exist. Test to delete it
			for _, v := range []string{"key1", "key3"} {
				res := vm.PolicyGet(v)
				res.ExpectSuccess(fmt.Sprintf("Cannot get policy rule with key %s", v))

				res = vm.PolicyDel(v)
				res.ExpectSuccess("Unable to delete policy rule with key %s", v)
			}

			res = vm.PolicyGetAll()
			res.ExpectSuccess("unable to get policy rules from cilium")

			res = vm.PolicyDelAll()
			res.ExpectSuccess("deleting all policy rules should not fail even if no rules are imported to cilium")
		})
	})

	It("checks policy trace output", func() {

		httpd2Label := "id.httpd2"
		httpd1Label := "id.httpd1"
		allowedVerdict := "Final verdict: ALLOWED"

		By("Checking policy trace by labels")

		By("Importing policy that allows ingress to %q from the host and %q", httpd1Label, httpd2Label)

		allowHttpd1IngressHostHttpd2 := `
			[{
    			"endpointSelector": {"matchLabels":{"id.httpd1":""}},
    			"ingress": [{
        			"fromEndpoints": [
            			{"matchLabels":{"reserved:host":""}},
            			{"matchLabels":{"id.httpd2":""}}
					]
    			}]
			}]`

		_, err := vm.PolicyRenderAndImport(allowHttpd1IngressHostHttpd2)
		Expect(err).Should(BeNil(), "Error importing policy: %s", err)

		By("Verifying that trace says that %q can reach %q", httpd2Label, httpd1Label)

		res := vm.Exec(fmt.Sprintf(`cilium policy trace -s %s -d %s/TCP`, httpd2Label, httpd1Label))
		Expect(res.Stdout()).Should(ContainSubstring(allowedVerdict), "Policy trace did not contain %s", allowedVerdict)

		Expect(vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")

		endpointIDS, err := vm.GetEndpointsIds()
		Expect(err).To(BeNil(), "Unable to get IDs of endpoints")

		httpd2EndpointID, exists := endpointIDS[helpers.Httpd2]
		Expect(exists).To(BeTrue(), "Expected endpoint ID to exist for %s", helpers.Httpd2)

		httpd1EndpointID, exists := endpointIDS[helpers.Httpd1]
		Expect(exists).To(BeTrue(), "Expected endpoint ID to exist for %s", helpers.Httpd1)

		By("Getting models of endpoints to access policy-related metadata")
		httpd2EndpointModel := vm.EndpointGet(httpd2EndpointID)
		Expect(httpd2EndpointModel).To(Not(BeNil()), "Expected non-nil model for endpoint %s", helpers.Httpd2)
		Expect(httpd2EndpointModel.Status.Identity).To(Not(BeNil()), "Expected non-nil identity for endpoint %s", helpers.Httpd2)

		httpd2ContainerLabel := "container:id.httpd2"

		By("Getting all identities which contain label %s", httpd2ContainerLabel)
		res = vm.ExecCilium(fmt.Sprintf(
			`identity list -o json | jq 'map(select(.labels[] | contains("%s")).id) | sort'`,
			httpd2ContainerLabel))
		var identities []int64
		err = res.Unmarshal(&identities)
		Expect(err).Should(BeNil(), "unable to get identities containing label %s", httpd2ContainerLabel)
		// We expect the host to be allowed.
		identities = append([]int64{1}, identities...)

		httpd1EndpointModel := vm.EndpointGet(httpd1EndpointID)
		Expect(httpd1EndpointModel).To(Not(BeNil()), "Expected non-nil model for endpoint %s", helpers.Httpd1)
		Expect(httpd1EndpointModel.Status.Identity).To(Not(BeNil()), "Expected non-nil identity for endpoint %s", helpers.Httpd1)
		Expect(httpd1EndpointModel.Status.Policy).To(Not(BeNil()), "Expected non-nil policy for endpoint %s", helpers.Httpd1)

		httpd1SecurityIdentity := httpd1EndpointModel.Status.Identity.ID
		httpd2SecurityIdentity := httpd2EndpointModel.Status.Identity.ID

		// TODO - remove hardcoding of host identity.
		By("Verifying allowed identities for ingress traffic to %q", helpers.Httpd1)
		actualIngressIdentitiesHttpd1 := httpd1EndpointModel.Status.Policy.Realized.AllowedIngressIdentities
		Expect(identities).Should(ConsistOf(actualIngressIdentitiesHttpd1),
			"Expected allowed identities %v, but instead got %v",
			identities, actualIngressIdentitiesHttpd1)

		By("Deleting all policies and adding a new policy to ensure that endpoint policy is updated accordingly")
		res = vm.PolicyDelAll()
		res.ExpectSuccess("Unable to delete all policies")

		allowHttpd1IngressHttpd2 := `
			[{
    			"endpointSelector": {"matchLabels":{"id.httpd1":""}},
    			"ingress": [{
        			"fromEndpoints": [
            			{"matchLabels":{"id.httpd2":""}}
					]
    			}]
			}]`

		_, err = vm.PolicyRenderAndImport(allowHttpd1IngressHttpd2)
		Expect(err).Should(BeNil(), "Error importing policy: %s", err)

		By("Verifying verbose trace for expected output using security identities")
		res = vm.Exec(fmt.Sprintf(
			`cilium policy trace --src-identity %d --dst-identity %d`,
			httpd2SecurityIdentity, httpd1SecurityIdentity))
		res.ExpectContains(allowedVerdict, "Policy trace did not contain %s", allowedVerdict)

		By("Verifying verbose trace for expected output using endpoint IDs")
		res = vm.Exec(fmt.Sprintf(
			`cilium policy trace --src-endpoint %s --dst-endpoint %s`,
			httpd2EndpointID, httpd1EndpointID))
		res.ExpectContains(allowedVerdict, "Policy trace did not contain %s", allowedVerdict)

		// Have to get models of endpoints again because policy has been updated.
		By("Getting models of endpoints to access policy-related metadata")
		httpd2EndpointModel = vm.EndpointGet(httpd2EndpointID)
		Expect(httpd2EndpointModel).To(Not(BeNil()), "Expected non-nil model for endpoint %s", helpers.Httpd2)
		Expect(httpd2EndpointModel.Status.Identity).To(Not(BeNil()), "Expected non-nil identity for endpoint %s", helpers.Httpd2)

		httpd1EndpointModel = vm.EndpointGet(httpd1EndpointID)
		Expect(httpd1EndpointModel).To(Not(BeNil()), "Expected non-nil model for endpoint %s", helpers.Httpd1)
		Expect(httpd1EndpointModel.Status.Identity).To(Not(BeNil()), "Expected non-nil identity for endpoint %s", helpers.Httpd1)
		Expect(httpd1EndpointModel.Status.Policy).To(Not(BeNil()), "Expected non-nil policy for endpoint %s", helpers.Httpd1)

		By("Getting all identities which contain label %s", httpd2ContainerLabel)
		res = vm.ExecCilium(fmt.Sprintf(
			`identity list -o json | jq 'map(select(.labels[] | contains("%s")).id) | sort'`,
			httpd2ContainerLabel))
		identities = []int64{}
		err = res.Unmarshal(&identities)
		Expect(err).Should(BeNil(), "unable to get identities containing label %s", httpd2ContainerLabel)

		By("Verifying allowed identities for ingress traffic to %q", helpers.Httpd1)
		actualIngressIdentitiesHttpd1 = httpd1EndpointModel.Status.Policy.Realized.AllowedIngressIdentities
		Expect(identities).Should(ConsistOf(actualIngressIdentitiesHttpd1),
			"Expected allowed identities %v, but instead got %v",
			identities, actualIngressIdentitiesHttpd1)

		res = vm.PolicyDelAll()
		res.ExpectSuccess("Unable to delete all policies")

		ExpectPolicyEnforcementUpdated(vm, helpers.PolicyEnforcementDefault)

		By("Checking that policy trace returns allowed verdict without any policies imported")
		res = vm.Exec(fmt.Sprintf(`cilium policy trace --src-endpoint %s --dst-endpoint %s`, httpd2EndpointID, httpd1EndpointID))
		res.ExpectContains(allowedVerdict, "Policy trace did not contain %s", allowedVerdict)
	})
})
