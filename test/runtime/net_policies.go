// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package RuntimeTest

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/gomega"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/policy/api"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	"github.com/cilium/cilium/test/helpers/constants"
)

const (
	// Policy files
	multL7PoliciesJSON       = "Policies-l7-multiple.json"
	policiesL7JSON           = "Policies-l7-simple.json"
	policiesL3JSON           = "Policies-l3-policy.json"
	policiesL4Json           = "Policies-l4-policy.json"
	policiesReservedInitJSON = "Policies-reserved-init.json"

	initContainer = "initContainer"
)

var _ = Describe("RuntimeAgentPolicies", func() {

	var (
		vm            *helpers.SSHMeta
		monitorStop   = func() error { return nil }
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

	// Cannot be tested in cilium-cli connectivity tests because of Daemon configuration changes
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

	// Cannot be tested in cilium-cli connectivity tests because of setting policy enforcement to default
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

	// TODO: discuss whether it should be tested in cilium-cli by creating a host network pod
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
			res := vm.ContainerExec(helpers.App1, helpers.CurlFail(cloudFlare))
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

	// cannot be tested in cilium-cli connectivity tests because of delicate timing required for this test
	// (this test relies heavily on the fact that pod is created and being pinged immediately after creation)
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

			By("Waiting for newly added endpoint to be ready")
			Expect(vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")

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
				`{.flow.source.labels} -> {.flow.destination.ID} {.flow.destination.labels} {.flow.IP.destination} : {.flow.verdict} {.flow.event_type.type}`,
				fmt.Sprintf(`["reserved:host"] -> %s ["container:somelabel"] %s : DROPPED 1`, endpointID, endpointIP.IPV4))
			Expect(err).To(BeNil(), "Default drop on ingress failed")
			hubbleRes.ExpectDoesNotContainFilterLine(
				`{.flow.source.labels} -> {.flow.destination.ID} {.flow.destination.labels} {.flow.IP.destination} : {.flow.verdict} {.flow.event_type.type}`,
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
				`{.flow.source.ID} {.flow.source.labels} -> {.flow.destination.labels} {.flow.IP.destination} : {.flow.verdict} {.flow.event_type.type}`,
				fmt.Sprintf(`%s ["container:somelabel"] -> ["reserved:host"] %s : DROPPED 1`, endpointID, hostIP))
			Expect(err).To(BeNil(), "Default drop on egress failed")

			hubbleRes.ExpectDoesNotContainFilterLine(
				`{.flow.source.labels} {.flow.IP.source} -> {.flow.destination.ID} : {.flow.verdict} {.flow.reply} {.flow.event_type.type}`,
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
					`{.flow.source.labels} -> {.flow.IP.destination} : {.flow.verdict} {.flow.event_type.type}`,
					fmt.Sprintf(`["reserved:host"] -> %s : AUDIT 5`, endpointIP.IPV4))
				Expect(err).To(BeNil(), "Default policy verdict on ingress failed")
				// Checks for the subsequent trace:to-endpoint event (type 4)
				hubbleRes.ExpectContainsFilterLine(
					`{.flow.source.labels} -> {.flow.destination.ID} {.flow.destination.labels} {.flow.IP.destination} : {.flow.verdict} {.flow.event_type.type}`,
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
					`{.flow.source.labels} {.flow.IP.source} -> {.flow.destination.ID} : {.flow.verdict} {.flow.reply} {.flow.event_type.type}`,
					fmt.Sprintf(`["reserved:host"] %s -> %s : FORWARDED true 4`, hostIP, endpointID))
				Expect(err).To(BeNil(), "No ingress traffic to endpoint")
				// Checks for a ingress policy verdict event (type 5)
				hubbleRes.ExpectContainsFilterLine(
					`{.flow.source.ID} -> {.flow.destination.labels} {.flow.IP.destination} : {.flow.verdict} {.flow.event_type.type}`,
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

			By("Waiting for newly added endpoint to be ready")
			Expect(vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")

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
				`{.flow.source.labels} -> {.flow.destination.ID} {.flow.IP.destination} : {.flow.verdict}`,
				fmt.Sprintf(`["reserved:host"] -> %s %s : FORWARDED`, endpointID, endpointIP.IPV4), 10*time.Second)
			Expect(err).To(BeNil(), "Allow on ingress failed")

			// Drop Reason 133 is "Policy denied"
			hubbleRes.ExpectDoesNotContainFilterLine(
				`{.flow.source.labels} -> {.flow.destination.ID} {.flow.IP.destination} : {.flow.verdict} {.flow.drop_reason}`,
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

			By("Waiting for newly added endpoint to be ready")
			Expect(vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")

			endpoints, err := vm.GetAllEndpointsIds()
			Expect(err).To(BeNil(), "Unable to get IDs of endpoints")
			endpointID, exists := endpoints[initContainer]
			Expect(exists).To(BeTrue(), "Expected endpoint ID to exist for %s", initContainer)
			egressEpModel := vm.EndpointGet(endpointID)
			Expect(egressEpModel).NotTo(BeNil(), "nil model returned for endpoint %s", endpointID)

			By("Testing hubble observe output")
			err = hubbleRes.WaitUntilMatchFilterLineTimeout(
				`{.flow.source.ID} {.flow.source.labels} -> {.flow.destination.labels} {.flow.IP.destination} : {.flow.verdict}`,
				fmt.Sprintf(`%s ["container:somelabel"] -> ["reserved:host"] %s : FORWARDED`, endpointID, hostIP),
				10*time.Second)
			Expect(err).To(BeNil(), "Allow on ingress failed")

			// Drop Reason 133 is "Policy denied"
			hubbleRes.ExpectDoesNotContainFilterLine(
				`{.flow.source.ID} {.flow.source.labels} -> {.flow.destination.labels} {.flow.IP.destination} : {.flow.verdict} {.flow.drop_reason}`,
				fmt.Sprintf(`%s ["container:somelabel"] -> ["reserved:host"] %s : DROPPED 133`, endpointID, hostIP),
				"Unexpected drop")
		})
	})
})
