// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package RuntimeTest

import (
	"context"
	"sync"
	"time"

	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	"github.com/cilium/cilium/test/helpers/constants"
)

var _ = Describe("RuntimeDatapathConntrackInVethModeTest", runtimeConntrackTest("veth"))

var runtimeConntrackTest = func(datapathMode string) func() {
	return func() {
		var (
			vm            *helpers.SSHMeta
			testStartTime time.Time
			monitorStop   = func() error { return nil }

			curl1ContainerName = "curl"
			curl2ContainerName = "curl2"
		)

		type conntestCases struct {
			from        string
			to          string
			destination string
			assert      func() types.GomegaMatcher
		}

		BeforeAll(func() {
			vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)
			ExpectCiliumReady(vm)

			ExpectPolicyEnforcementUpdated(vm, helpers.PolicyEnforcementAlways)
		})

		AfterAll(func() {
			vm.CloseSSHClient()
		})

		clientServerConnectivity := func() {
			By("============= Starting Connectivity Test ============= ")

			By("Getting IPs of each spawned container")
			clientDockerNetworking, err := vm.ContainerInspectNet(helpers.Client)
			ExpectWithOffset(1, err).Should(BeNil(),
				"could not get metadata for container %q", helpers.Client)
			By("client container Docker networking: %q", clientDockerNetworking)

			serverDockerNetworking, err := vm.ContainerInspectNet(helpers.Server)
			ExpectWithOffset(1, err).Should(BeNil(),
				"could not get metadata for container %q", helpers.Server)
			By("server container Docker networking: %q", serverDockerNetworking)

			httpdDockerNetworking, err := vm.ContainerInspectNet(helpers.Httpd1)
			ExpectWithOffset(1, err).Should(BeNil(),
				"could not get metadata for container %q", helpers.Httpd1)
			By("httpd1 container Docker networking: %q", httpdDockerNetworking)

			httpd2DockerNetworking, err := vm.ContainerInspectNet(helpers.Httpd2)
			ExpectWithOffset(1, err).Should(BeNil(),
				"could not get metadata for container %q", helpers.Httpd2)
			By("httpd2 container Docker networking: %q", httpd2DockerNetworking)

			curl1DockerNetworking, err := vm.ContainerInspectNet(curl1ContainerName)
			ExpectWithOffset(1, err).Should(BeNil(),
				"could not get metadata for container %q", curl1ContainerName)
			By("curl1 container Docker networking: %q", curl1DockerNetworking)

			curl2DockerNetworking, err := vm.ContainerInspectNet(curl2ContainerName)
			ExpectWithOffset(1, err).Should(BeNil(),
				"could not get metadata for container %q", curl2ContainerName)
			By("httpd1 container Docker networking: %q", curl2DockerNetworking)

			By("Showing policies imported to Cilium")
			res := vm.PolicyGetAll()
			GinkgoPrint(res.CombineOutput().String())

			testCases := []conntestCases{
				{
					from:        curl1ContainerName,
					to:          helpers.CurlFail("http://[%s]:80", httpdDockerNetworking[helpers.IPv6]),
					destination: helpers.Httpd1,
					assert:      BeTrue,
				},
				{
					from:        curl1ContainerName,
					to:          helpers.CurlFail("http://%s:80", httpdDockerNetworking[helpers.IPv4]),
					destination: helpers.Httpd1,
					assert:      BeTrue,
				},
				{
					from:        curl2ContainerName,
					to:          helpers.CurlFail("http://[%s]:80", httpdDockerNetworking[helpers.IPv6]),
					destination: helpers.Httpd1,
					assert:      BeFalse,
				},
				{
					from:        curl2ContainerName,
					to:          helpers.CurlFail("http://%s:80", httpdDockerNetworking[helpers.IPv4]),
					destination: helpers.Httpd1,
					assert:      BeFalse,
				},
				{
					from:        curl1ContainerName,
					to:          helpers.CurlFail("http://[%s]:80", httpd2DockerNetworking[helpers.IPv6]),
					destination: helpers.Httpd2,
					assert:      BeFalse,
				},
				{
					from:        curl1ContainerName,
					to:          helpers.CurlFail("http://%s:80", httpd2DockerNetworking[helpers.IPv4]),
					destination: helpers.Httpd2,
					assert:      BeFalse,
				},
				{
					from:        curl2ContainerName,
					to:          helpers.CurlFail("http://[%s]:80", httpdDockerNetworking[helpers.IPv6]),
					destination: helpers.Httpd2,
					assert:      BeFalse,
				},
				{
					from:        curl2ContainerName,
					to:          helpers.CurlFail("http://%s:80", httpdDockerNetworking[helpers.IPv4]),
					destination: helpers.Httpd2,
					assert:      BeFalse,
				},
				{
					// see comment below about ICMP ids
					from:        helpers.Client,
					to:          helpers.Ping6WithID(serverDockerNetworking[helpers.IPv6], 1111),
					destination: helpers.Server,
					assert:      BeTrue,
				},
				{
					// see comment below about ICMP ids
					from:        helpers.Client,
					to:          helpers.PingWithID(serverDockerNetworking[helpers.IPv4], 1111),
					destination: helpers.Server,
					assert:      BeTrue,
				},
				{
					from:        helpers.Client,
					to:          helpers.Netcat("%s 777", serverDockerNetworking[helpers.IPv6]),
					destination: helpers.Server,
					assert:      BeFalse,
				},
				{
					from:        helpers.Client,
					to:          helpers.Netcat("%s 777", serverDockerNetworking[helpers.IPv4]),
					destination: helpers.Server,
					assert:      BeFalse,
				},

				{
					from:        helpers.Client,
					to:          helpers.Netperf(serverDockerNetworking[helpers.IPv6], helpers.TCP_RR, ""),
					destination: helpers.Server,
					assert:      BeTrue,
				},
				{
					from:        helpers.Client,
					to:          helpers.Netperf(serverDockerNetworking[helpers.IPv4], helpers.TCP_RR, ""),
					destination: helpers.Server,
					assert:      BeTrue,
				},
				{
					from:        helpers.Client,
					to:          helpers.Netperf(serverDockerNetworking[helpers.IPv6], helpers.UDP_RR, ""),
					destination: helpers.Server,
					assert:      BeTrue,
				},
				{
					from:        helpers.Client,
					to:          helpers.Netperf(serverDockerNetworking[helpers.IPv4], helpers.UDP_RR, ""),
					destination: helpers.Server,
					assert:      BeTrue,
				},
			}

			for _, test := range testCases {
				By("Container %q test connectivity to %q", test.from, test.destination)
				res = vm.ContainerExec(test.from, test.to)
				ExpectWithOffset(1, res.WasSuccessful()).To(test.assert(),
					"The result of %q from container %q to %s does not match", test.to, test.from, test.destination)
			}

			By("Testing bidirectional connectivity from client to server")

			By("container %s pinging %s IPv6 (should NOT work)", helpers.Server, helpers.Client)
			res = vm.ContainerExec(helpers.Server, helpers.Ping6WithID(clientDockerNetworking[helpers.IPv6], 1111))
			ExpectWithOffset(1, res).ShouldNot(helpers.CMDSuccess(),
				"container %q unexpectedly was able to ping to %q IP:%q", helpers.Server, helpers.Client, clientDockerNetworking[helpers.IPv6])

			By("container %s pinging %s IPv4 (should NOT work)", helpers.Server, helpers.Client)
			res = vm.ContainerExec(helpers.Server, helpers.PingWithID(clientDockerNetworking[helpers.IPv4], 1111))
			ExpectWithOffset(1, res).ShouldNot(helpers.CMDSuccess(),
				"%q was unexpectedly able to ping to %q IP:%q", helpers.Server, helpers.Client, clientDockerNetworking[helpers.IPv4])

			By("============= Finished Connectivity Test ============= ")
		}

		BeforeEach(func() {
			// TODO: provide map[string]string instead of one string representing KV pair.
			res := vm.ContainerCreate(helpers.Client, constants.NetperfImage, helpers.CiliumDockerNetwork, "-l id.client")
			res.ExpectSuccess("failed to create client container")
			res = vm.ContainerCreate(helpers.Server, constants.NetperfImage, helpers.CiliumDockerNetwork, "-l id.server")
			res.ExpectSuccess("failed to create server container")
			res = vm.ContainerCreate(helpers.Httpd1, constants.HttpdImage, helpers.CiliumDockerNetwork, "-l id.httpd")
			res.ExpectSuccess("failed to create httpd1 container")
			res = vm.ContainerCreate(helpers.Httpd2, constants.HttpdImage, helpers.CiliumDockerNetwork, "-l id.httpd_deny")
			res.ExpectSuccess("failed to create httpd2 container")
			res = vm.ContainerCreate(curl1ContainerName, constants.NetperfImage, helpers.CiliumDockerNetwork, "-l id.curl")
			res.ExpectSuccess("failed to create curl container")
			res = vm.ContainerCreate(curl2ContainerName, constants.NetperfImage, helpers.CiliumDockerNetwork, "-l id.curl2")
			res.ExpectSuccess("failed to create curl2 container")

			vm.PolicyDelAll().ExpectSuccess("cannot delete all policies")

			_, err := vm.PolicyImportAndWait(vm.GetFullPath("ct-test-policy.json"), helpers.HelperTimeout)
			Expect(err).Should(BeNil())

		})

		JustBeforeEach(func() {
			_, monitorStop = vm.MonitorStart()
			testStartTime = time.Now()
		})

		AfterEach(func() {
			containersToRm := []string{helpers.Client, helpers.Server, helpers.Httpd1, helpers.Httpd2, curl1ContainerName, curl2ContainerName}
			for _, containerToRm := range containersToRm {
				vm.ContainerRm(containerToRm)
			}
			vm.PolicyDelAll().ExpectSuccess("Policies cannot be deleted")

			ExpectPolicyEnforcementUpdated(vm, helpers.PolicyEnforcementDefault)
		})

		JustAfterEach(func() {
			vm.ValidateNoErrorsInLogs(time.Since(testStartTime))
			Expect(monitorStop()).To(BeNil(), "cannot stop monitor command")
		})

		AfterFailed(func() {
			vm.ReportFailed("cilium policy get")
			vm.ReportFailed("cilium bpf policy get --all")
		})

		It("Conntrack-related configuration options for endpoints", func() {
			By("Getting Endpoint IDs")
			endpoints, err := vm.GetEndpointsIds()
			Expect(err).Should(BeNil(), "could not get endpoint IDs")

			// Check that endpoint IDs exist in map.
			for _, endpointName := range []string{helpers.Server, helpers.Client} {
				_, exists := endpoints[endpointName]
				Expect(exists).To(BeTrue(), "unable to retrieve endpoint ID for endpoint %s", endpointName)
				By("Endpoint ID for %q = %q", endpointName, endpoints[endpointName])

			}

			endpointsToConfigure := []string{endpoints[helpers.Server], endpoints[helpers.Client]}

			// Iterate through possible values to configure ConntrackLocal option,
			// apply to both endpoints, verify the option configuration change matches
			// what was performed, and then run connectivity test with endpoints.
			conntrackLocalOptionModes := []string{helpers.OptionDisabled, helpers.OptionEnabled}
			for _, conntrackLocalOptionMode := range conntrackLocalOptionModes {
				By("Testing with endpoint configuration option: ConntrackLocal=%s", conntrackLocalOptionMode)

				for _, endpointToConfigure := range endpointsToConfigure {
					err := vm.SetAndWaitForEndpointConfiguration(
						endpointToConfigure, helpers.OptionConntrackLocal, conntrackLocalOptionMode)
					Expect(err).To(BeNil(), "Cannot set ConnTrackLocal=%q for endpoint %q",
						conntrackLocalOptionMode, endpointToConfigure)
				}
				Expect(vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")
				clientServerConnectivity()
			}
		})
	}
}

var restartChaosTest = func() {
	var vm *helpers.SSHMeta

	BeforeAll(func() {
		vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)
	})

	AfterAll(func() {
		vm.CloseSSHClient()
	})

	It("Checking that during restart no traffic is dropped using Egress + Ingress Traffic", func() {
		By("Installing sample containers")
		vm.SampleContainersActions(helpers.Create, helpers.CiliumDockerNetwork)
		vm.PolicyDelAll().ExpectSuccess("Cannot deleted all policies")

		_, err := vm.PolicyImportAndWait(vm.GetFullPath(policiesL4Json), helpers.HelperTimeout)
		Expect(err).Should(BeNil(), "Cannot install L4 policy")

		Expect(vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")

		By("Starting background connection from app2 to httpd1 container")
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

		err = vm.RestartCilium()
		Expect(err).Should(BeNil(), "restarting Cilium failed")

		By("Stopping background connections")
		cancel()
		wg.Wait()

		GinkgoPrint("Made %d connections in total", len(backgroundChecks))
		Expect(backgroundChecks).ShouldNot(BeEmpty(), "No background connections were made")
		for _, check := range backgroundChecks {
			check.res.ExpectSuccess("Curl from app2 to httpd1 should work but it failed at %s", check.time)
		}
	})
}
