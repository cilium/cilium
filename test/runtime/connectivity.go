package RuntimeTest

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	"github.com/cilium/cilium/test/helpers/constants"

	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
)

func runOnNetNextOnly(f func()) func() {
	if helpers.RunsOnNetNext() {
		return f
	}
	return func() {}
}

var _ = Describe("RuntimeConnectivityInVethModeTest", runtimeConnectivityTest("veth"))
var _ = Describe("RuntimeConnectivityInIpvlanModeTest", runOnNetNextOnly(runtimeConnectivityTest("ipvlan")))

// TODO(brb) Either create a dummy netdev or determine the master device at runtime
const ipvlanMasterDevice = "enp0s8"

var runtimeConnectivityTest = func(datapathMode string) func() {
	return func() {
		var (
			vm          *helpers.SSHMeta
			monitorStop = func() error { return nil }
		)

		BeforeAll(func() {
			vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)

			if datapathMode == "ipvlan" {
				vm.SetUpCiliumInIpvlanMode(ipvlanMasterDevice)
				// cilium-docker has to be restarted because the datapath mode
				// has changed
				vm.Exec("sudo systemctl restart cilium-docker")
			}

			ExpectCiliumReady(vm)
		})

		JustBeforeEach(func() {
			monitorStop = vm.MonitorStart()
		})

		AfterAll(func() {
			// Restore the datapath mode and cilium-docker
			if datapathMode == "ipvlan" {
				vm.SetUpCilium()
				vm.Exec("sudo systemctl restart cilium-docker")
			}
			vm.CloseSSHClient()
		})

		removeContainer := func(containerName string) {
			By("removing container %s", containerName)
			res := vm.ContainerRm(containerName)
			ExpectWithOffset(1, res).To(helpers.CMDSuccess(), "cannot delete container")
		}

		AfterEach(func() {
			vm.PolicyDelAll().ExpectSuccess("Policies cannot be deleted")
		})

		JustAfterEach(func() {
			vm.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
			Expect(monitorStop()).To(BeNil(), "cannot stop monitor command")
		})

		AfterFailed(func() {
			vm.ReportFailed()
		})

		Context("Basic Connectivity test", func() {

			BeforeEach(func() {
				vm.ContainerCreate(helpers.Client, constants.NetperfImage, helpers.CiliumDockerNetwork, "-l id.client")
				vm.ContainerCreate(helpers.Server, constants.NetperfImage, helpers.CiliumDockerNetwork, "-l id.server")
				vm.PolicyDelAll()
				vm.WaitEndpointsReady()
				err := helpers.WithTimeout(func() bool {
					if data, _ := vm.GetEndpointsNames(); len(data) < 2 {
						logger.Info("Waiting for endpoints to be ready")
						return false
					}
					return true
				}, "Endpoints are not ready", &helpers.TimeoutConfig{Timeout: 150 * time.Second})
				Expect(err).Should(BeNil())

				err = helpers.WithTimeout(func() bool {
					res := vm.ContainerExec(helpers.Server, "netperf -H 127.0.0.1 -l 1")
					if !res.WasSuccessful() {
						logger.Info("Waiting for netserver to come up")
					}
					return res.WasSuccessful()
				}, "netserver did not come up in time", &helpers.TimeoutConfig{Timeout: 20 * time.Second})
				Expect(err).Should(BeNil(), "timeout while waiting for netserver to start inside netperf container")
			}, 150)

			AfterEach(func() {
				removeContainer(helpers.Client)
				removeContainer(helpers.Server)
				return
			})

			It("Test connectivity between containers without policies imported", func() {
				// TODO: this code is duplicated in the next "It" in this file. refactor it into a function.
				// See if we can make the "Filter" strings for getting IPv4 and IPv6 addresses into constants.
				By("inspecting container %s", helpers.Server)
				serverData := vm.ContainerInspect(helpers.Server)
				serverIP, err := serverData.Filter(fmt.Sprintf("{[0].NetworkSettings.Networks.%s.IPAddress}", helpers.CiliumDockerNetwork))
				Expect(err).Should(BeNil())

				By("serverIP: %q", serverIP)
				serverIPv6, err := serverData.Filter(fmt.Sprintf("{[0].NetworkSettings.Networks.%s.GlobalIPv6Address}", helpers.CiliumDockerNetwork))
				By("serverIPv6: %q", serverIPv6)
				Expect(err).Should(BeNil())

				By("checking %q can ping to %q IPv6", helpers.Client, helpers.Server)
				res := vm.ContainerExec(helpers.Client, helpers.Ping6(serverIPv6.String()))
				res.ExpectSuccess()

				By("checking %q can ping to %q IPv4", helpers.Client, helpers.Server)
				res = vm.ContainerExec(helpers.Client, helpers.Ping(serverIP.String()))
				res.ExpectSuccess()

				// TODO: remove this hardcoding ; it is not clean. Have command wrappers that take maps of strings.
				By("netperf to %q from %q IPv6", helpers.Server, helpers.Client)
				cmd := fmt.Sprintf(
					"netperf -c -C -t TCP_SENDFILE -H %s", serverIPv6)

				res = vm.ContainerExec(helpers.Client, cmd)
				res.ExpectSuccess()
			}, 300)

			It("Test connectivity between containers with policy imported", func() {
				policyID, err := vm.PolicyImportAndWait(
					fmt.Sprintf("%s/test.policy", vm.ManifestsPath()), 150*time.Second)
				Expect(err).Should(BeNil())
				logger.Debugf("New policy created with id '%d'", policyID)

				serverData := vm.ContainerInspect(helpers.Server)
				serverIP, err := serverData.Filter(fmt.Sprintf("{[0].NetworkSettings.Networks.%s.IPAddress}", helpers.CiliumDockerNetwork))
				Expect(err).Should(BeNil())
				By("serverIP: %q", serverIP)
				serverIPv6, err := serverData.Filter(fmt.Sprintf("{[0].NetworkSettings.Networks.%s.GlobalIPv6Address}", helpers.CiliumDockerNetwork))
				By("serverIPv6: %q", serverIPv6)
				Expect(err).Should(BeNil())

				By("%q can ping to %q IPV6", helpers.Client, helpers.Server)
				res := vm.ContainerExec(helpers.Client, helpers.Ping6(serverIPv6.String()))
				res.ExpectSuccess()

				By("%s can ping to %s IPv4", helpers.Client, helpers.Server)
				res = vm.ContainerExec(helpers.Client, helpers.Ping(serverIP.String()))
				res.ExpectSuccess()

				By("netperf to %q from %q (should succeed)", helpers.Server, helpers.Client)
				cmd := fmt.Sprintf("netperf -c -C -H %s", serverIP)
				res = vm.ContainerExec(helpers.Client, cmd)

				// TODO: remove this hardcoding ; it is not clean. Have command wrappers that take maps of strings.
				By("netperf to %q from %q IPv6 with -t TCP_SENDFILE", helpers.Server, helpers.Client)
				cmd = fmt.Sprintf(
					"netperf -c -C -t TCP_SENDFILE -H %s", serverIPv6)

				res = vm.ContainerExec(helpers.Client, cmd)
				res.ExpectSuccess()

				By("super_netperf to %q from %q (should succeed)", helpers.Server, helpers.Client)
				cmd = fmt.Sprintf("super_netperf 10 -c -C -t TCP_SENDFILE -H %s", serverIP)
				res = vm.ContainerExec(helpers.Client, cmd)
				res.ExpectSuccess()

				By("ping from %q to %q", helpers.Host, helpers.Server)
				res = vm.Exec(helpers.Ping(serverIP.String()))
				res.ExpectSuccess()
			}, 300)

			It("Test NAT46 connectivity between containers", func() {
				if datapathMode == "ipvlan" {
					Skip("NAT64 is not implemented in the ipvlan mode")
				}
				endpoints, err := vm.GetEndpointsIds()
				Expect(err).Should(BeNil(), "could not get endpoint IDs")

				server, err := vm.ContainerInspectNet(helpers.Server)
				Expect(err).Should(BeNil())
				By("server: %q", server)

				client, err := vm.ContainerInspectNet(helpers.Client)
				Expect(err).Should(BeNil())
				By("client: %q", client)

				status := vm.EndpointSetConfig(endpoints[helpers.Client], "NAT46", helpers.OptionEnabled)
				Expect(status).Should(BeTrue())

				areEndpointsReady := vm.WaitEndpointsReady()
				Expect(areEndpointsReady).Should(BeTrue(), "Endpoints not ready after timeout")

				res := vm.ContainerExec(helpers.Client, helpers.Ping6(fmt.Sprintf(
					"::FFFF:%s", server[helpers.IPv4])))

				res.ExpectSuccess()

				res = vm.ContainerExec(helpers.Server,
					helpers.Ping6(fmt.Sprintf("::FFFF:%s", client[helpers.IPv4])))
				res.ExpectFail(fmt.Sprintf("unexpectedly succeeded pinging IPv6 %s from %s",
					client[helpers.IPv4], helpers.Server))
			})
		})

		Context("With CNI", func() {
			var (
				cniPlugin = "/opt/cni/bin/cilium-cni"
				cniServer = "cni-server"
				cniClient = "cni-client"
				netDPath  = "/etc/cni/net.d/"
				tmpDir    *helpers.CmdRes
			)

			BeforeAll(func() {
				// Remove any CNI plugin installed in the provision server. This
				// helps to avoid issues on installing the new CNI
				_ = vm.ExecWithSudo(fmt.Sprintf("rm -rf %[1]s/*.conf", netDPath)).ExpectSuccess(
					"CNI config cannot be deleted")

				tmpDir = vm.Exec("mktemp -d")
				tmpDir.ExpectSuccess("TMP folder cannot be created %s", tmpDir.Output())
			})

			AfterAll(func() {
				vm.Exec(fmt.Sprintf("rm -rf %s", tmpDir.Output()))
			})

			BeforeEach(func() {
				vm.PolicyDelAll().ExpectSuccess("Policies cannot be deleted")
			})

			AfterEach(func() {
				vm.ContainerRm(cniServer)
				vm.ContainerRm(cniClient)
				vm.Exec(fmt.Sprintf("docker rm -f $(docker ps --filter ancestor=%s --format '{{.ID}}')", constants.BusyboxImage))
			})

			runCNIContainer := func(name string, label string) {
				res := vm.Exec(fmt.Sprintf("docker run -t -d --net=none -l %s %s", label, constants.BusyboxImage))
				res.ExpectSuccess()
				containerID := res.SingleOut()

				pid := vm.Exec(fmt.Sprintf("docker inspect -f '{{ .State.Pid }}' %s", containerID))
				pid.ExpectSuccess()
				netnspath := fmt.Sprintf("/proc/%s/ns/net", pid.SingleOut())

				res = vm.Exec(fmt.Sprintf(
					"sudo -E PATH=$PATH:/opt/cni/bin -E CNI_PATH=%[1]s/bin %[1]s/cni/scripts/exec-plugins.sh add %s %s",
					tmpDir.SingleOut(), containerID, netnspath))
				res.ExpectSuccess("CNI exec-plugins did not work correctly")

				res = vm.ContainerCreate(
					name, constants.NetperfImage,
					fmt.Sprintf("container:%s", containerID), fmt.Sprintf("-l %s", label))
				res.ExpectSuccess("Container %s cannot be created", name)
			}

			It("Basic connectivity test", func() {
				filename := "05-cilium-cni.conf"
				cniConf := `{"name": "cilium",
				"type": "cilium-cni"}`
				err := helpers.RenderTemplateToFile(filename, cniConf, os.ModePerm)
				Expect(err).To(BeNil())

				cmd := vm.ExecWithSudo(fmt.Sprintf("mv %s %s",
					helpers.GetFilePath(filename),
					filepath.Join(netDPath, filename)))
				cmd.ExpectSuccess("cannot install cilium cni plugin conf")
				script := fmt.Sprintf(`
				cd %s && \
				git clone https://github.com/containernetworking/cni -b v0.5.2 --single-branch && \
				cd cni && \
				./build.sh
			`, tmpDir.SingleOut())
				vm.Exec(script).ExpectSuccess("Cannot install cni")
				vm.Exec(fmt.Sprintf("cp %s %s", cniPlugin, filepath.Join(tmpDir.SingleOut(), "bin")))

				By("Importing policy")
				policyFileName := "CNI-policy.json"
				policy := `
				[{
					"endpointSelector": {"matchLabels":{"id.server":""}},
					"ingress": [{
						"fromEndpoints": [
						{"matchLabels":{"reserved:host":""}},
						{"matchLabels":{"id.client":""}}
					]
					}]
				}]`
				err = helpers.RenderTemplateToFile(policyFileName, policy, os.ModePerm)
				Expect(err).Should(BeNil())
				_, err = vm.PolicyImportAndWait(helpers.GetFilePath(policyFileName), helpers.HelperTimeout)
				Expect(err).Should(BeNil(), fmt.Sprintf("Cannot import policy %s", policyFileName))

				By("Adding containers")

				runCNIContainer(cniServer, "id.server")
				runCNIContainer(cniClient, "id.client")

				areEndpointsReady := vm.WaitEndpointsReady()
				Expect(areEndpointsReady).Should(BeTrue())

				serverIPv4 := vm.ContainerExec(
					cniServer,
					`ip -4 a show dev eth0 scope global | grep inet | sed -e 's%.*inet \(.*\)\/.*%\1%'`)

				serverIPv6 := vm.ContainerExec(
					cniServer,
					`ip -6 a show dev eth0 scope global | grep inet6 | sed -e 's%.*inet6 \(.*\)\/.*%\1%'`)

				vm.ContainerExec(cniClient, helpers.Ping(serverIPv4.SingleOut())).ExpectSuccess(
					"cannot ping from client to server %q", serverIPv4.SingleOut())

				vm.ContainerExec(cniClient, helpers.Ping6(serverIPv6.SingleOut())).ExpectSuccess(
					"cannot ping6 from client to server %q", serverIPv6.SingleOut())
			})
		})
	}
}

var _ = Describe("RuntimeConntrackInVethModeTest", runtimeConntrackTest("veth"))
var _ = Describe("RuntimeConntrackInIpvlanModeTest", runOnNetNextOnly(runtimeConntrackTest("ipvlan")))

var runtimeConntrackTest = func(datapathMode string) func() {
	return func() {
		var (
			vm          *helpers.SSHMeta
			monitorStop = func() error { return nil }

			curl1ContainerName             = "curl"
			curl2ContainerName             = "curl2"
			CTPolicyConntrackLocalDisabled = "ct-test-policy-conntrack-local-disabled.json"
		)

		type conntestCases struct {
			from        string
			to          string
			destination string
			assert      func() types.GomegaMatcher
		}

		BeforeAll(func() {
			vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)

			if datapathMode == "ipvlan" {
				vm.SetUpCiliumInIpvlanMode(ipvlanMasterDevice)
				// cilium-docker has to be restarted because the datapath mode
				// has changed
				vm.Exec("sudo systemctl restart cilium-docker")
			}

			ExpectCiliumReady(vm)

			ExpectPolicyEnforcementUpdated(vm, helpers.PolicyEnforcementAlways)
		})

		AfterAll(func() {
			// Restore the datapath mode and cilium-docker
			if datapathMode == "ipvlan" {
				vm.SetUpCilium()
				vm.Exec("sudo systemctl restart cilium-docker")
			}
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
					from:        helpers.Client,
					to:          helpers.Ping6(serverDockerNetworking[helpers.IPv6]),
					destination: helpers.Server,
					assert:      BeTrue,
				},
				{
					from:        helpers.Client,
					to:          helpers.Ping(serverDockerNetworking[helpers.IPv4]),
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
					to:          helpers.Netperf(serverDockerNetworking[helpers.IPv6], helpers.TCP_RR),
					destination: helpers.Server,
					assert:      BeTrue,
				},
				{
					from:        helpers.Client,
					to:          helpers.Netperf(serverDockerNetworking[helpers.IPv4], helpers.TCP_RR),
					destination: helpers.Server,
					assert:      BeTrue,
				},
				{
					from:        helpers.Client,
					to:          helpers.Netperf(serverDockerNetworking[helpers.IPv6], helpers.UDP_RR),
					destination: helpers.Server,
					assert:      BeTrue,
				},
				{
					from:        helpers.Client,
					to:          helpers.Netperf(serverDockerNetworking[helpers.IPv4], helpers.UDP_RR),
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
			res = vm.ContainerExec(helpers.Server, helpers.Ping6(clientDockerNetworking[helpers.IPv6]))
			ExpectWithOffset(1, res).ShouldNot(helpers.CMDSuccess(),
				"container %q unexpectedly was able to ping to %q IP:%q", helpers.Server, helpers.Client, clientDockerNetworking[helpers.IPv6])

			By("container %s pinging %s IPv4 (should NOT work)", helpers.Server, helpers.Client)
			res = vm.ContainerExec(helpers.Server, helpers.Ping(clientDockerNetworking[helpers.IPv4]))
			ExpectWithOffset(1, res).ShouldNot(helpers.CMDSuccess(),
				"%q was unexpectedly able to ping to %q IP:%q", helpers.Server, helpers.Client, clientDockerNetworking[helpers.IPv4])

			By("============= Finished Connectivity Test ============= ")
		}

		clientServerL3Connectivity := func() {
			By("============= Starting Connectivity Test ============= ")

			By("Getting IPs of each spawned container")
			clientDockerNetworking, err := vm.ContainerInspectNet(helpers.Client)
			ExpectWithOffset(1, err).Should(BeNil(),
				"could not get metadata for container %q", helpers.Client)
			By("client container Docker networking: %s", clientDockerNetworking)

			serverDockerNetworking, err := vm.ContainerInspectNet(helpers.Server)
			ExpectWithOffset(1, err).Should(BeNil(),
				"could not get metadata for container %q", helpers.Server)
			By("server container Docker networking: %s", serverDockerNetworking)

			httpdDockerNetworking, err := vm.ContainerInspectNet(helpers.Httpd1)
			ExpectWithOffset(1, err).Should(BeNil(),
				"could not get metadata for container %q", helpers.Httpd1)
			By("httpd1 container Docker networking: %s", httpdDockerNetworking)

			httpd2DockerNetworking, err := vm.ContainerInspectNet(helpers.Httpd2)
			ExpectWithOffset(1, err).Should(BeNil(),
				"could not get metadata for container %q", helpers.Httpd2)
			By("httpd2 container Docker networking: %s", httpd2DockerNetworking)

			curl1DockerNetworking, err := vm.ContainerInspectNet(curl1ContainerName)
			ExpectWithOffset(1, err).Should(BeNil(),
				"could not get metadata for container %q", curl1ContainerName)
			By("curl1 container Docker networking: %s", curl1DockerNetworking)

			curl2DockerNetworking, err := vm.ContainerInspectNet(curl2ContainerName)
			ExpectWithOffset(1, err).Should(BeNil(),
				"could not get metadata for container %q", curl2ContainerName)
			By("httpd1 container Docker networking: %s", curl2DockerNetworking)

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
					to:          helpers.CurlFail("http://[%s]:80", httpd2DockerNetworking[helpers.IPv6]),
					destination: helpers.Httpd2,
					assert:      BeFalse,
				},
				{
					from:        curl2ContainerName,
					to:          helpers.CurlFail("http://%s:80", httpd2DockerNetworking[helpers.IPv4]),
					destination: helpers.Httpd2,
					assert:      BeFalse,
				},
				{
					from:        helpers.Client,
					to:          helpers.Ping6(serverDockerNetworking[helpers.IPv6]),
					destination: helpers.Server,
					assert:      BeTrue,
				},
				{
					from:        helpers.Client,
					to:          helpers.Ping(serverDockerNetworking[helpers.IPv4]),
					destination: helpers.Server,
					assert:      BeTrue,
				},
				{
					from:        helpers.Client,
					to:          helpers.Netperf(serverDockerNetworking[helpers.IPv6], helpers.TCP_RR),
					destination: helpers.Server,
					assert:      BeTrue,
				},
				{
					from:        helpers.Client,
					to:          helpers.Netperf(serverDockerNetworking[helpers.IPv4], helpers.TCP_RR),
					destination: helpers.Server,
					assert:      BeTrue,
				},
				{
					from:        helpers.Client,
					to:          helpers.Netperf(serverDockerNetworking[helpers.IPv6], helpers.UDP_RR),
					destination: helpers.Server,
					assert:      BeTrue,
				},
				{
					from:        helpers.Client,
					to:          helpers.Netperf(serverDockerNetworking[helpers.IPv4], helpers.UDP_RR),
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

			By("============= Finished Connectivity Test ============= ")
		}

		BeforeEach(func() {
			// TODO: provide map[string]string instead of one string representing KV pair.
			vm.ContainerCreate(helpers.Client, constants.NetperfImage, helpers.CiliumDockerNetwork, "-l id.client")
			vm.ContainerCreate(helpers.Server, constants.NetperfImage, helpers.CiliumDockerNetwork, "-l id.server")
			vm.ContainerCreate(helpers.Httpd1, constants.HttpdImage, helpers.CiliumDockerNetwork, "-l id.httpd")
			vm.ContainerCreate(helpers.Httpd2, constants.HttpdImage, helpers.CiliumDockerNetwork, "-l id.httpd_deny")
			vm.ContainerCreate(curl1ContainerName, constants.NetperfImage, helpers.CiliumDockerNetwork, "-l id.curl")
			vm.ContainerCreate(curl2ContainerName, constants.NetperfImage, helpers.CiliumDockerNetwork, "-l id.curl2")

			vm.PolicyDelAll().ExpectSuccess("cannot delete all policies")

			_, err := vm.PolicyImportAndWait(vm.GetFullPath("ct-test-policy.json"), helpers.HelperTimeout)
			Expect(err).Should(BeNil())

		})

		JustBeforeEach(func() {
			monitorStop = vm.MonitorStart()
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
			vm.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
			Expect(monitorStop()).To(BeNil(), "cannot stop monitor command")
		})

		AfterFailed(func() {
			vm.ReportFailed("cilium policy get")
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
				areEndpointsReady := vm.WaitEndpointsReady()
				Expect(areEndpointsReady).Should(BeTrue(), "Endpoints are not ready after timeout")
				clientServerConnectivity()
			}

			By("Testing Conntrack endpoint configuration option disabled")

			// Delete all L4 policy so we can disable connection tracking
			vm.PolicyDelAll().ExpectSuccess("Policies cannot be deleted")

			for _, endpointToConfigure := range endpointsToConfigure {
				// ConntrackLocal must be disabled as it depends on Conntrack
				err := vm.SetAndWaitForEndpointConfiguration(endpointToConfigure, helpers.OptionConntrackLocal, helpers.OptionDisabled)
				Expect(err).To(BeNil(), "Cannot disable ConntrackLocal for the endpoint %q", endpointToConfigure)
				err = vm.SetAndWaitForEndpointConfiguration(endpointToConfigure, helpers.OptionConntrack, helpers.OptionDisabled)
				Expect(err).To(BeNil(), "Cannot disable ConnTrack for the endpoint %q", endpointToConfigure)
			}

			// Need to add policy that allows communication in both directions.
			_, err = vm.PolicyImportAndWait(
				vm.GetFullPath(CTPolicyConntrackLocalDisabled),
				helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "cannot import %s", CTPolicyConntrackLocalDisabled)

			clientServerL3Connectivity()
		})

	}
}
