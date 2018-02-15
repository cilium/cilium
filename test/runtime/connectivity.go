package RuntimeTest

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("RuntimeValidatedConnectivityTest", func() {

	var once sync.Once
	var logger *logrus.Entry
	var vm *helpers.SSHMeta

	initialize := func() {
		logger = log.WithFields(logrus.Fields{"test": "RuntimeConnectivityTest"})
		logger.Info("Starting")
		vm = helpers.CreateNewRuntimeHelper(helpers.Runtime, logger)
	}

	BeforeEach(func() {
		once.Do(initialize)
	})

	removeContainer := func(containerName string) {
		By(fmt.Sprintf("removing container %s", containerName))
		res := vm.ContainerRm(containerName)
		Expect(res.WasSuccessful()).Should(BeTrue())
	}

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			vm.ReportFailed()
		}
		vm.PolicyDelAll().ExpectSuccess("Policies cannot be deleted")
		return
	})

	Context("Basic Connectivity test", func() {

		BeforeEach(func() {
			vm.ContainerCreate(helpers.Client, helpers.NetperfImage, helpers.CiliumDockerNetwork, "-l id.client")
			vm.ContainerCreate(helpers.Server, helpers.NetperfImage, helpers.CiliumDockerNetwork, "-l id.server")
			vm.PolicyDelAll()
			vm.WaitEndpointsReady()
			err := helpers.WithTimeout(func() bool {
				if data, _ := vm.GetEndpointsNames(); len(data) < 2 {
					logger.Info("Waiting for endpoints to be ready")
					return false
				}
				return true
			}, "Endpoints are not ready", &helpers.TimeoutConfig{Timeout: 150})
			Expect(err).Should(BeNil())
		}, 150)

		AfterEach(func() {
			removeContainer(helpers.Client)
			removeContainer(helpers.Server)
			return
		})

		It("Test connectivity between containers without policies imported", func() {
			// TODO: this code is duplicated in the next "It" in this file. refactor it into a function.
			// See if we can make the "Filter" strings for getting IPv4 and IPv6 addresses into constants.
			By(fmt.Sprintf("inspecting container %s", helpers.Server))
			serverData := vm.ContainerInspect(helpers.Server)
			serverIP, err := serverData.Filter(fmt.Sprintf("{[0].NetworkSettings.Networks.%s.IPAddress}", helpers.CiliumDockerNetwork))
			Expect(err).Should(BeNil())

			By(fmt.Sprintf("serverIP: %s", serverIP))
			serverIPv6, err := serverData.Filter(fmt.Sprintf("{[0].NetworkSettings.Networks.%s.GlobalIPv6Address}", helpers.CiliumDockerNetwork))
			By(fmt.Sprintf("serverIPv6: %s", serverIPv6))
			Expect(err).Should(BeNil())

			By(fmt.Sprintf("checking %s can ping to %s IPv6", helpers.Client, helpers.Server))
			res := vm.ContainerExec(helpers.Client, helpers.Ping6(serverIPv6.String()))
			res.ExpectSuccess()

			By(fmt.Sprintf("checking %s can ping to %s IPv4", helpers.Client, helpers.Server))
			res = vm.ContainerExec(helpers.Client, helpers.Ping(serverIP.String()))
			res.ExpectSuccess()

			// TODO: remove this hardcoding ; it is not clean. Have command wrappers that take maps of strings.
			By(fmt.Sprintf("netperf to %s from %s IPv6", helpers.Server, helpers.Client))
			cmd := fmt.Sprintf(
				"netperf -c -C -t TCP_SENDFILE -H %s", serverIPv6)

			res = vm.ContainerExec(helpers.Client, cmd)
			res.ExpectSuccess()
		}, 300)

		It("Test connectivity between containers with policy imported", func() {
			policyID, err := vm.PolicyImportAndWait(
				fmt.Sprintf("%s/test.policy", vm.ManifestsPath()), 150)
			Expect(err).Should(BeNil())
			logger.Debug("New policy created with id '%d'", policyID)

			serverData := vm.ContainerInspect(helpers.Server)
			serverIP, err := serverData.Filter(fmt.Sprintf("{[0].NetworkSettings.Networks.%s.IPAddress}", helpers.CiliumDockerNetwork))
			Expect(err).Should(BeNil())
			By(fmt.Sprintf("serverIP: %s", serverIP))
			serverIPv6, err := serverData.Filter(fmt.Sprintf("{[0].NetworkSettings.Networks.%s.GlobalIPv6Address}", helpers.CiliumDockerNetwork))
			By(fmt.Sprintf("serverIPv6: %s", serverIPv6))
			Expect(err).Should(BeNil())

			By(fmt.Sprintf("%s can ping to %s IPV6", helpers.Client, helpers.Server))
			res := vm.ContainerExec(helpers.Client, helpers.Ping6(serverIPv6.String()))
			res.ExpectSuccess()

			By(fmt.Sprintf("%s can ping to %s IPv4", helpers.Client, helpers.Server))
			res = vm.ContainerExec(helpers.Client, helpers.Ping(serverIP.String()))
			res.ExpectSuccess()

			By(fmt.Sprintf("netperf to %s from %s (should succeed)", helpers.Server, helpers.Client))
			cmd := fmt.Sprintf("netperf -c -C -H %s", serverIP)
			res = vm.ContainerExec(helpers.Client, cmd)

			// TODO: remove this hardcoding ; it is not clean. Have command wrappers that take maps of strings.
			By(fmt.Sprintf("netperf to %s from %s IPv6 with -t TCP_SENDFILE", helpers.Server, helpers.Client))
			cmd = fmt.Sprintf(
				"netperf -c -C -t TCP_SENDFILE -H %s", serverIPv6)

			res = vm.ContainerExec(helpers.Client, cmd)
			res.ExpectSuccess()

			By(fmt.Sprintf("super_netperf to %s from %s (should succeed)", helpers.Server, helpers.Client))
			cmd = fmt.Sprintf("super_netperf 10 -c -C -t TCP_SENDFILE -H %s", serverIP)
			res = vm.ContainerExec(helpers.Client, cmd)
			res.ExpectSuccess()

			By(fmt.Sprintf("ping from %s to %s", helpers.Host, helpers.Server))
			res = vm.Exec(helpers.Ping(serverIP.String()))
			res.ExpectSuccess()
		}, 300)

		It("Test NAT46 connectivity between containers", func() {

			endpoints, err := vm.GetEndpointsIds()
			Expect(err).Should(BeNil(), "could not get endpoint IDs")

			server, err := vm.ContainerInspectNet(helpers.Server)
			Expect(err).Should(BeNil())
			By(fmt.Sprintf("server: %s", server))

			client, err := vm.ContainerInspectNet(helpers.Client)
			Expect(err).Should(BeNil())
			By(fmt.Sprintf("client: %s", client))

			status := vm.EndpointSetConfig(endpoints[helpers.Client], "NAT46", helpers.OptionEnabled)
			Expect(status).Should(BeTrue())

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
			cniPlugin   = "/opt/cni/bin/cilium-cni"
			dockerImage = "busybox:latest"
			cniServer   = "cni-server"
			cniClient   = "cni-client"
		)
		var tmpDir *helpers.CmdRes

		BeforeEach(func() {
			vm.PolicyDelAll().ExpectSuccess("Policies cannot be deleted")
		})

		AfterEach(func() {
			vm.ContainerRm(cniServer)
			vm.ContainerRm(cniClient)
			vm.Exec("docker rm -f $(docker ps | grep busybox:latest | awk '{print $1}')")
		})

		runCNIContainer := func(name string, label string) {
			res := vm.Exec(fmt.Sprintf("docker run -t -d --net=none -l %s %s", label, dockerImage))
			res.ExpectSuccess()
			containerID := res.SingleOut()

			pid := vm.Exec(fmt.Sprintf("docker inspect -f '{{ .State.Pid }}' %s", containerID))
			pid.ExpectSuccess()
			netnspath := fmt.Sprintf("/proc/%s/ns/net", pid.SingleOut())

			res = vm.Exec(fmt.Sprintf(
				"sudo -E PATH=$PATH:/opt/cni/bin -E CNI_PATH=%[1]s/bin %[1]s/cni/scripts/exec-plugins.sh add %s %s",
				tmpDir.SingleOut(), containerID, netnspath))
			res.ExpectSuccess("CNI exec-plugins did not work correctly '%s'", res.CombineOutput().String())

			res = vm.ContainerCreate(
				name, helpers.NetperfImage,
				fmt.Sprintf("container:%s", containerID), fmt.Sprintf("-l %s", label))
			res.ExpectSuccess("Container %s cannot be created", name)
		}

		It("Basic connectivity test", func() {
			filename := "10-cilium-cni.conf"
			tmpDir = vm.Exec("mktemp -d")
			tmpDir.ExpectSuccess("TMP folder cannot be created %s", tmpDir.Output())
			defer vm.Exec(fmt.Sprintf("rm -rf %s", tmpDir.Output()))
			netDPath := filepath.Join(tmpDir.SingleOut(), "net.d")
			vm.Exec(fmt.Sprintf("mkdir -p %s", netDPath)).ExpectSuccess()

			cniConf := `{"name": "cilium",
				"type": "cilium-cni",
				"mtu": 1450}`

			err := helpers.RenderTemplateToFile(filename, cniConf, os.ModePerm)
			Expect(err).To(BeNil())

			cmd := vm.Exec(fmt.Sprintf("cat %s > %s/%s",
				helpers.GetFilePath(filename), netDPath, filename))
			cmd.ExpectSuccess()
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
})

var _ = Describe("RuntimeValidatedConntrackTest", func() {
	var logger *logrus.Entry
	var vm *helpers.SSHMeta
	var once sync.Once

	var curl1ContainerName = "curl"
	var curl2ContainerName = "curl2"

	initialize := func() {
		logger = log.WithFields(logrus.Fields{"test": "RunConntrackTest"})
		logger.Info("Starting")
		vm = helpers.CreateNewRuntimeHelper(helpers.Runtime, logger)

		res := vm.SetPolicyEnforcement(helpers.PolicyEnforcementAlways)
		res.ExpectSuccess(fmt.Sprintf("Unable to set PolicyEnforcement to %s", helpers.PolicyEnforcementAlways))
	}

	clientServerConnectivity := func(bidirectional bool) {

		By("Getting IPs of each spawned container")
		clientDockerNetworking, err := vm.ContainerInspectNet(helpers.Client)
		Expect(err).Should(BeNil(), fmt.Sprintf("could not get metadata for container %q", helpers.Client))
		By(fmt.Sprintf("client container Docker networking: %s", clientDockerNetworking))

		serverDockerNetworking, err := vm.ContainerInspectNet(helpers.Server)
		Expect(err).Should(BeNil(), fmt.Sprintf("could not get metadata for container %q", helpers.Server))
		By(fmt.Sprintf("server container Docker networking: %s", serverDockerNetworking))

		httpdDockerNetworking, err := vm.ContainerInspectNet(helpers.Httpd1)
		Expect(err).Should(BeNil(), fmt.Sprintf("could not get metadata for container %q", helpers.Httpd1))
		By(fmt.Sprintf("httpd1 container Docker networking: %s", httpdDockerNetworking))

		httpd2DockerNetworking, err := vm.ContainerInspectNet(helpers.Httpd2)
		Expect(err).Should(BeNil(), fmt.Sprintf("could not get metadata for container %q", helpers.Httpd2))
		By(fmt.Sprintf("httpd2 container Docker networking: %s", httpd2DockerNetworking))

		curl1DockerNetworking, err := vm.ContainerInspectNet(curl1ContainerName)
		Expect(err).Should(BeNil(), fmt.Sprintf("could not get metadata for container %q", curl1ContainerName))
		By(fmt.Sprintf("curl1 container Docker networking: %s", curl1DockerNetworking))

		curl2DockerNetworking, err := vm.ContainerInspectNet(curl2ContainerName)
		Expect(err).Should(BeNil(), fmt.Sprintf("could not get metadata for container %q", curl2ContainerName))
		By(fmt.Sprintf("httpd1 container Docker networking: %s", curl2DockerNetworking))

		// TODO - would be cool if we found a way to collapse this into a function with parameters; lots of boilerplate here.
		By(fmt.Sprintf("container %s curl on port 80 %s IPv6 (should work)", curl1ContainerName, helpers.Httpd1))
		res := vm.ContainerExec(curl1ContainerName, helpers.CurlFail(fmt.Sprintf("[%s]:80", httpdDockerNetworking[helpers.IPv6])))
		Expect(res.WasSuccessful()).Should(BeTrue(),
			fmt.Sprintf("container %s could not reach %s on port 80", curl1ContainerName, helpers.Httpd1))

		By(fmt.Sprintf("container %s curl on port 80 %s IPv4 (should work)", curl1ContainerName, helpers.Httpd1))
		res = vm.ContainerExec(curl1ContainerName, helpers.CurlFail(fmt.Sprintf("%s:80", httpdDockerNetworking[helpers.IPv4])))
		Expect(res.WasSuccessful()).Should(BeTrue(),
			fmt.Sprintf("container %s could not reach %s on port 80", curl1ContainerName, helpers.Httpd1))

		By(fmt.Sprintf("container %s curl on port 80 %s IPv6 (should NOT work)", curl2ContainerName, helpers.Httpd1))
		res = vm.ContainerExec(curl2ContainerName, helpers.CurlFail(fmt.Sprintf("[%s]:80", httpdDockerNetworking[helpers.IPv6])))
		Expect(res.WasSuccessful()).Should(BeFalse(),
			fmt.Sprintf("container %s unexpectedly reached %s on port 80", curl2ContainerName, helpers.Httpd1))

		By(fmt.Sprintf("container %s curl on port 80 %s IPv4 (should NOT work)", curl2ContainerName, helpers.Httpd1))
		res = vm.ContainerExec(curl2ContainerName, helpers.CurlFail(fmt.Sprintf("%s:80", httpdDockerNetworking[helpers.IPv4])))
		Expect(res.WasSuccessful()).Should(BeFalse(),
			fmt.Sprintf("container %s unexpectedly reached %s on port 80", curl2ContainerName, helpers.Httpd1))

		By(fmt.Sprintf("container %s curl on port 80 %s IPv6 (should work)", curl1ContainerName, helpers.Httpd2))
		res = vm.ContainerExec(curl1ContainerName, helpers.CurlFail(fmt.Sprintf("[%s]:80", httpd2DockerNetworking[helpers.IPv6])))
		Expect(res.WasSuccessful()).Should(BeFalse(),
			fmt.Sprintf("container %s unexpectedly reached %s on port 80", curl1ContainerName, helpers.Httpd2))

		By(fmt.Sprintf("container %s curl on port 80 %s IPv6 (should work)", curl1ContainerName, helpers.Httpd2))
		res = vm.ContainerExec(curl1ContainerName, helpers.CurlFail(fmt.Sprintf("[%s]:80", httpd2DockerNetworking[helpers.IPv4])))
		Expect(res.WasSuccessful()).Should(BeFalse(),
			fmt.Sprintf("container %s unexpectedly reached %s on port 80", curl1ContainerName, helpers.Httpd2))

		By(fmt.Sprintf("container %s pinging %s IPv6 (should work)", helpers.Client, helpers.Server))
		res = vm.ContainerExec(helpers.Client, helpers.Ping6(serverDockerNetworking[helpers.IPv6]))
		Expect(res.WasSuccessful()).Should(BeTrue(), fmt.Sprintf(
			fmt.Sprintf("container %s cannot ping to %s %s", helpers.Client, helpers.Server, serverDockerNetworking[helpers.IPv6])))

		By(fmt.Sprintf("container %s pinging %s IPv4 (should work)", helpers.Client, helpers.Server))
		res = vm.ContainerExec(helpers.Client, helpers.Ping(serverDockerNetworking[helpers.IPv4]))
		Expect(res.WasSuccessful()).Should(BeTrue(), fmt.Sprintf(
			"%s cannot ping server %s", helpers.Client, serverDockerNetworking[helpers.IPv4]))

		By(fmt.Sprintf("container %s pinging %s IPv6 (should work)", helpers.Host, helpers.Server))
		res = vm.Exec(helpers.Ping6(serverDockerNetworking[helpers.IPv6]))
		Expect(res.WasSuccessful()).Should(BeTrue(), fmt.Sprintf("%s cannot ping %s", helpers.Host, helpers.Server))

		By(fmt.Sprintf("container %s pinging %s IPv4 (should work)", helpers.Host, helpers.Server))
		res = vm.Exec(helpers.Ping(serverDockerNetworking[helpers.IPv4]))
		Expect(res.WasSuccessful()).Should(BeTrue(), fmt.Sprintf("%s cannot ping %s", helpers.Host, helpers.Server))

		if bidirectional {

			By("Testing bidirectional connectivity from client to server")

			By(fmt.Sprintf("container %s pinging %s IPv6 (should NOT work)", helpers.Server, helpers.Client))
			res = vm.ContainerExec(helpers.Server, helpers.Ping6(clientDockerNetworking[helpers.IPv6]))
			Expect(res.WasSuccessful()).Should(BeFalse(), fmt.Sprintf(
				"container %s unexpectedly was able to ping to %s %s", helpers.Server, helpers.Client, clientDockerNetworking[helpers.IPv6]))

			By(fmt.Sprintf("container %s pinging %s IPv4 (should NOT work)", helpers.Server, helpers.Client))
			res = vm.ContainerExec(helpers.Server, helpers.Ping(clientDockerNetworking[helpers.IPv4]))
			Expect(res.WasSuccessful()).Should(BeFalse(), fmt.Sprintf(
				"%s was unexpectedly able to ping to %s %s", helpers.Server, helpers.Client, clientDockerNetworking[helpers.IPv4]))

		}

		// TODO: remove this hardcoding ; it is not clean. Have command wrappers that take maps of strings.
		By(fmt.Sprintf("container %s netcat to port 777 IPv6 (should NOT work)", helpers.Client))
		res = vm.ContainerExec(helpers.Client, fmt.Sprintf("nc -w 4 %s 777", serverDockerNetworking[helpers.IPv6]))
		Expect(res.WasSuccessful()).Should(BeFalse(), fmt.Sprintf(
			"container %s can connect to %s:777. should fail", helpers.Client, serverDockerNetworking[helpers.IPv6]))

		// TODO: remove this hardcoding ; it is not clean. Have command wrappers that take maps of strings.
		By(fmt.Sprintf("%s netcat to port 777 IPv4 (should NOT work)", helpers.Client))
		res = vm.ContainerExec(helpers.Client, fmt.Sprintf("nc -w 4 %s 777", serverDockerNetworking[helpers.IPv4]))
		Expect(res.WasSuccessful()).Should(BeFalse(), fmt.Sprintf(
			"container %s can connect to %s:777; should fail", helpers.Client, serverDockerNetworking[helpers.IPv4]))

		By(fmt.Sprintf("%s netperf to %s IPv6 (should work)", helpers.Client, helpers.Server))
		res = vm.ContainerExec(helpers.Client, helpers.Netperf(serverDockerNetworking[helpers.IPv6], helpers.TCP_RR))
		Expect(res.WasSuccessful()).Should(BeTrue(), fmt.Sprintf(
			"container %s cannot netperf to %s %s", helpers.Client, helpers.Server, serverDockerNetworking[helpers.IPv6]))

		By(fmt.Sprintf("container %s netperf to %s IPv4 (should work)", helpers.Client, helpers.Server))
		res = vm.ContainerExec(helpers.Client, helpers.Netperf(serverDockerNetworking[helpers.IPv4], helpers.TCP_RR))
		Expect(res.WasSuccessful()).Should(BeTrue(), fmt.Sprintf(
			"container %s cannot netperf to %s %s", helpers.Client, helpers.Server, serverDockerNetworking[helpers.IPv4]))

		By(fmt.Sprintf("container %s UDP netperf to %s IPv6 (should work)", helpers.Client, helpers.Server))
		res = vm.ContainerExec(helpers.Client, helpers.Netperf(serverDockerNetworking[helpers.IPv6], helpers.UDP_RR))
		Expect(res.WasSuccessful()).Should(BeTrue(), fmt.Sprintf(
			"container %s cannot netperf to %s %s", helpers.Client, helpers.Server, serverDockerNetworking[helpers.IPv6]))

		By(fmt.Sprintf("container %s UDP netperf to %s IPv4 (should work)", helpers.Client, helpers.Server))
		res = vm.ContainerExec(helpers.Client, helpers.Netperf(serverDockerNetworking[helpers.IPv4], helpers.UDP_RR))
		Expect(res.WasSuccessful()).Should(BeTrue(), fmt.Sprintf(
			"container %s cannot netperf to %s %s", helpers.Client, helpers.Server, serverDockerNetworking[helpers.IPv4]))

	}

	BeforeEach(func() {
		once.Do(initialize)

		// TODO: provide map[string]string instead of one string representing KV pair.
		vm.ContainerCreate(helpers.Client, helpers.NetperfImage, helpers.CiliumDockerNetwork, "-l id.client")
		vm.ContainerCreate(helpers.Server, helpers.NetperfImage, helpers.CiliumDockerNetwork, "-l id.server")
		vm.ContainerCreate(helpers.Httpd1, helpers.HttpdImage, helpers.CiliumDockerNetwork, "-l id.httpd")
		vm.ContainerCreate(helpers.Httpd2, helpers.HttpdImage, helpers.CiliumDockerNetwork, "-l id.httpd_deny")
		vm.ContainerCreate(curl1ContainerName, helpers.NetperfImage, helpers.CiliumDockerNetwork, "-l id.curl")
		vm.ContainerCreate(curl2ContainerName, helpers.NetperfImage, helpers.CiliumDockerNetwork, "-l id.curl2")

		vm.PolicyDelAll()

		_, err := vm.PolicyImportAndWait(vm.GetFullPath("ct-test-policy.json"), helpers.HelperTimeout)
		Expect(err).Should(BeNil())

	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			vm.ReportFailed()
		}

		containersToRm := []string{helpers.Client, helpers.Server, helpers.Httpd1, helpers.Httpd2, curl1ContainerName, curl2ContainerName}
		for _, containerToRm := range containersToRm {
			vm.ContainerRm(containerToRm)
		}
	})

	It("Conntrack-related configuration options for endpoints", func() {

		By("ConntrackLocal configuration option disabled for each endpoint")
		endpoints, err := vm.GetEndpointsIds()
		Expect(err).Should(BeNil(), "could not get endpoint IDs")

		conntrackOptionModes := []string{helpers.OptionDisabled, helpers.OptionEnabled}
		for _, conntrackOptionMode := range conntrackOptionModes {
			By(fmt.Sprintf("Testing ConntrackLocal endpoint configuration option: %s", conntrackOptionMode))
			status := vm.EndpointSetConfig(endpoints[helpers.Server], helpers.OptionConntrackLocal, conntrackOptionMode)
			Expect(status).Should(BeTrue(), fmt.Sprintf("could not set %s=%s on endpoint %q", helpers.OptionConntrackLocal, helpers.OptionDisabled, helpers.Server))

			status = vm.EndpointSetConfig(endpoints[helpers.Client], helpers.OptionConntrackLocal, conntrackOptionMode)
			Expect(status).Should(BeTrue(), fmt.Sprintf("could not set %s=%s on endpoint %q", helpers.OptionConntrackLocal, helpers.OptionDisabled, helpers.Client))

			clientServerConnectivity(true)
		}

		By("Testing Conntrack endpoint configuration option disabled")

		status := vm.EndpointSetConfig(endpoints[helpers.Server], helpers.OptionConntrack, helpers.OptionDisabled)
		Expect(status).Should(BeTrue(), fmt.Sprintf("could not set %s=%s on endpoint %q", helpers.OptionConntrack, helpers.OptionDisabled, helpers.Server))

		status = vm.EndpointSetConfig(endpoints[helpers.Client], helpers.OptionConntrack, helpers.OptionDisabled)
		Expect(status).Should(BeTrue(), fmt.Sprintf("could not set %s=%s on endpoint %q", helpers.OptionConntrack, helpers.OptionDisabled, helpers.Client))

		clientServerConnectivity(false)
	})

})
