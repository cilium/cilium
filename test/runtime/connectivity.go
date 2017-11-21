package RuntimeTest

import (
	"fmt"

	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
)

var _ = Describe("RuntimeConnectivityTest", func() {

	var initialized bool
	var logger *log.Entry
	var docker *helpers.Docker
	var cilium *helpers.Cilium

	initialize := func() {
		if initialized == true {
			return
		}
		logger = log.WithFields(log.Fields{"test": "RuntimeConnectivityTest"})
		logger.Info("Starting")
		docker, cilium = helpers.CreateNewRuntimeHelper(helpers.Runtime, logger)
		cilium.WaitUntilReady(100)
		docker.NetworkCreate(helpers.CiliumDockerNetwork, "")
		initialized = true
	}

	BeforeEach(func() {
		initialize()
		docker.ContainerCreate(helpers.Client, helpers.NetperfImage, helpers.CiliumDockerNetwork, "-l id.client")
		docker.ContainerCreate(helpers.Server, helpers.NetperfImage, helpers.CiliumDockerNetwork, "-l id.server")
		cilium.PolicyDelAll()
		cilium.WaitEndpointsReady()
		err := helpers.WithTimeout(func() bool {
			if data, _ := cilium.GetEndpointsNames(); len(data) < 2 {
				logger.Info("Waiting for endpoints to be ready")
				return false
			}
			return true
		}, "Endpoints are not ready", &helpers.TimeoutConfig{Timeout: 150})
		Expect(err).Should(BeNil())
	}, 150)

	removeContainer := func(containerName string) {
		By(fmt.Sprintf("removing container %s", containerName))
		res := docker.ContainerRm(containerName)
		Expect(res.WasSuccessful()).Should(BeTrue())
	}

	AfterEach(func() {
		removeContainer(helpers.Client)
		removeContainer(helpers.Server)
		return
	})

	It("Test connectivity between containers without policies imported", func() {
		// TODO: this code is duplicated in the next "It" in this file. refactor it into a function.
		// See if we can make the "Filter" strings for getting IPv4 and IPv6 addresses into constants.
		By(fmt.Sprintf("inspecting container %s", helpers.Server))
		serverData := docker.ContainerInspect(helpers.Server)
		serverIP, err := serverData.Filter(fmt.Sprintf("{[0].NetworkSettings.Networks.%s.IPAddress}", helpers.CiliumDockerNetwork))
		Expect(err).Should(BeNil())

		By(fmt.Sprintf("serverIP: %s", serverIP))
		serverIPv6, err := serverData.Filter(fmt.Sprintf("{[0].NetworkSettings.Networks.%s.GlobalIPv6Address}", helpers.CiliumDockerNetwork))
		By(fmt.Sprintf("serverIPv6: %s", serverIPv6))
		Expect(err).Should(BeNil())

		By(fmt.Sprintf("checking %s can ping to %s IPv6", helpers.Client, helpers.Server))
		res := docker.ContainerExec(helpers.Client, helpers.Ping6(serverIPv6.String()))
		res.ExpectSuccess()

		By(fmt.Sprintf("checking %s can ping to %s IPv4", helpers.Client, helpers.Server))
		res = docker.ContainerExec(helpers.Client, helpers.Ping(serverIP.String()))
		res.ExpectSuccess()

		// TODO: remove this hardcoding ; it is not clean. Have command wrappers that take maps of strings.
		By(fmt.Sprintf("netperf to %s from %s IPv6", helpers.Server, helpers.Client))
		cmd := fmt.Sprintf(
			"netperf -c -C -t TCP_SENDFILE -H %s", serverIPv6)

		res = docker.ContainerExec(helpers.Client, cmd)
		res.ExpectSuccess()
	}, 300)

	It("Test connectivity between containers with policy imported", func() {
		policyID, err := cilium.PolicyImport(
			fmt.Sprintf("%s/test.policy", cilium.ManifestsPath()), 150)
		Expect(err).Should(BeNil())
		logger.Debug("New policy created with id '%d'", policyID)

		serverData := docker.ContainerInspect(helpers.Server)
		serverIP, err := serverData.Filter(fmt.Sprintf("{[0].NetworkSettings.Networks.%s.IPAddress}", helpers.CiliumDockerNetwork))
		Expect(err).Should(BeNil())
		By(fmt.Sprintf("serverIP: %s", serverIP))
		serverIPv6, err := serverData.Filter(fmt.Sprintf("{[0].NetworkSettings.Networks.%s.GlobalIPv6Address}", helpers.CiliumDockerNetwork))
		By(fmt.Sprintf("serverIPv6: %s", serverIPv6))
		Expect(err).Should(BeNil())

		By(fmt.Sprintf("%s can ping to %s IPV6", helpers.Client, helpers.Server))
		res := docker.ContainerExec(helpers.Client, helpers.Ping6(serverIPv6.String()))
		res.ExpectSuccess()

		By(fmt.Sprintf("%s can ping to %s IPv4", helpers.Client, helpers.Server))
		res = docker.ContainerExec(helpers.Client, helpers.Ping(serverIP.String()))
		res.ExpectSuccess()

		By(fmt.Sprintf("netperf to %s from %s (should succeed)", helpers.Server, helpers.Client))
		cmd := fmt.Sprintf("netperf -c -C -H %s", serverIP)
		res = docker.ContainerExec(helpers.Client, cmd)

		// TODO: remove this hardcoding ; it is not clean. Have command wrappers that take maps of strings.
		By(fmt.Sprintf("netperf to %s from %s IPv6 with -t TCP_SENDFILE", helpers.Server, helpers.Client))
		cmd = fmt.Sprintf(
			"netperf -c -C -t TCP_SENDFILE -H %s", serverIPv6)

		res = docker.ContainerExec(helpers.Client, cmd)
		res.ExpectSuccess()

		By(fmt.Sprintf("super_netperf to %s from %s (should succeed)", helpers.Server, helpers.Client))
		cmd = fmt.Sprintf("super_netperf 10 -c -C -t TCP_SENDFILE -H %s", serverIP)
		res = docker.ContainerExec(helpers.Client, cmd)
		res.ExpectSuccess()

		By(fmt.Sprintf("ping from %s to %s", helpers.Host, helpers.Server))
		res = docker.Node.Exec(helpers.Ping(serverIP.String()))
		res.ExpectSuccess()
	}, 300)

	It("Test NAT46 connectivity between containers", func() {

		endpoints, err := cilium.GetEndpointsIds()
		Expect(err).Should(BeNil(), "could not get endpoint IDs")

		server, err := docker.ContainerInspectNet(helpers.Server)
		Expect(err).Should(BeNil())
		By(fmt.Sprintf("server: %s", server))

		client, err := docker.ContainerInspectNet(helpers.Client)
		Expect(err).Should(BeNil())
		By(fmt.Sprintf("client: %s", client))

		status := cilium.EndpointSetConfig(endpoints[helpers.Client], "NAT46", helpers.OptionEnabled)
		Expect(status).Should(BeTrue())

		res := docker.ContainerExec(helpers.Client, helpers.Ping6(fmt.Sprintf(
			"::FFFF:%s", server[helpers.IPv4])))

		res.ExpectSuccess()

		res = docker.ContainerExec(helpers.Server,
			helpers.Ping6(fmt.Sprintf("::FFFF:%s", client[helpers.IPv4])))
		res.ExpectFail(fmt.Sprintf("unexpectedly succeeded pinging IPv6 %s from %s", client[helpers.IPv4], helpers.Server))
	})
})

var _ = Describe("RuntimeConntrackTest", func() {

	var initialized bool
	var logger *log.Entry
	var docker *helpers.Docker
	var cilium *helpers.Cilium

	initialize := func() {
		if initialized == true {
			return
		}
		logger = log.WithFields(log.Fields{"test": "RunConntrackTest"})
		logger.Info("Starting")
		docker, cilium = helpers.CreateNewRuntimeHelper(helpers.Runtime, logger)
		docker.NetworkCreate(helpers.CiliumDockerNetwork, "")
		initialized = true
	}

	clientServerConnectivity := func() {
		cliIP, err := docker.ContainerInspectNet(helpers.Client)
		Expect(err).Should(BeNil(), fmt.Sprintf("could not get metadata for container %q", helpers.Client))
		By(fmt.Sprintf("cliIP: %s", cliIP))

		srvIP, err := docker.ContainerInspectNet(helpers.Server)
		Expect(err).Should(BeNil(), fmt.Sprintf("could not get metadata for container %q", helpers.Server))
		By(fmt.Sprintf("srvIP: %s", srvIP))

		By(fmt.Sprintf("%s pinging %s IPv6", helpers.Client, helpers.Server))
		res := docker.ContainerExec(helpers.Client, helpers.Ping6(srvIP[helpers.IPv6]))
		Expect(res.WasSuccessful()).Should(BeTrue(), fmt.Sprintf(
			fmt.Sprintf("%s cannot ping to % %s", helpers.Client, helpers.Server, srvIP[helpers.IPv6])))

		By(fmt.Sprintf("%s pinging %s IPv4", helpers.Client, helpers.Server))
		res = docker.ContainerExec(helpers.Client, helpers.Ping(srvIP[helpers.IPv4]))
		Expect(res.WasSuccessful()).Should(BeTrue(), fmt.Sprintf(
			"%s cannot ping server %s", helpers.Client, srvIP[helpers.IPv4]))

		// TODO: remove this hardcoding ; it is not clean. Have command wrappers that take maps of strings.
		By(fmt.Sprintf("%s netcat to port 777 IPv6", helpers.Client))
		res = docker.ContainerExec(helpers.Client, fmt.Sprintf("nc -w 4 %s 777", srvIP[helpers.IPv6]))
		Expect(res.WasSuccessful()).Should(BeFalse(), fmt.Sprintf(
			"%s can connect to %s:777. Should fail", helpers.Client, srvIP[helpers.IPv6]))

		// TODO: remove this hardcoding ; it is not clean. Have command wrappers that take maps of strings.
		By(fmt.Sprintf("%s netcat to port 777 IPv4", helpers.Client))
		res = docker.ContainerExec(helpers.Client, fmt.Sprintf("nc -w 4 %s 777", srvIP[helpers.IPv4]))
		Expect(res.WasSuccessful()).Should(BeFalse(), fmt.Sprintf(
			"%s can connect to %s:777; should fail", helpers.Client, srvIP[helpers.IPv4]))

		By(fmt.Sprintf("%s netperf to %s IPv6", helpers.Client, helpers.Server))
		res = docker.ContainerExec(helpers.Client, helpers.Netperf(srvIP[helpers.IPv6], helpers.TCP_RR))
		Expect(res.WasSuccessful()).Should(BeTrue(), fmt.Sprintf(
			"%s cannot netperf to %s %s", helpers.Client, helpers.Server, srvIP[helpers.IPv6]))

		By(fmt.Sprintf("%s netperf to %s IPv4", helpers.Client, helpers.Server))
		res = docker.ContainerExec(helpers.Client, helpers.Netperf(srvIP[helpers.IPv4], helpers.TCP_RR))
		Expect(res.WasSuccessful()).Should(BeTrue(), fmt.Sprintf(
			"%s cannot netperf to %s %s", helpers.Client, helpers.Server, srvIP[helpers.IPv4]))

		By(fmt.Sprintf("%s UDP netperf to %s IPv6", helpers.Client, helpers.Server))
		res = docker.ContainerExec(helpers.Client, helpers.Netperf(srvIP[helpers.IPv6], helpers.UDP_RR))
		Expect(res.WasSuccessful()).Should(BeTrue(), fmt.Sprintf(
			"%s cannot netperf to %s %s", helpers.Client, helpers.Server, srvIP[helpers.IPv6]))

		By(fmt.Sprintf("%s UDP netperf to %s IPv4", helpers.Client, helpers.Server))
		res = docker.ContainerExec(helpers.Client, helpers.Netperf(srvIP[helpers.IPv4], helpers.UDP_RR))
		Expect(res.WasSuccessful()).Should(BeTrue(), fmt.Sprintf(
			"%s cannot netperf to %s %s", helpers.Client, helpers.Server, srvIP[helpers.IPv4]))

		By(fmt.Sprintf("ping from %s to %s IPv6", helpers.Host, helpers.Server))
		res = docker.Node.Exec(helpers.Ping6(srvIP[helpers.IPv6]))
		Expect(res.WasSuccessful()).Should(BeTrue(), fmt.Sprintf("%s cannot ping %s", helpers.Host, helpers.Server))

		By(fmt.Sprintf("ping from %s to %s IPv4", helpers.Host, helpers.Server))
		res = docker.Node.Exec(helpers.Ping(srvIP[helpers.IPv4]))
		Expect(res.WasSuccessful()).Should(BeTrue(), fmt.Sprintf("%s cannot ping %s", helpers.Host, helpers.Server))

		By(fmt.Sprintf("ping from %s to %s IPv6", helpers.Server, helpers.Client))
		res = docker.ContainerExec(helpers.Server, helpers.Ping6(cliIP[helpers.IPv6]))
		Expect(res.WasSuccessful()).Should(BeTrue(), fmt.Sprintf(
			"%s cannot ping to %s %s", helpers.Server, helpers.Client, cliIP[helpers.IPv6]))

		By(fmt.Sprintf("ping from %s to %s IPv4", helpers.Server, helpers.Client))
		res = docker.ContainerExec(helpers.Server, helpers.Ping(cliIP[helpers.IPv4]))
		Expect(res.WasSuccessful()).Should(BeTrue(), fmt.Sprintf(
			"%s cannot ping to %s %s", helpers.Server, helpers.Client, cliIP[helpers.IPv4]))
	}

	BeforeEach(func() {
		initialize()
		// TODO: provide map[string]string instead of one string representing KV pair.
		docker.ContainerCreate(helpers.Client, helpers.NetperfImage, helpers.CiliumDockerNetwork, "-l id.client")
		docker.ContainerCreate(helpers.Server, helpers.NetperfImage, helpers.CiliumDockerNetwork, "-l id.server")
		cilium.PolicyDelAll()
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			cilium.ReportFailed()
		}

		docker.ContainerRm(helpers.Server)
		docker.ContainerRm(helpers.Client)
	})
	It("Conntrack disabled", func() {
		endpoints, err := cilium.GetEndpointsIds()
		Expect(err).Should(BeNil(), "could not get endpoints IDs")

		status := cilium.EndpointSetConfig(endpoints[helpers.Server], helpers.OptionConntrack, helpers.OptionDisabled)
		Expect(status).Should(BeTrue(), fmt.Sprintf("could not set %s=%s on endpoint %q", helpers.OptionConntrack, helpers.OptionDisabled, helpers.Server))

		status = cilium.EndpointSetConfig(endpoints[helpers.Client], helpers.OptionConntrack, helpers.OptionDisabled)
		Expect(status).Should(BeTrue(), fmt.Sprintf("could not set %s=%s on endpoint %q", helpers.OptionConntrack, helpers.OptionDisabled, helpers.Client))

		clientServerConnectivity()
	})

	It("ConntrackLocal disabled", func() {
		endpoints, err := cilium.GetEndpointsIds()
		Expect(err).Should(BeNil(), "could not get endpoint IDs")

		status := cilium.EndpointSetConfig(endpoints[helpers.Server], helpers.OptionConntrackLocal, helpers.OptionDisabled)
		Expect(status).Should(BeTrue(), fmt.Sprintf("could not set %s=%s on endpoint %q", helpers.OptionConntrackLocal, helpers.OptionDisabled, helpers.Server))

		status = cilium.EndpointSetConfig(endpoints[helpers.Client], helpers.OptionConntrackLocal, helpers.OptionDisabled)
		Expect(status).Should(BeTrue(), fmt.Sprintf("could not set %s=%s on endpoint %q", helpers.OptionConntrackLocal, helpers.OptionDisabled, helpers.Client))

		clientServerConnectivity()
	})

	It("ConntrackLocal Enabled", func() {
		endpoints, err := cilium.GetEndpointsIds()
		Expect(err).Should(BeNil(), "could not get endpoint IDs")

		status := cilium.EndpointSetConfig(endpoints[helpers.Server], helpers.OptionConntrackLocal, helpers.OptionEnabled)
		Expect(status).Should(BeTrue(), fmt.Sprintf("could not set %s=%s on endpoint %q", helpers.OptionConntrackLocal, helpers.OptionEnabled, helpers.Server))

		status = cilium.EndpointSetConfig(endpoints[helpers.Client], helpers.OptionConntrackLocal, helpers.OptionEnabled)
		Expect(status).Should(BeTrue(), fmt.Sprintf("could not set %s=%s on endpoint %q", helpers.OptionConntrackLocal, helpers.OptionEnabled, helpers.Client))

		clientServerConnectivity()
	})

})
