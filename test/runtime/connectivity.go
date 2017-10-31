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
	var networkName string = "cilium-net"

	var netperfImage string = "tgraf/netperf"
	var logger *log.Entry
	var docker *helpers.Docker
	var cilium *helpers.Cilium

	initialize := func() {
		if initialized == true {
			return
		}
		logger = log.WithFields(log.Fields{"test": "RuntimeConnectivityTest"})
		logger.Info("Starting")
		docker, cilium = helpers.CreateNewRuntimeHelper("runtime", logger)
		cilium.WaitUntilReady(100)
		docker.NetworkCreate(networkName, "")
		initialized = true
	}

	BeforeEach(func() {
		initialize()
		docker.ContainerCreate("client", netperfImage, networkName, "-l id.client")
		docker.ContainerCreate("server", netperfImage, networkName, "-l id.server")
		cilium.Exec("policy delete --all")
		cilium.EndpointWaitUntilReady()
		err := helpers.WithTimeout(func() bool {
			if data, _ := cilium.GetEndpointsNames(); len(data) < 2 {
				logger.Info("Waiting for endpoints to be ready")
				return false
			}
			return true
		}, "Endpoints are not ready", &helpers.TimeoutConfig{Timeout: 150})
		Expect(err).Should(BeNil())
	}, 150)

	AfterEach(func() {
		docker.ContainerRm("client")
		docker.ContainerRm("server")
		return
	})

	It("Test containers connectivity without policy", func() {
		serverData := docker.ContainerInspect("server")
		serverIP, err := serverData.Filter("{[0].NetworkSettings.Networks.cilium-net.IPAddress}")
		Expect(err).Should(BeNil())
		serverIPv6, err := serverData.Filter("{[0].NetworkSettings.Networks.cilium-net.GlobalIPv6Address}")
		Expect(err).Should(BeNil())

		By("Client can ping to server IPV6")
		res := docker.ContainerExec("client", fmt.Sprintf("ping6 -c 4 %s", serverIPv6))
		Expect(res.WasSuccessful()).Should(BeTrue())

		By("Client can ping to server Ipv4")
		res = docker.ContainerExec("client", fmt.Sprintf("ping -c 5 %s", serverIP))
		Expect(res.WasSuccessful()).Should(BeTrue())

		By("Netperf to server from client IPv6")
		cmd := fmt.Sprintf(
			"netperf -c -C -t TCP_SENDFILE -H %s", serverIPv6)
		res = docker.ContainerExec("client", cmd)
		Expect(res.WasSuccessful()).Should(BeTrue())
	}, 300)

	It("Test containers connectivity WITH policy", func() {
		policyID, _ := cilium.PolicyImport(
			fmt.Sprintf("%s/test.policy", cilium.ManifestsPath()), 150)
		logger.Debug("New policy created with id '%d'", policyID)

		serverData := docker.ContainerInspect("server")
		serverIP, err := serverData.Filter("{[0].NetworkSettings.Networks.cilium-net.IPAddress}")
		Expect(err).Should(BeNil())
		serverIPv6, err := serverData.Filter("{[0].NetworkSettings.Networks.cilium-net.GlobalIPv6Address}")
		Expect(err).Should(BeNil())

		By("Client can ping to server IPV6")
		res := docker.ContainerExec("client", fmt.Sprintf("ping6 -c 4 %s", serverIPv6))
		Expect(res.WasSuccessful()).Should(BeTrue())

		By("Client can ping to server Ipv4")
		res = docker.ContainerExec("client", fmt.Sprintf("ping -c 5 %s", serverIP))
		Expect(res.WasSuccessful()).Should(BeTrue())

		By("Netperf to server from client IPv6")
		cmd := fmt.Sprintf(
			"netperf -c -C -t TCP_SENDFILE -H %s", serverIPv6)
		res = docker.ContainerExec("client", cmd)
		Expect(res.WasSuccessful()).Should(BeTrue())

		By("Ping from host to server")
		res = docker.Node.Exec(fmt.Sprintf("ping -c 4 %s", serverIP))
		Expect(res.WasSuccessful()).Should(BeTrue())
	}, 300)

	It("Test containers NAT46 connectivity ", func() {

		endpoints, err := cilium.GetEndpointsIds()
		Expect(err).Should(BeNil(), "Couldn't get endpoints IDS")

		server, err := docker.ContainerInspectNet("server")
		Expect(err).Should(BeNil())

		client, err := docker.ContainerInspectNet("client")
		Expect(err).Should(BeNil())

		status := cilium.EndpointSetConfig(endpoints["client"], "NAT46", "Enabled")
		Expect(status).Should(BeTrue())

		res := docker.ContainerExec("client", fmt.Sprintf(
			"ping6 -c 4 ::FFFF:%s", server["IPv4"]))
		Expect(res.WasSuccessful()).Should(BeTrue())

		res = docker.ContainerExec("server", fmt.Sprintf(
			"ping6 -c 4 ::FFFF:%s", client["IPv4"]))
		Expect(res.WasSuccessful()).Should(BeFalse(), "Unexpected NAT46 access")
	})
})

var _ = Describe("RunConntrackTest", func() {

	var initialized bool
	var networkName string = "cilium-net"

	var netperfImage string = "tgraf/netperf"
	var logger *log.Entry
	var docker *helpers.Docker
	var cilium *helpers.Cilium

	initialize := func() {
		if initialized == true {
			return
		}
		logger = log.WithFields(log.Fields{"test": "RunConntrackTest"})
		logger.Info("Starting")
		docker, cilium = helpers.CreateNewRuntimeHelper("runtime", logger)
		docker.NetworkCreate(networkName, "")
		initialized = true
	}

	clientServerConnectivity := func() {
		cliIP, err := docker.ContainerInspectNet("client")
		Expect(err).Should(BeNil(), "Couldn't get container client Meta")

		srvIP, err := docker.ContainerInspectNet("server")
		Expect(err).Should(BeNil(), "Couldn't get container server Meta")

		By("Client pinging server IPv6")
		res := docker.ContainerExec("client", fmt.Sprintf("ping6 -c 4 %s", srvIP["IPv6"]))
		Expect(res.WasSuccessful()).Should(BeTrue(), fmt.Sprintf(
			"Client can't ping to server %s", srvIP["IPv6"]))

		By("Client pinging server IPv4")
		res = docker.ContainerExec("client", fmt.Sprintf("ping -c 4 %s", srvIP["IPv4"]))
		Expect(res.WasSuccessful()).Should(BeTrue(), fmt.Sprintf(
			"Client can't ping to server %s", srvIP["IPv4"]))

		By("Client netcat to port 777 IPv6")
		res = docker.ContainerExec("client", fmt.Sprintf("nc -w 4 %s 777", srvIP["IPv6"]))
		Expect(res.WasSuccessful()).Should(BeFalse(), fmt.Sprintf(
			"Client can connect to %s:777. Should fail", srvIP["IPv6"]))

		By("Client netcat to port 777 IPv4")
		res = docker.ContainerExec("client", fmt.Sprintf("nc -w 4 %s 777", srvIP["IPv4"]))
		Expect(res.WasSuccessful()).Should(BeFalse(), fmt.Sprintf(
			"Client can connect to %s:777. Should fail", srvIP["IPv4"]))

		By("Client netperf to server IPv6")
		res = docker.ContainerExec("client", fmt.Sprintf(
			"netperf -l 3 -t TCP_RR -H %s", srvIP["IPv6"]))
		Expect(res.WasSuccessful()).Should(BeTrue(), fmt.Sprintf(
			"Client can't netperf to server %s", srvIP["IPv6"]))

		By("Client netperf to server IPv4")
		res = docker.ContainerExec("client", fmt.Sprintf(
			"netperf -l 3 -t TCP_RR -H %s", srvIP["IPv4"]))
		Expect(res.WasSuccessful()).Should(BeTrue(), fmt.Sprintf(
			"Client can't netperf to server %s", srvIP["IPv4"]))

		By("Client UDP netperf to server IPv6")
		res = docker.ContainerExec("client", fmt.Sprintf(
			"netperf -l 3 -t UDP_RR -H %s", srvIP["IPv6"]))
		Expect(res.WasSuccessful()).Should(BeTrue(), fmt.Sprintf(
			"Client can't netperf to server %s", srvIP["IPv6"]))

		By("Client UDP netperf to server IPv4")
		res = docker.ContainerExec("client", fmt.Sprintf(
			"netperf -l 3 -t UDP_RR -H %s", srvIP["IPv4"]))
		Expect(res.WasSuccessful()).Should(BeTrue(), fmt.Sprintf(
			"Client can't netperf to server %s", srvIP["IPv4"]))

		By("Ping from host to server IPv6")
		res = docker.Node.Exec(fmt.Sprintf("ping6 -c 4 %s", srvIP["IPv6"]))
		Expect(res.WasSuccessful()).Should(BeTrue(), "Host Can't ping to server")

		By("Ping from host to server IPv4")
		res = docker.Node.Exec(fmt.Sprintf("ping -c 4 %s", srvIP["IPv4"]))
		Expect(res.WasSuccessful()).Should(BeTrue(), "Host can't ping to server")

		By("Ping from server to client IPv6")
		res = docker.ContainerExec("server", fmt.Sprintf("ping6 -c 4 %s", cliIP["IPv6"]))
		Expect(res.WasSuccessful()).Should(BeTrue(), fmt.Sprintf(
			"Server can't ping to client %s", cliIP["IPv6"]))

		By("Ping from server to client IPv4")
		res = docker.ContainerExec("server", fmt.Sprintf("ping -c 4 %s", cliIP["IPv4"]))
		Expect(res.WasSuccessful()).Should(BeTrue(), fmt.Sprintf(
			"Server can't ping to client %s", cliIP["IPv4"]))
	}

	BeforeEach(func() {
		initialize()
		docker.ContainerCreate("client", netperfImage, networkName, "-l id.client")
		docker.ContainerCreate("server", netperfImage, networkName, "-l id.server")
		cilium.Exec("policy delete --all")
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			cilium.ReportFailed()
		}

		docker.ContainerRm("server")
		docker.ContainerRm("client")
	})
	It("Conntrack disabled", func() {
		endpoints, err := cilium.GetEndpointsIds()
		Expect(err).Should(BeNil(), "Couldn't get endpoints IDS")

		status := cilium.EndpointSetConfig(endpoints["server"], "Conntrack", "Disabled")
		Expect(status).Should(BeTrue(), "Couldn't set conntrack=false on endpoint 'server'")

		status = cilium.EndpointSetConfig(endpoints["client"], "Conntrack", "Disabled")
		Expect(status).Should(BeTrue(), "Couldn't set conntrack=false on endpoint 'client'")

		clientServerConnectivity()
	})

	It("ConntrackLocal disabled", func() {
		endpoints, err := cilium.GetEndpointsIds()
		Expect(err).Should(BeNil(), "Couldn't get endpoints IDS")

		status := cilium.EndpointSetConfig(endpoints["server"], "ConntrackLocal", "Disabled")
		Expect(status).Should(BeTrue(), "Couldn't set conntrack=false on endpoint 'server'")

		status = cilium.EndpointSetConfig(endpoints["client"], "ConntrackLocal", "Disabled")
		Expect(status).Should(BeTrue(), "Couldn't set conntrack=false on endpoint 'client'")

		clientServerConnectivity()
	})

	It("ConntrackLocal Enabled", func() {
		endpoints, err := cilium.GetEndpointsIds()
		Expect(err).Should(BeNil(), "Couldn't get endpoints IDS")

		status := cilium.EndpointSetConfig(endpoints["server"], "ConntrackLocal", "Enabled")
		Expect(status).Should(BeTrue(), "Couldn't set conntrack=false on endpoint 'server'")

		status = cilium.EndpointSetConfig(endpoints["client"], "ConntrackLocal", "Enabled")
		Expect(status).Should(BeTrue(), "Couldn't set conntrack=false on endpoint 'client'")

		clientServerConnectivity()
	})

})
