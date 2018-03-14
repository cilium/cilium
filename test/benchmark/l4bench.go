package BenchmarkTest

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("BenchmarkNetperfPerformance", func() {

	var once sync.Once
	var logger *logrus.Entry
	var vm *helpers.SSHMeta
	var PerfLogWriter bytes.Buffer
	var PerfLogFile string
	var f *os.File

	initialize := func() {
		logger = logrus.WithFields(logrus.Fields{"testName": "BenchmarkNetperf"})
		logger.Info("Starting")
		vm = helpers.CreateNewRuntimeHelper(helpers.Runtime, logger)

		PerfLogFile := "perf.log"
		By(fmt.Sprintf("Create file %s", PerfLogFile))
		f, _ = os.Create(PerfLogFile)
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
		By(fmt.Sprintf("writing to log %s", PerfLogFile))
		PerfLogWriter.WriteTo(f)
		f.Close()
		return
	})

	ClientServerCheck := func(serverIPv6 *bytes.Buffer, serverIP *bytes.Buffer) {
		By(fmt.Sprintf("checking %s can ping to %s IPv6", helpers.Client, helpers.Server))
		res := vm.ContainerExec(helpers.Client, helpers.Ping6(serverIPv6.String()))
		res.ExpectSuccess()

		By(fmt.Sprintf("checking %s can ping to %s IPv4", helpers.Client, helpers.Server))
		res = vm.ContainerExec(helpers.Client, helpers.Ping(serverIP.String()))
		res.ExpectSuccess()
	}

	Context("Benchmark Netperf Tests Container2Container", func() {

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

		__SuperNetperfRR := func(client bool, num int, serverIP *bytes.Buffer) {
			var res *helpers.CmdRes

			By(fmt.Sprintf("super_netperf to %s from %s (should succeed)", helpers.Server, helpers.Client))
			cmd := fmt.Sprintf("super_netperf %d -t TCP_RR -H %s", num, serverIP)
			if client {
				res = vm.ContainerExec(helpers.Client, cmd)
			} else {
				res = vm.ContainerExec(helpers.Server, cmd)
			}

			res.ExpectSuccess()
			fmt.Fprintf(&PerfLogWriter, "%s,", strings.TrimSuffix(res.GetStdOut(), "\n"))
		}

		SuperNetperfRR := func(client bool, num int, serverIP *bytes.Buffer, serverIPv6 *bytes.Buffer) {
			__SuperNetperfRR(client, num, serverIP)
			ClientServerCheck(serverIPv6, serverIP)
		}

		__SuperNetperfStream := func(client bool, num int, serverIP *bytes.Buffer) {
			var res *helpers.CmdRes

			By(fmt.Sprintf("super_netperf to %s from %s (should succeed)", helpers.Server, helpers.Client))
			cmd := fmt.Sprintf("super_netperf %d -f g -t TCP_STREAM -H %s", num, serverIP)
			if client {
				res = vm.ContainerExec(helpers.Client, cmd)
			} else {
				res = vm.ContainerExec(helpers.Server, cmd)
			}

			res.ExpectSuccess()
			fmt.Fprintf(&PerfLogWriter, "%s,", strings.TrimSuffix(res.GetStdOut(), "\n"))
		}

		SuperNetperfStream := func(client bool, num int, serverIP *bytes.Buffer, serverIPv6 *bytes.Buffer) {
			__SuperNetperfStream(client, num, serverIP)
			ClientServerCheck(serverIPv6, serverIP)
		}

		It("Test L4 Netperf Performance", func() {
			By(fmt.Sprintf("inspecting container %s", helpers.Server))
			serverData := vm.ContainerInspect(helpers.Server)
			serverIP, err := serverData.Filter(fmt.Sprintf("{[0].NetworkSettings.Networks.%s.IPAddress}", helpers.CiliumDockerNetwork))
			Expect(err).Should(BeNil())

			By(fmt.Sprintf("serverIP: %s", serverIP))
			serverIPv6, err := serverData.Filter(fmt.Sprintf("{[0].NetworkSettings.Networks.%s.GlobalIPv6Address}", helpers.CiliumDockerNetwork))
			By(fmt.Sprintf("serverIPv6: %s", serverIPv6))
			Expect(err).Should(BeNil())

			fmt.Fprintf(&PerfLogWriter, "lo netperf req/sec: ")
			SuperNetperfRR(false, 1, serverIP, serverIPv6)
			SuperNetperfRR(false, 10, serverIP, serverIPv6)
			SuperNetperfRR(false, 100, serverIP, serverIPv6)
			SuperNetperfRR(false, 1000, serverIP, serverIPv6)
			fmt.Fprintf(&PerfLogWriter, "\ninter-container netperf req/sec: ")
			SuperNetperfRR(true, 1, serverIP, serverIPv6)
			SuperNetperfRR(true, 10, serverIP, serverIPv6)
			SuperNetperfRR(true, 100, serverIP, serverIPv6)
			SuperNetperfRR(true, 1000, serverIP, serverIPv6)
			fmt.Fprintf(&PerfLogWriter, "\nlo netperf stream: ")
			SuperNetperfStream(false, 1, serverIP, serverIPv6)
			SuperNetperfStream(false, 10, serverIP, serverIPv6)
			SuperNetperfStream(false, 100, serverIP, serverIPv6)
			SuperNetperfStream(false, 1000, serverIP, serverIPv6)
			fmt.Fprintf(&PerfLogWriter, "\ninter-container netperf stream: ")
			SuperNetperfStream(true, 1, serverIP, serverIPv6)
			SuperNetperfStream(true, 10, serverIP, serverIPv6)
			SuperNetperfStream(true, 100, serverIP, serverIPv6)
			SuperNetperfStream(true, 1000, serverIP, serverIPv6)
			fmt.Fprintf(&PerfLogWriter, "\n")
		}, 300)
	})
})
