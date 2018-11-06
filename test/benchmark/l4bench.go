package BenchmarkTest

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/cilium/pkg/logging"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("BenchmarkNetperfPerformance", func() {
	var (
		vm          *helpers.SSHMeta
		monitorStop = func() error { return nil }

		log    = logging.DefaultLogger
		logger = logrus.NewEntry(log)

		PerfLogFile   = "l4bench_perf.log"
		PerfLogWriter bytes.Buffer
	)

	BeforeAll(func() {
		vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)
		helpers.ExpectCiliumReady(vm)
	})

	AfterAll(func() {
	})

	JustBeforeEach(func() {
		monitorStop = vm.MonitorStart()
	})

	JustAfterEach(func() {
		vm.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
		Expect(monitorStop()).To(BeNil(), "cannot stop monitor command")
	})

	AfterFailed(func() {
		vm.ReportFailed(
			"cilium service list",
			"cilium policy get")
	})

	AfterEach(func() {
		LogPerm := os.FileMode(0666)
		testPath, err := helpers.CreateReportDirectory()
		Expect(err).Should(BeNil(), "cannot create log file")
		helpers.WriteOrAppendToFile(filepath.Join(testPath, PerfLogFile), PerfLogWriter.Bytes(), LogPerm)
		PerfLogWriter.Reset()
	}, 500)

	createContainers := func() {
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
	}

	removeContainers := func(containerName string) {
		By(fmt.Sprintf("removing container %s", containerName))
		res := vm.ContainerRm(containerName)
		Expect(res.WasSuccessful()).Should(BeTrue())
	}

	deleteContainers := func() {
		removeContainers(helpers.Client)
		removeContainers(helpers.Server)
	}

	BeforeEach(func() {
	}, 500)

	Context("Benchmark Netperf Tests Container2Container", func() {
		BeforeAll(func() {
			createContainers()
		})

		AfterAll(func() {
			deleteContainers()
		})

		ClientServerCheck := func(serverIPv6 string, serverIP string) {
			By("checking %s can ping to %s IPv6", helpers.Client, helpers.Server)
			res := vm.ContainerExec(helpers.Client, helpers.Ping6(serverIPv6))
			res.ExpectSuccess()

			By("checking %s can ping to %s IPv4", helpers.Client, helpers.Server)
			res = vm.ContainerExec(helpers.Client, helpers.Ping(serverIP))
			res.ExpectSuccess()
		}

		__SuperNetperfRR := func(client bool, num int, serverIP string) {
			var res *helpers.CmdRes

			By("super_netperf to %s from %s (should succeed)", helpers.Server, helpers.Client)
			cmd := fmt.Sprintf("super_netperf %d -t TCP_RR -H %s", num, serverIP)
			if client {
				res = vm.ContainerExec(helpers.Client, cmd)
			} else {
				res = vm.ContainerExec(helpers.Server, cmd)
			}

			res.ExpectSuccess()
			fmt.Fprintf(&PerfLogWriter, "%s,", strings.TrimSuffix(res.GetStdOut(), "\n"))
		}

		SuperNetperfRR := func(client bool, num int, serverIP string, serverIPv6 string) {
			__SuperNetperfRR(client, num, serverIP)
			ClientServerCheck(serverIPv6, serverIP)
		}

		__SuperNetperfStream := func(client bool, num int, serverIP string) {
			var res *helpers.CmdRes

			By("super_netperf to %s from %s (should succeed)", helpers.Server, helpers.Client)
			cmd := fmt.Sprintf("super_netperf %d -f g -t TCP_STREAM -H %s", num, serverIP)
			if client {
				res = vm.ContainerExec(helpers.Client, cmd)
			} else {
				res = vm.ContainerExec(helpers.Server, cmd)
			}

			res.ExpectSuccess()
			fmt.Fprintf(&PerfLogWriter, "%s,", strings.TrimSuffix(res.GetStdOut(), "\n"))
		}

		SuperNetperfStream := func(client bool, num int, serverIP string, serverIPv6 string) {
			__SuperNetperfStream(client, num, serverIP)
			ClientServerCheck(serverIPv6, serverIP)
		}

		NetperfTest := func() {
			serverData := vm.ContainerInspect(helpers.Server)
			_serverIP, err := serverData.Filter(fmt.Sprintf("{[0].NetworkSettings.Networks.%s.IPAddress}", helpers.CiliumDockerNetwork))
			Expect(err).Should(BeNil())

			_serverIPv6, err := serverData.Filter(fmt.Sprintf("{[0].NetworkSettings.Networks.%s.GlobalIPv6Address}", helpers.CiliumDockerNetwork))
			Expect(err).Should(BeNil())

			serverIP := _serverIP.String()
			serverIPv6 := _serverIPv6.String()
			By("serverIP: %s", serverIP)
			By("serverIPv6: %s", serverIPv6)

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
		}

		It("Test L4 Netperf Performance", func() {
			NetperfTest()
		}, 300)

		It("Test L4 Netperf Performance with Sockmap", func() {
			vm.RestartCiliumSockops()
			NetperfTest()
		}, 300)
	})
})
