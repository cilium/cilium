// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package RuntimeTest

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/logging"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	"github.com/cilium/cilium/test/helpers/constants"
)

func superNetperfRRIPv4(s *helpers.SSHMeta, client string, server string, num int) *helpers.CmdRes {
	var res *helpers.CmdRes

	serverNet, _ := s.ContainerInspectNet(server)
	serverIpv4 := serverNet[helpers.IPv4]
	By("super_netperf to %s from %s (should succeed)", server, client)
	cmd := fmt.Sprintf("super_netperf %d -t TCP_RR -H %s", num, serverIpv4)
	res = s.ContainerExec(client, cmd)
	res.ExpectSuccess("failed: %s", cmd)
	return res
}

// SuperNetperfRR launches 'num' parallel netperf TCP_RR
// (request/response) tests from client to server.
func superNetperfRR(s *helpers.SSHMeta, client string, server string, num int) *helpers.CmdRes {
	return superNetperfRRIPv4(s, client, server, num)
}

func superNetperfStreamIPv4(s *helpers.SSHMeta, client string, server string, num int) *helpers.CmdRes {
	var res *helpers.CmdRes

	serverNet, _ := s.ContainerInspectNet(server)
	serverIpv4 := serverNet[helpers.IPv4]
	By("super_netperf to %s from %s (should succeed)", server, client)
	cmd := fmt.Sprintf("super_netperf %d -f g -t TCP_STREAM -H %s", num, serverIpv4)
	res = s.ContainerExec(client, cmd)
	res.ExpectSuccess("failed: %s", cmd)
	return res
}

// SuperNetperfStream launches 'num' parallel netperf TCP_STREAM
// tests from client to server.
func superNetperfStream(s *helpers.SSHMeta, client string, server string, num int) *helpers.CmdRes {
	return superNetperfStreamIPv4(s, client, server, num)
}

var _ = Describe("BenchmarkNetperfPerformance", func() {
	var (
		vm            *helpers.SSHMeta
		testStartTime time.Time
		monitorStop   = func() error { return nil }

		log    = logging.DefaultLogger
		logger = logrus.NewEntry(log)

		PerfLogFile   = "l4bench_perf.log"
		PerfLogWriter bytes.Buffer
	)

	BeforeAll(func() {
		vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)
		ExpectCiliumReady(vm)
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

	AfterAll(func() {
		vm.CloseSSHClient()
	})

	createContainers := func() {
		By("create Client container")
		res := vm.ContainerCreate(helpers.Client, constants.NetperfImage, helpers.CiliumDockerNetwork, "-l id.client")
		res.ExpectSuccess("failed to create client container")
		By("create Server container")
		res = vm.ContainerCreate(helpers.Server, constants.NetperfImage, helpers.CiliumDockerNetwork, "-l id.server")
		res.ExpectSuccess("failed to create server container")
		vm.PolicyDelAll()
		Expect(vm.WaitEndpointsReady()).To(BeNil(), "Endpoints are not ready")
	}

	removeContainers := func(containerName string) {
		By("removing container %s", containerName)
		res := vm.ContainerRm(containerName)
		Expect(res.WasSuccessful()).Should(BeTrue(), "Container removal failed")
	}

	deleteContainers := func() {
		removeContainers(helpers.Client)
		removeContainers(helpers.Server)
	}

	superNetperfRRLog := func(client string, server string, num int) {
		res := superNetperfRR(vm, client, server, num)
		fmt.Fprintf(&PerfLogWriter, "%s,", strings.TrimSuffix(res.Stdout(), "\n"))
	}

	superNetperfStreamLog := func(client string, server string, num int) {
		res := superNetperfStream(vm, client, server, num)
		fmt.Fprintf(&PerfLogWriter, "%s,", strings.TrimSuffix(res.Stdout(), "\n"))
	}

	Context("Benchmark Netperf Tests", func() {
		BeforeAll(func() {
			createContainers()
		})

		AfterAll(func() {
			deleteContainers()
		})

		It("Test L4 Netperf TCP_RR Performance lo:1", func() {
			superNetperfRRLog(helpers.Server, helpers.Server, 1)
		}, 300)

		It("Test L4 Netperf TCP_RR Performance lo:10", func() {
			superNetperfRRLog(helpers.Server, helpers.Server, 10)
		}, 300)

		It("Test L4 Netperf Performance lo:100", func() {
			superNetperfRRLog(helpers.Server, helpers.Server, 100)
		}, 300)

		It("Test L4 Netperf TCP_RR Performance lo:1000", func() {
			superNetperfRRLog(helpers.Server, helpers.Server, 1000)
		}, 300)

		It("Test L4 Netperf TCP_RR Performance inter-container:1", func() {
			superNetperfRRLog(helpers.Client, helpers.Server, 1)
		}, 300)

		It("Test L4 Netperf TCP_RR Performance inter-container:10", func() {
			superNetperfRRLog(helpers.Client, helpers.Server, 10)
		}, 300)

		It("Test L4 Netperf TCP_RR Performance inter-container:100", func() {
			superNetperfRRLog(helpers.Client, helpers.Server, 100)
		}, 300)

		It("Test L4 Netperf TCP_RR Performance inter-container:1000", func() {
			superNetperfRRLog(helpers.Client, helpers.Server, 1000)
		}, 300)

		It("Test L4 Netperf TCP_STREAM Performance lo:1", func() {
			superNetperfStreamLog(helpers.Server, helpers.Server, 1)
		}, 300)

		It("Test L4 Netperf TCP_STREAM Performance lo:10", func() {
			superNetperfStreamLog(helpers.Server, helpers.Server, 10)
		}, 300)

		It("Test L4 Netperf TCP_STREAM Performance lo:100", func() {
			superNetperfStreamLog(helpers.Server, helpers.Server, 100)
		}, 300)

		It("Test L4 Netperf TCP_STREAM Performance lo:1000", func() {
			superNetperfStreamLog(helpers.Server, helpers.Server, 1000)
		}, 300)

		It("Test L4 Netperf TCP_STREAM Performance lo:1", func() {
			superNetperfStreamLog(helpers.Client, helpers.Server, 1)
		}, 300)

		It("Test L4 Netperf TCP_STREAM Performance lo:10", func() {
			superNetperfStreamLog(helpers.Client, helpers.Server, 10)
		}, 300)

		It("Test L4 Netperf TCP_STREAM Performance lo:100", func() {
			superNetperfStreamLog(helpers.Client, helpers.Server, 100)
		}, 300)

		It("Test L4 Netperf TCP_STREAM Performance lo:1000", func() {
			superNetperfStreamLog(helpers.Client, helpers.Server, 1000)
		}, 300)
	})

	Context("Benchmark Netperf Tests Sockops-Enabled", func() {
		BeforeAll(func() {
			vm.SetUpCiliumWithSockops()
			ExpectCiliumReady(vm)
			createContainers()
		})

		AfterAll(func() {
			deleteContainers()
		})

		It("Test L4 Netperf TCP_RR Performance Sockops lo:1", func() {
			superNetperfRRLog(helpers.Server, helpers.Server, 1)
		}, 300)

		It("Test L4 Netperf TCP_RR Performance Sockops lo:10", func() {
			superNetperfRRLog(helpers.Server, helpers.Server, 10)
		}, 300)

		It("Test L4 Netperf TCP_RR Performance Sockops lo:100", func() {
			superNetperfRRLog(helpers.Server, helpers.Server, 100)
		}, 300)

		It("Test L4 Netperf TCP_RR Performance Sockops lo:1000", func() {
			superNetperfRRLog(helpers.Server, helpers.Server, 1000)
		}, 300)

		It("Test L4 Netperf TCP_RR Performance Sockops inter-container:1", func() {
			superNetperfRRLog(helpers.Client, helpers.Server, 1)
		}, 300)

		It("Test L4 Netperf TCP_RR Performance Sockops inter-container:10", func() {
			superNetperfRRLog(helpers.Client, helpers.Server, 10)
		}, 300)

		It("Test L4 Netperf TCP_RR Performance Sockops inter-container:100", func() {
			superNetperfRRLog(helpers.Client, helpers.Server, 100)
		}, 300)

		It("Test L4 Netperf TCP_RR Performance Sockops inter-container:1000", func() {
			superNetperfRRLog(helpers.Client, helpers.Server, 1000)
		}, 300)

		It("Test L4 Netperf TCP_STREAM Performance Sockops lo:1", func() {
			superNetperfStreamLog(helpers.Server, helpers.Server, 1)
		}, 300)

		It("Test L4 Netperf TCP_STREAM Performance Sockops lo:10", func() {
			superNetperfStreamLog(helpers.Server, helpers.Server, 10)
		}, 300)

		It("Test L4 Netperf TCP_STREAM Performance Sockops lo:100", func() {
			superNetperfStreamLog(helpers.Server, helpers.Server, 100)
		}, 300)

		It("Test L4 Netperf TCP_STREAM Performance Sockops lo:1000", func() {
			superNetperfStreamLog(helpers.Server, helpers.Server, 1000)
		}, 300)

		It("Test L4 Netperf TCP_STREAM Performance Sockops lo:1", func() {
			superNetperfStreamLog(helpers.Client, helpers.Server, 1)
		}, 300)

		It("Test L4 Netperf TCP_STREAM Performance Sockops lo:10", func() {
			superNetperfStreamLog(helpers.Client, helpers.Server, 10)
		}, 300)

		It("Test L4 Netperf TCP_STREAM Performance Sockops lo:100", func() {
			superNetperfStreamLog(helpers.Client, helpers.Server, 100)
		}, 300)

		It("Test L4 Netperf TCP_STREAM Performance Sockops lo:1000", func() {
			superNetperfStreamLog(helpers.Client, helpers.Server, 1000)
		}, 300)
	})
})
