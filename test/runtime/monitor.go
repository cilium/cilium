// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package RuntimeTest

import (
	"context"
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/gomega"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
)

const (
	// MonitorDropNotification represents the DropNotification configuration
	// value for the Cilium monitor
	MonitorDropNotification = "DropNotification"

	// MonitorTraceNotification represents the TraceNotification configuration
	// value for the Cilium monitor
	MonitorTraceNotification = "TraceNotification"
)

var _ = Describe("RuntimeDatapathMonitorTest", func() {

	var (
		vm            *helpers.SSHMeta
		testStartTime time.Time
	)

	BeforeAll(func() {
		vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)
		ExpectCiliumReady(vm)

		dbgDone := vm.MonitorDebug(true, "")
		Expect(dbgDone).Should(BeTrue())

		Expect(vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")

		endpoints, err := vm.GetEndpointsIds()
		Expect(err).Should(BeNil())

		for _, v := range endpoints {
			dbgDone := vm.MonitorDebug(true, v)
			Expect(dbgDone).Should(BeTrue())
		}
	})

	JustBeforeEach(func() {
		testStartTime = time.Now()
	})

	JustAfterEach(func() {
		vm.ValidateNoErrorsInLogs(time.Since(testStartTime))
	})

	AfterFailed(func() {
		vm.ReportFailed()
	})

	BeforeEach(func() {
		ExpectPolicyEnforcementUpdated(vm, helpers.PolicyEnforcementDefault)
	})

	AfterAll(func() {
		endpoints, err := vm.GetEndpointsIds()
		Expect(err).Should(BeNil())

		for _, v := range endpoints {
			dbgDone := vm.MonitorDebug(false, v)
			Expect(dbgDone).Should(BeTrue())
		}

		dbgDone := vm.MonitorDebug(false, "")
		Expect(dbgDone).Should(BeTrue())

		vm.CloseSSHClient()
	})

	Context("With Sample Containers", func() {

		BeforeAll(func() {
			vm.SampleContainersActions(helpers.Create, helpers.CiliumDockerNetwork)
		})

		AfterEach(func() {
			_ = vm.PolicyDelAll()
		})

		AfterAll(func() {
			vm.SampleContainersActions(helpers.Delete, helpers.CiliumDockerNetwork)
		})

		monitorConfig := func() {
			res := vm.ExecCilium(fmt.Sprintf("config %s=true %s=true",
				MonitorDropNotification, MonitorTraceNotification))
			ExpectWithOffset(1, res.WasSuccessful()).To(BeTrue(), "cannot update monitor config")
		}

		It("Cilium monitor event types", func() {
			monitorConfig()

			_, err := vm.PolicyImportAndWait(vm.GetFullPath(policiesL3JSON), helpers.HelperTimeout)
			Expect(err).Should(BeNil())

			Expect(vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")

			eventTypes := map[string]string{
				"drop":    "DROP:",
				"debug":   "DEBUG:",
				"capture": "DEBUG:",
			}

			for k, v := range eventTypes {
				By("Type %s", k)

				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				res := vm.ExecInBackground(ctx, fmt.Sprintf("cilium monitor --type %s -vv", k))

				vm.ContainerExec(helpers.App1, helpers.Ping(helpers.Httpd1))
				vm.ContainerExec(helpers.App3, helpers.Ping(helpers.Httpd1))

				Expect(res.WaitUntilMatch(v)).To(BeNil(),
					"%q is not in the output after timeout", v)
				Expect(res.CountLines()).Should(BeNumerically(">", 3))
				Expect(res.Stdout()).Should(ContainSubstring(v))
				cancel()
			}

			By("all types together")
			command := "cilium monitor -vv"
			for k := range eventTypes {
				command = command + " --type " + k
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			By(command)
			res := vm.ExecInBackground(ctx, command)

			Expect(vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")

			vm.ContainerExec(helpers.App3, helpers.Ping(helpers.Httpd1))
			vm.ContainerExec(helpers.App1, helpers.Ping(helpers.Httpd1))

			for _, v := range eventTypes {
				Expect(res.WaitUntilMatch(v)).To(BeNil(),
					"%q is not in the output after timeout", v)
				Expect(res.Stdout()).Should(ContainSubstring(v))
			}

			Expect(res.CountLines()).Should(BeNumerically(">", 3))
		})

		It("cilium monitor check --from", func() {
			monitorConfig()

			Expect(vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")

			endpoints, err := vm.GetEndpointsIds()
			Expect(err).Should(BeNil())

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			res := vm.ExecInBackground(ctx, fmt.Sprintf(
				"cilium monitor --type debug --from %s -vv", endpoints[helpers.App1]))
			vm.ContainerExec(helpers.App1, helpers.Ping(helpers.Httpd1))

			filter := fmt.Sprintf("FROM %s DEBUG:", endpoints[helpers.App1])
			Expect(res.WaitUntilMatch(filter)).To(BeNil(),
				"%q is not in the output after timeout", filter)
			Expect(res.CountLines()).Should(BeNumerically(">", 3))
			Expect(res.Stdout()).Should(ContainSubstring(filter))

			//MonitorDebug mode shouldn't have DROP lines
			Expect(res.Stdout()).ShouldNot(ContainSubstring("DROP"))
		})

		It("cilium monitor check --to", func() {
			monitorConfig()

			Expect(vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")

			endpoints, err := vm.GetEndpointsIds()
			Expect(err).Should(BeNil())

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			res := vm.ExecInBackground(ctx, fmt.Sprintf(
				"cilium monitor -vv --to %s", endpoints[helpers.Httpd1]))

			vm.ContainerExec(helpers.App1, helpers.Ping(helpers.Httpd1))
			vm.ContainerExec(helpers.App2, helpers.Ping(helpers.Httpd1))

			filter := fmt.Sprintf("to endpoint %s", endpoints[helpers.Httpd1])
			Expect(res.WaitUntilMatch(filter)).To(BeNil(),
				"%q is not in the output after timeout", filter)
			Expect(res.CountLines()).Should(BeNumerically(">=", 3))
			Expect(res.Stdout()).Should(ContainSubstring(filter))
		})

		It("cilium monitor check --related-to", func() {
			monitorConfig()

			Expect(vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")

			endpoints, err := vm.GetEndpointsIds()
			Expect(err).Should(BeNil())

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			res := vm.ExecInBackground(ctx, fmt.Sprintf(
				"cilium monitor -vv --related-to %s", endpoints[helpers.Httpd1]))

			vm.WaitEndpointsReady()
			vm.ContainerExec(helpers.App1, helpers.CurlFail("http://httpd1/public"))

			filter := fmt.Sprintf("FROM %s DEBUG:", endpoints[helpers.Httpd1])
			Expect(res.WaitUntilMatch(filter)).To(BeNil(),
				"%q is not in the output after timeout", filter)
			Expect(res.CountLines()).Should(BeNumerically(">=", 3))
			Expect(res.Stdout()).Should(ContainSubstring(filter))
		})

		It("delivers the same information to multiple monitors", func() {
			monitorConfig()

			Expect(vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")

			var monitorRes []*helpers.CmdRes
			ctx, cancelfn := context.WithCancel(context.Background())

			for i := 1; i <= 3; i++ {
				monitorRes = append(monitorRes, vm.ExecInBackground(ctx, "cilium monitor"))
			}

			vm.ContainerExec(helpers.App1, helpers.Ping(helpers.Httpd1))
			cancelfn()

			for _, res := range monitorRes {
				res.WaitUntilFinish()
			}

			Expect(monitorRes[0].CountLines()).Should(BeNumerically(">", 2))

			// Some monitor instances may see more data than others due to timing. We
			// want to find a run of lines that matches between all monitor
			// instances, ignoring earlier or later lines that may have not been seen
			// by an instance. We find the shortest sample and check that those lines
			// occur in all monitor responses.
			var (
				// shortestResult is the smallest set of monitor output lines, after we
				// trim leading init lines.
				shortestResult string

				// Output lines from each monitor, trimmed to ignore init messages.
				// The order matches monitorRes.
				trimmedResults []string
			)

			// Trim the result lines to ignore startup/shutdown messages like
			//    "level=info msg="Initializing dissection cache..." subsys=monitor"
			//    "Received an interrupt, disconnecting from monitor..."
			// and note the shortest
			for _, result := range monitorRes {
				lines := result.ByLines()
				trimmedResult := make([]string, 0, len(lines))
				for _, line := range lines {
					if strings.HasPrefix(line, " <- endpoint") {
						trimmedResult = append(trimmedResult, line)
					}
				}
				trimmedResults = append(trimmedResults, strings.Join(trimmedResult, "\n"))

				if len(trimmedResult) < len(shortestResult) {
					shortestResult = strings.Join(trimmedResult, "\n")
				}
			}

			// The shortest output must occur in whole within the other outputs
			for _, trimmedResult := range trimmedResults {
				Expect(strings.Contains(trimmedResult, shortestResult)).Should(Equal(true),
					"Inconsistent monitor output between 2 monitor instances during the same time period\nExpected:\n%s\nFound:\n%s\n", shortestResult, trimmedResult)
			}
		})

		It("checks container ids match monitor output", func() {
			ExpectPolicyEnforcementUpdated(vm, helpers.PolicyEnforcementAlways)

			ctx, cancel := context.WithCancel(context.Background())
			res := vm.ExecInBackground(ctx, "cilium monitor -vv")

			vm.ContainerExec(helpers.App1, helpers.Ping(helpers.Httpd1))
			vm.ContainerExec(helpers.Httpd1, helpers.Ping(helpers.App1))

			endpoints, err := vm.GetEndpointsIDMap()
			Expect(err).Should(BeNil())

			helpers.Sleep(10)
			cancel()

			// Expected full example output:
			// CPU 01: MARK 0x3de3947b FROM 48896 DEBUG: Attempting local delivery for container id 29381 from seclabel 263
			//                              ^                                                       ^
			for _, line := range res.ByLines() {
				var toID, fromID string

				fields := strings.Split(line, " ")
				for i := range fields {
					switch fields[i] {
					case "FROM":
						fromID = fields[i+1]
					case "id":
						toID = fields[i+1]
					}
				}
				if fromID == "" || toID == "" {
					continue
				}
				By("checking endpoints in monitor line:\n%q", line)

				Expect(toID).Should(Not(Equal(fromID)))
				Expect(endpoints[toID]).Should(Not(BeNil()))
				Expect(endpoints[fromID]).Should(Not(BeNil()))
			}
		})
	})
})
