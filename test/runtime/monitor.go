// Copyright 2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package RuntimeTest

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"sync"

	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

const (
	// MonitorDropNotification represents the DropNotification configuration
	// value for the Cilium monitor
	MonitorDropNotification = "DropNotification"

	// MonitorTraceNotification represents the TraceNotification configuration
	// value for the Cilium monitor
	MonitorTraceNotification = "TraceNotification"

	// MonitorDebug represents the Debug configuration  value for
	// the Cilium monitor
	MonitorDebug = "Debug"
)

var _ = Describe("RuntimeValidatedMonitorTest", func() {

	var once sync.Once
	var logger *logrus.Entry
	var vm *helpers.SSHMeta

	initialize := func() {
		logger = log.WithFields(logrus.Fields{"testName": "RuntimeMonitorTest"})
		logger.Info("Starting")
		vm = helpers.CreateNewRuntimeHelper(helpers.Runtime, logger)
		areEndpointsReady := vm.WaitEndpointsReady()
		Expect(areEndpointsReady).Should(BeTrue())
	}

	BeforeEach(func() {
		once.Do(initialize)
		res := vm.SetPolicyEnforcement(helpers.PolicyEnforcementDefault)
		res.ExpectSuccess()

	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			vm.ReportFailed()
		}

		vm.SampleContainersActions(helpers.Delete, helpers.CiliumDockerNetwork)
	})

	It("Cilium monitor verbose mode", func() {

		res := vm.ExecCilium(fmt.Sprintf("config %s=true %s=true %s=true",
			MonitorDebug, MonitorDropNotification, MonitorTraceNotification))
		res.ExpectSuccess()

		ctx, cancel := context.WithCancel(context.Background())

		res = vm.ExecContext(ctx, "cilium monitor -v")
		vm.SampleContainersActions(helpers.Create, helpers.CiliumDockerNetwork)
		areEndpointsReady := vm.WaitEndpointsReady()
		Expect(areEndpointsReady).Should(BeTrue())

		helpers.Sleep(5)
		cancel()
		endpoints, err := vm.GetEndpointsIds()
		Expect(err).Should(BeNil())

		for k, v := range endpoints {
			filter := fmt.Sprintf("FROM %s DEBUG:", v)
			vm.ContainerExec(k, helpers.Ping(helpers.Httpd1))
			Expect(res.Output().String()).Should(ContainSubstring(filter))
		}
	})

	It("Cilium monitor event types", func() {
		eventTypes := map[string]string{
			"drop":    "DROP:",
			"debug":   "DEBUG:",
			"capture": "DEBUG:",
		}

		res := vm.ExecCilium(fmt.Sprintf("config %s=true %s=true %s=true",
			MonitorDebug, MonitorDropNotification, MonitorTraceNotification))
		res.ExpectSuccess()
		for k, v := range eventTypes {
			By(fmt.Sprintf("Type %s", k))

			ctx, cancel := context.WithCancel(context.Background())
			res := vm.ExecContext(ctx, fmt.Sprintf("cilium monitor --type %s -v", k))
			vm.SampleContainersActions(helpers.Create, helpers.CiliumDockerNetwork)
			areEndpointsReady := vm.WaitEndpointsReady()
			Expect(areEndpointsReady).Should(BeTrue())

			vm.ContainerExec(helpers.App1, helpers.Ping(helpers.Httpd1))
			helpers.Sleep(5)
			cancel()

			Expect(res.CountLines()).Should(BeNumerically(">", 3))
			Expect(res.Output().String()).Should(ContainSubstring(v))
			vm.SampleContainersActions(helpers.Delete, helpers.CiliumDockerNetwork)
		}
	})

	It("cilium monitor check --from", func() {
		res := vm.ExecCilium(fmt.Sprintf("config %s=true %s=true %s=true", MonitorDebug, MonitorDropNotification, MonitorTraceNotification))
		res.ExpectSuccess()

		vm.SampleContainersActions(helpers.Create, helpers.CiliumDockerNetwork)
		areEndpointsReady := vm.WaitEndpointsReady()
		Expect(areEndpointsReady).Should(BeTrue())

		endpoints, err := vm.GetEndpointsIds()
		Expect(err).Should(BeNil())

		ctx, cancel := context.WithCancel(context.Background())
		res = vm.ExecContext(ctx, fmt.Sprintf(
			"cilium monitor --type debug --from %s -v", endpoints[helpers.App1]))
		vm.ContainerExec(helpers.App1, helpers.Ping(helpers.Httpd1))
		helpers.Sleep(5)
		cancel()

		Expect(res.CountLines()).Should(BeNumerically(">", 3))
		filter := fmt.Sprintf("FROM %s DEBUG:", endpoints[helpers.App1])
		Expect(res.Output().String()).Should(ContainSubstring(filter))

		//MonitorDebug mode shouldn't have DROP lines
		Expect(res.Output().String()).ShouldNot(ContainSubstring("DROP"))

	})

	It("cilium monitor check --to", func() {

		res := vm.ExecCilium(fmt.Sprintf(
			"config %s=true %s=true %s=true", MonitorDebug, MonitorDropNotification, MonitorTraceNotification))
		res.ExpectSuccess()

		vm.SampleContainersActions(helpers.Create, helpers.CiliumDockerNetwork)
		areEndpointsReady := vm.WaitEndpointsReady()
		Expect(areEndpointsReady).Should(BeTrue())

		endpoints, err := vm.GetEndpointsIds()
		Expect(err).Should(BeNil())

		ctx, cancel := context.WithCancel(context.Background())
		res = vm.ExecContext(ctx, fmt.Sprintf(
			"cilium monitor -v --to %s", endpoints[helpers.Httpd1]))

		vm.ContainerExec(helpers.App1, helpers.Ping(helpers.Httpd1))
		vm.ContainerExec(helpers.App2, helpers.Ping(helpers.Httpd1))
		helpers.Sleep(5)
		cancel()

		Expect(res.CountLines()).Should(BeNumerically(">=", 3))
		filter := fmt.Sprintf("to endpoint %s", endpoints[helpers.Httpd1])
		Expect(res.Output().String()).Should(ContainSubstring(filter))

	})

	It("cilium monitor check --related-to", func() {

		res := vm.ExecCilium(fmt.Sprintf(
			"config %s=true %s=true %s=true", MonitorDebug, MonitorDropNotification, MonitorTraceNotification))
		res.ExpectSuccess()

		vm.SampleContainersActions(helpers.Create, helpers.CiliumDockerNetwork)
		areEndpointsReady := vm.WaitEndpointsReady()
		Expect(areEndpointsReady).Should(BeTrue())

		endpoints, err := vm.GetEndpointsIds()
		Expect(err).Should(BeNil())

		ctx, cancel := context.WithCancel(context.Background())
		res = vm.ExecContext(ctx, fmt.Sprintf(
			"cilium monitor -v --related-to %s", endpoints[helpers.Httpd1]))

		vm.WaitEndpointsReady()
		vm.ContainerExec(helpers.App1, helpers.CurlFail("http://httpd1/public"))

		helpers.Sleep(2)
		cancel()
		Expect(res.CountLines()).Should(BeNumerically(">=", 3))
		filter := fmt.Sprintf("FROM %s DEBUG:", endpoints[helpers.Httpd1])
		Expect(res.Output().String()).Should(ContainSubstring(filter))
	})

	prepareContainers := func() {
		vm.ContainerCreate(helpers.Client, helpers.NetperfImage, helpers.CiliumDockerNetwork, "-l id.client")
		vm.ContainerCreate(helpers.Server, helpers.NetperfImage, helpers.CiliumDockerNetwork, "-l id.server")

		areEndpointsReady := vm.WaitEndpointsReady()
		Expect(areEndpointsReady).Should(BeTrue())
	}

	cleanupContainers := func() {
		vm.ContainerRm(helpers.Client)
		vm.ContainerRm(helpers.Server)
	}

	It("multiple monitors", func() {
		res := vm.ExecCilium(fmt.Sprintf(
			"config %s=true %s=true %s=true %s=default",
			MonitorDebug, MonitorDropNotification,
			MonitorTraceNotification, helpers.PolicyEnforcement))
		res.ExpectSuccess()

		var monitorRes []*helpers.CmdRes

		prepareContainers()
		defer cleanupContainers()

		ctx, cancelfn := context.WithCancel(context.Background())

		for i := 1; i <= 3; i++ {
			monitorRes = append(monitorRes, vm.ExecContext(ctx, "cilium monitor"))
		}

		vm.ContainerExec(helpers.Client, helpers.Ping(helpers.Server))
		cancelfn()

		Expect(monitorRes[0].CountLines()).Should(BeNumerically(">", 2))

		//Due to the ssh connection, sometimes the result has one line more in
		//any output. So we check at least 5 lines are in the all outputs.
		for i := 0; i < 5; i++ {
			//ln: return a random number in the array len upper than 5 (First 5 lines)
			ln := rand.Intn((len(monitorRes[0].ByLines())-1)-5) + 5
			str := monitorRes[0].ByLines()[ln]
			Expect(monitorRes[1].Output().String()).Should(ContainSubstring(str))
			Expect(monitorRes[2].Output().String()).Should(ContainSubstring(str))
		}
	})

	It("checks container ids match monitor output", func() {
		res := vm.ExecCilium(fmt.Sprintf("config %s=true", MonitorDebug))
		res.ExpectSuccess()
		res = vm.SetPolicyEnforcement(helpers.PolicyEnforcementAlways)
		res.ExpectSuccess()

		prepareContainers()
		defer cleanupContainers()

		ctx, cancel := context.WithCancel(context.Background())
		res = vm.ExecContext(ctx, "cilium monitor -v")

		vm.ContainerExec(helpers.Client, helpers.Ping(helpers.Server))
		vm.ContainerExec(helpers.Server, helpers.Ping(helpers.Client))

		endpoints, err := vm.GetEndpointsIDMap()
		Expect(err).Should(BeNil())

		helpers.Sleep(2)
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
					break
				case "id":
					toID = fields[i+1]
					break
				}
			}
			if fromID == "" || toID == "" {
				continue
			}
			By(fmt.Sprintf("checking endpoints in monitor line:\n%s",
				line))

			Expect(toID).Should(Not(Equal(fromID)))
			Expect(endpoints[toID]).Should(Not(BeNil()))
			Expect(endpoints[fromID]).Should(Not(BeNil()))
		}
	})
})
