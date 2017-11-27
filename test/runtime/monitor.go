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

	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	log "github.com/sirupsen/logrus"
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

var _ = Describe("RuntimeMonitorTest", func() {

	var initialized bool
	var logger *log.Entry
	var docker *helpers.Docker
	var cilium *helpers.Cilium

	initialize := func() {
		if initialized == true {
			return
		}
		logger = log.WithFields(log.Fields{"testName": "RuntimeMonitorTest"})
		logger.Info("Starting")
		docker, cilium = helpers.CreateNewRuntimeHelper(helpers.Runtime, logger)
		cilium.WaitUntilReady(100)
		docker.NetworkCreate(helpers.CiliumDockerNetwork, "")

		res := cilium.SetPolicyEnforcement(helpers.PolicyEnforcementDefault, false)
		res.ExpectSuccess()

		initialized = true
	}

	BeforeEach(func() {
		initialize()
	})

	AfterEach(func() {

		if CurrentGinkgoTestDescription().Failed {
			cilium.ReportFailed()
		}

		docker.SampleContainersActions(helpers.Delete, helpers.CiliumDockerNetwork)
	})

	It("Cilium monitor verbose mode", func() {

		res := cilium.Exec(fmt.Sprintf("config %s=true %s=true %s=true",
			MonitorDebug, MonitorDropNotification, MonitorTraceNotification))
		res.ExpectSuccess()

		ctx, cancel := context.WithCancel(context.Background())

		res = docker.Node.ExecContext(ctx, "cilium monitor -v")
		docker.SampleContainersActions(helpers.Create, helpers.CiliumDockerNetwork)
		helpers.Sleep(5)
		cancel()
		endpoints, err := cilium.GetEndpointsIds()
		Expect(err).Should(BeNil())

		for k, v := range endpoints {
			filter := fmt.Sprintf("FROM %s DEBUG:", v)
			docker.ContainerExec(k, helpers.Ping(helpers.Httpd1))
			Expect(res.Output().String()).Should(ContainSubstring(filter))
		}
	})

	It("Cilium monitor event types", func() {
		eventTypes := map[string]string{
			"drop":    "DROP:",
			"debug":   "DEBUG:",
			"capture": "DEBUG:",
		}

		res := cilium.Exec(fmt.Sprintf("config %s=true %s=true %s=true",
			MonitorDebug, MonitorDropNotification, MonitorTraceNotification))
		res.ExpectSuccess()
		for k, v := range eventTypes {
			By(fmt.Sprintf("Type %s", k))

			ctx, cancel := context.WithCancel(context.Background())
			res := docker.Node.ExecContext(ctx, fmt.Sprintf("cilium monitor --type %s -v", k))
			docker.SampleContainersActions(helpers.Create, helpers.CiliumDockerNetwork)
			docker.ContainerExec(helpers.App1, helpers.Ping(helpers.Httpd1))
			helpers.Sleep(5)
			cancel()

			Expect(res.CountLines()).Should(BeNumerically(">", 3))
			Expect(res.Output().String()).Should(ContainSubstring(v))
			docker.SampleContainersActions(helpers.Delete, helpers.CiliumDockerNetwork)
		}
	})

	It("cilium monitor check --from", func() {
		res := cilium.Exec(fmt.Sprintf("config %s=true %s=true %s=true", MonitorDebug, MonitorDropNotification, MonitorTraceNotification))
		res.ExpectSuccess()

		docker.SampleContainersActions(helpers.Create, helpers.CiliumDockerNetwork)
		endpoints, err := cilium.GetEndpointsIds()
		Expect(err).Should(BeNil())

		ctx, cancel := context.WithCancel(context.Background())
		res = docker.Node.ExecContext(ctx, fmt.Sprintf(
			"cilium monitor --type debug --from %s -v", endpoints[helpers.App1]))
		docker.ContainerExec(helpers.App1, helpers.Ping(helpers.Httpd1))
		helpers.Sleep(5)
		cancel()

		Expect(res.CountLines()).Should(BeNumerically(">", 3))
		filter := fmt.Sprintf("FROM %s DEBUG:", endpoints[helpers.App1])
		Expect(res.Output().String()).Should(ContainSubstring(filter))

		//MonitorDebug mode shouldn't have DROP lines
		Expect(res.Output().String()).ShouldNot(ContainSubstring("DROP"))

	})

	It("cilium monitor check --to", func() {

		res := cilium.Exec(fmt.Sprintf(
			"config %s=true %s=true %s=true %s=always", MonitorDebug, MonitorDropNotification, MonitorTraceNotification, helpers.PolicyEnforcement))
		res.ExpectSuccess()

		docker.SampleContainersActions(helpers.Create, helpers.CiliumDockerNetwork)
		endpoints, err := cilium.GetEndpointsIds()
		Expect(err).Should(BeNil())
		cilium.WaitEndpointsReady()
		ctx, cancel := context.WithCancel(context.Background())
		res = docker.Node.ExecContext(ctx, fmt.Sprintf(
			"cilium monitor --type drop -v --to %s", endpoints[helpers.Httpd1]))

		docker.ContainerExec(helpers.App1, helpers.Ping(helpers.Httpd1))
		docker.ContainerExec(helpers.App2, helpers.Ping(helpers.Httpd1))
		helpers.Sleep(5)
		cancel()

		Expect(res.CountLines()).Should(BeNumerically(">", 3))
		filter := fmt.Sprintf("FROM %s DROP:", endpoints[helpers.Httpd1])
		Expect(res.Output().String()).Should(ContainSubstring(filter))

	})

	It("cilium monitor check --related-to", func() {

		res := cilium.Exec(fmt.Sprintf(
			"config %s=true %s=true %s=true %s=always", MonitorDebug, MonitorDropNotification, MonitorTraceNotification, helpers.PolicyEnforcement))
		res.ExpectSuccess()

		docker.SampleContainersActions(helpers.Create, helpers.CiliumDockerNetwork)
		endpoints, err := cilium.GetEndpointsIds()
		Expect(err).Should(BeNil())

		ctx, cancel := context.WithCancel(context.Background())
		res = docker.Node.ExecContext(ctx, fmt.Sprintf(
			"cilium monitor -v --type drop --related-to %s", endpoints[helpers.Httpd1]))
		cilium.WaitEndpointsReady()
		docker.ContainerExec(helpers.App1, helpers.CurlFail("http://httpd1/public"))

		helpers.Sleep(2)
		cancel()
		Expect(res.CountLines()).Should(BeNumerically(">=", 3))
		filter := fmt.Sprintf("FROM %s DROP:", endpoints[helpers.Httpd1])
		Expect(res.Output().String()).Should(ContainSubstring(filter))
	})

	It("multiple monitors", func() {

		res := cilium.Exec(fmt.Sprintf(
			"config %s=true %s=true %s=true %s=default", MonitorDebug, MonitorDropNotification, MonitorTraceNotification, helpers.PolicyEnforcement))
		res.ExpectSuccess()

		var monitorRes []*helpers.CmdRes

		docker.ContainerCreate(helpers.Client, helpers.NetperfImage, helpers.CiliumDockerNetwork, "-l id.client")
		docker.ContainerCreate(helpers.Server, helpers.NetperfImage, helpers.CiliumDockerNetwork, "-l id.server")

		defer docker.ContainerRm(helpers.Client)
		defer docker.ContainerRm(helpers.Server)

		ctx, cancelfn := context.WithCancel(context.Background())

		for i := 1; i <= 3; i++ {
			monitorRes = append(monitorRes, docker.Node.ExecContext(ctx, "cilium monitor"))
		}

		docker.ContainerExec(helpers.Client, helpers.Ping(helpers.Server))
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
})
