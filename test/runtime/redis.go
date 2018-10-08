// Copyright 2018 Authors of Cilium
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
	"fmt"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

var _ = Describe("RuntimeRedis", func() {

	var (
		vm      *helpers.SSHMeta
		redisIP string
	)

	containers := func(mode string) {

		images := map[string]string{
			"redis-server": "redis",
			"redis-client": "redis",
		}
		cmds := map[string][]string{
			"redis-client": {"sleep", "10000"},
		}

		switch mode {
		case "create":
			for k, v := range images {
				cmd, ok := cmds[k]
				var res *helpers.CmdRes
				if ok {
					res = vm.ContainerCreate(k, v, helpers.CiliumDockerNetwork, fmt.Sprintf("-l id.%s", k), cmd...)
				} else {
					res = vm.ContainerCreate(k, v, helpers.CiliumDockerNetwork, fmt.Sprintf("-l id.%s", k))
				}
				res.ExpectSuccess("failed to create container %s", k)
			}
			redisServer, err := vm.ContainerInspectNet("redis-server")
			Expect(err).Should(BeNil(), "Could not get redis-server network info")
			redisIP = redisServer["IPv4"]

		case "delete":
			for k := range images {
				vm.ContainerRm(k)
			}
		}
	}

	runRedisCli := func(cmd string) *helpers.CmdRes {
		logger.Infof("Executing command '%s'", cmd)
		res := vm.ContainerExec("redis-client", fmt.Sprintf(`redis-cli -h %s %s`, redisIP, cmd))
		return res
	}

	// Waits for the server to be ready, by executing
	// a command repeatedly until it succeeds, or a timeout occurs
	waitForRedisServer := func() error {
		body := func() bool {
			res := runRedisCli("PING")
			return res.WasSuccessful()
		}
		err := helpers.WithTimeout(body, "Redis server not ready", &helpers.TimeoutConfig{Timeout: helpers.HelperTimeout})
		return err
	}

	BeforeAll(func() {
		vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)

		ExpectCiliumReady(vm)

		containers("create")
		epsReady := vm.WaitEndpointsReady()
		Expect(epsReady).Should(BeTrue(), "Endpoints are not ready after timeout")

		err := waitForRedisServer()
		Expect(err).To(BeNil(), "Redis Server failed to come up")

	})

	AfterEach(func() {
		vm.PolicyDelAll()
	})

	AfterAll(func() {
		containers("delete")
	})

	JustAfterEach(func() {
		vm.ValidateNoErrorsOnLogs(CurrentGinkgoTestDescription().Duration)
	})

	AfterFailed(func() {
		vm.ReportFailed("cilium policy get")
	})

	It("Tests policy allowing all actions", func() {
		_, err := vm.PolicyImportAndWait(vm.GetFullPath("Policies-redis-allow-all.json"), 300)
		Expect(err).Should(BeNil(), "Failed to import policy")

		endPoints, err := vm.PolicyEndpointsSummary()
		Expect(err).Should(BeNil(), "Cannot get endpoint list")
		Expect(endPoints[helpers.Enabled]).To(Equal(1),
			"Check number of endpoints with policy enforcement enabled")
		Expect(endPoints[helpers.Disabled]).To(Equal(1),
			"Check number of endpoints with policy enforcement disabled")

		By("Setting Value in Redis (no policy)")
		r := runRedisCli("SET mykey foo")
		r.ExpectSuccess("Unable to 'set' on key 'mykey'")

		By("Getting Value in Redis (no policy)")
		r = runRedisCli("GET mykey")
		r.ExpectSuccess("Unable to 'get' on key 'mykey'")
		r.ExpectContains("foo", "Did not see expected value in 'get'")
	})

	It("Tests policy disallowing 'get' action", func() {

		_, err := vm.PolicyImportAndWait(vm.GetFullPath("Policies-redis-allow-specific-set.json"), 300)
		Expect(err).Should(BeNil(), "Failed to import policy")

		endPoints, err := vm.PolicyEndpointsSummary()
		Expect(err).Should(BeNil(), "Cannot get endpoint list")
		Expect(endPoints[helpers.Enabled]).To(Equal(1),
			"Check number of endpoints with policy enforcement enabled")
		Expect(endPoints[helpers.Disabled]).To(Equal(1),
			"Check number of endpoints with policy enforcement disabled")

		By("Setting value in Redis (allowed by policy)")
		r := runRedisCli("SET team packers")
		r.ExpectSuccess("Unable to set key 'team'")
		r.ExpectContains("OK", "Did not get 'OK' response from server after set")

		By("Getting value from Redis (denied by policy)")
		r = runRedisCli("GET team")
		r.ExpectDoesNotContain("packers", "Got value on 'get' that should not have not been allowed")
		r.ExpectContains("Access Denied", "Did not get 'Access Denied' error as expected")

		By("Setting value in Redis (denied by policy)")
		r = runRedisCli("SET player rogers")
		r.ExpectDoesNotContain("OK", "Got 'OK' response on set that should not have not been allowed")
		r.ExpectContains("Access Denied", "Did not get 'Access Denied' error as expected")
	})

})
