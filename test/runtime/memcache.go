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

var _ = Describe("RuntimeMemcacheBinary", func() {

	var (
		vm         *helpers.SSHMeta
		memcacheIP string
	)

	containers := func(mode string) {

		images := map[string]string{
			"memcache":        "memcached",
			"memcache-client": "nebril/python-binary-memcached",
		}
		cmds := map[string][]string{
			"memcache-client": {"sleep", "10000"},
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
			memcache, err := vm.ContainerInspectNet("memcache")
			Expect(err).Should(BeNil(), "Could not get memcache network")
			memcacheIP = memcache["IPv4"]

		case "delete":
			for k := range images {
				vm.ContainerRm(k)
			}
		}
	}

	setKey := func(key, value string) *helpers.CmdRes {
		logger.Infof("Setting %s as %s", key, value)
		res := vm.ContainerExec("memcache-client", fmt.Sprintf(
			`python -c 'import bmemcached; client = bmemcached.Client(("%s:11211", )); print(client.set("%s", "%s"))'`, memcacheIP, key, value))
		return res
	}

	getKey := func(key string) *helpers.CmdRes {
		logger.Infof("Getting %s", key)
		res := vm.ContainerExec("memcache-client", fmt.Sprintf(
			`python -c 'import bmemcached; client = bmemcached.Client(("%s:11211", )); print(client.get("%s"))'`, memcacheIP, key))
		return res
	}

	runWithClient := func(code string) *helpers.CmdRes {
		logger.Infof("Executing %s", code)
		res := vm.ContainerExec("memcache-client", fmt.Sprintf(
			`python -c 'import bmemcached; client = bmemcached.Client(("%s:11211", )); %s'`, memcacheIP, code))
		return res
	}

	BeforeAll(func() {
		vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)

		ExpectCiliumReady(vm)

		containers("create")
		epsReady := vm.WaitEndpointsReady()
		Expect(epsReady).Should(BeTrue(), "Endpoints are not ready after timeout")
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

	It("Tests basic memcache operation", func() {
		key := "test1"
		value := "value1"
		By("Setting memcache value")
		r := setKey(key, value)

		r.ExpectSuccess("Unable to set key", key)

		By("getting memcache value")
		r = getKey(key)
		r.ExpectSuccess("Unable to get key", key)
		r.ExpectContains(value, "Value mismatch on get")
	})

	It("Tests policy allowing all actions", func() {
		_, err := vm.PolicyImportAndWait(vm.GetFullPath("Policies-memcache-binary-allow.json"), 300)
		Expect(err).Should(BeNil(), "Failed to import policy")

		key := "test2"
		value := "value2"
		By("Setting memcache value")
		r := setKey(key, value)
		r.ExpectSuccess("Unable to set key", key)

		By("getting memcache value")
		r = getKey(key)
		r.ExpectSuccess("Unable to get key", key)
		r.ExpectContains(value)
	})

	It("Tests policy disallowing set action", func() {
		By("Setting key before disallowing set")
		keyBeforePolicy := "before"
		valBeforePolicy := "beforeval"
		r := setKey(keyBeforePolicy, valBeforePolicy)
		r.ExpectSuccess("Unable to set key %q without policy loaded", keyBeforePolicy)

		By("Importing policy disallowing set")
		_, err := vm.PolicyImportAndWait(vm.GetFullPath("Policies-memcache-binary-disallow-set.json"), 300)
		Expect(err).Should(BeNil(), "Failed to import policy")

		By("Trying to set new key")
		key := "keyAfterPolicy"
		value := "valAfterPolicy"

		By("Setting memcache value")
		r = setKey(key, value)
		r.ExpectFail("Set key should be prohibited by policy")

		By("getting memcache value")
		r = getKey(keyBeforePolicy)
		r.ExpectSuccess("Unable to get key set before applying policy")
		r.ExpectContains(valBeforePolicy, "Value mismatch on get")
	})

	It("Tests policy allowing actions only for key", func() {
		By("Importing key-specific policy")
		_, err := vm.PolicyImportAndWait(vm.GetFullPath("Policies-memcache-binary-allow-key.json"), 300)
		Expect(err).Should(BeNil(), "Failed to import policy")

		key := "allowed"
		value := "value"
		By("Setting memcache allowed key")
		r := setKey(key, value)
		r.ExpectSuccess("Unable to set allowed key")
		By("Getting memcache allowed key")
		r = getKey(key)
		r.ExpectSuccess("Unable to get allowed key")

		key = "disallowed"
		By("Setting memcache disallowed key")
		r = setKey(key, value)
		r.ExpectFail("Able to set disallowed key")
	})

	It("Tests if you are able to multi-get from a disallowed and allowed keys", func() {
		By("Setting value to both keys")
		r := setKey("allowed", "value")
		r.ExpectSuccess("Unable to set allowed value")
		r = setKey("disallowed", "value")
		r.ExpectSuccess("Unable to set disallowed value")

		By("Importing key-specific policy")
		_, err := vm.PolicyImportAndWait(vm.GetFullPath("Policies-memcache-binary-allow-key-get.json"), 300)
		Expect(err).Should(BeNil(), "Failed to import policy")

		By("Getting multiple keys")
		code := "print(client.get_multi([\"allowed\", \"disallowed\"]))"
		r = runWithClient(code)

		r.ExpectFail("Unable to get multiple keys")
	})
})
