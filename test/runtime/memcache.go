// Copyright 2018-2019 Authors of Cilium
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
	"time"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	"github.com/cilium/cilium/test/helpers/constants"

	. "github.com/onsi/gomega"
)

var _ = XDescribe("RuntimeMemcache", func() {

	var (
		vm            *helpers.SSHMeta
		testStartTime time.Time
		memcacheIP    string
	)

	containers := func(mode string) {

		images := map[string]string{
			"memcache":             constants.MemcacheDImage,
			"memcache-bin-client":  constants.MemcacheBinClient,
			"memcache-text-client": constants.AlpineImage,
		}
		cmds := map[string][]string{
			"memcache-bin-client":  {"sleep", "10000"},
			"memcache-text-client": {"sleep", "10000"},
		}

		switch mode {
		case "create":
			for k, v := range images {
				cmd, ok := cmds[k]
				var res *helpers.CmdRes
				if ok {
					// client containers
					res = vm.ContainerCreate(k, v, helpers.CiliumDockerNetwork, "-l memcache-client", cmd...)
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

	setKeyBinary := func(key, value string) *helpers.CmdRes {
		logger.Infof("Setting %s as %s", key, value)
		res := vm.ContainerExec("memcache-bin-client", fmt.Sprintf(
			`python -c 'import bmemcached; client = bmemcached.Client(("%s:11211", )); print(client.set("%s", "%s"))'`, memcacheIP, key, value))
		return res
	}

	getKeyBinary := func(key string) *helpers.CmdRes {
		logger.Infof("Getting %s", key)
		res := vm.ContainerExec("memcache-bin-client", fmt.Sprintf(
			`python -c 'import bmemcached; client = bmemcached.Client(("%s:11211", )); print(client.get("%s"))'`, memcacheIP, key))
		return res
	}

	runWithClientBinary := func(code string) *helpers.CmdRes {
		logger.Infof("Executing %s", code)
		res := vm.ContainerExec("memcache-bin-client", fmt.Sprintf(
			`python -c 'import bmemcached; client = bmemcached.Client(("%s:11211", )); %s'`, memcacheIP, code))
		return res
	}

	flush := func() *helpers.CmdRes {
		logger.Infof("flushing memcached")
		cmd := fmt.Sprintf(
			`sh -c 'echo -en "flush_all\r\nquit\r\n" | nc %s 11211'`, memcacheIP)
		res := vm.ContainerExec("memcache-text-client", cmd)
		return res
	}

	BeforeAll(func() {
		vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)

		ExpectCiliumReady(vm)

		containers("create")
		Expect(vm.WaitEndpointsReady()).Should(BeTrue(), "Endpoints are not ready after timeout")
	})

	AfterEach(func() {
		vm.PolicyDelAll()
		flush().ExpectContains("OK", "Unable to flush memcache")
	})

	AfterAll(func() {
		containers("delete")
		vm.CloseSSHClient()
	})

	JustBeforeEach(func() {
		testStartTime = time.Now()
	})

	JustAfterEach(func() {
		vm.ValidateNoErrorsInLogs(time.Since(testStartTime))
	})

	AfterFailed(func() {
		containers("delete")
		vm.ReportFailed("cilium policy get")
	})

	Context("Testing binary memcache", func() {
		It("Tests basic memcache operation", func() {
			key := "test1"
			value := "value1"
			By("Setting memcache value")
			r := setKeyBinary(key, value)

			r.ExpectSuccess("Unable to set key %s", key)

			By("getting memcache value")
			r = getKeyBinary(key)
			r.ExpectSuccess("Unable to get key %s", key)
			r.ExpectContains(value, "Value mismatch on get")
		})

		It("Tests policy allowing all actions", func() {
			_, err := vm.PolicyImportAndWait(vm.GetFullPath("Policies-memcache-allow.json"), helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Failed to import policy")

			key := "test2"
			value := "value2"
			By("Setting memcache value")
			r := setKeyBinary(key, value)
			r.ExpectSuccess("Unable to set key %s", key)

			By("getting memcache value")
			r = getKeyBinary(key)
			r.ExpectSuccess("Unable to get key %s", key)
			r.ExpectContains(value, "Value mismatch for key %s", key)
		})

		It("Tests policy disallowing set action", func() {
			By("Setting key before disallowing set")
			keyBeforePolicy := "before"
			valBeforePolicy := "beforeval"
			r := setKeyBinary(keyBeforePolicy, valBeforePolicy)
			r.ExpectSuccess("Unable to set key %q without policy loaded", keyBeforePolicy)

			By("Importing policy disallowing set")
			_, err := vm.PolicyImportAndWait(vm.GetFullPath("Policies-memcache-disallow-set.json"), helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Failed to import policy")

			By("Trying to set new key")
			key := "keyAfterPolicy"
			value := "valAfterPolicy"

			By("Setting memcache value")
			r = setKeyBinary(key, value)
			r.ExpectFail("Set key should be prohibited by policy")

			By("getting memcache value")
			r = getKeyBinary(keyBeforePolicy)
			r.ExpectSuccess("Unable to get key set before applying policy")
			r.ExpectContains(valBeforePolicy, "Value mismatch on get")
		})

		It("Tests policy allowing actions only for key", func() {
			By("Importing key-specific policy")
			_, err := vm.PolicyImportAndWait(vm.GetFullPath("Policies-memcache-allow-key.json"), helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Failed to import policy")

			key := "allowed"
			value := "value"
			By("Setting memcache allowed key")
			r := setKeyBinary(key, value)
			r.ExpectSuccess("Unable to set allowed key")
			By("Getting memcache allowed key")
			r = getKeyBinary(key)
			r.ExpectSuccess("Unable to get allowed key")

			key = "disallowed"
			By("Setting memcache disallowed key")
			r = setKeyBinary(key, value)
			r.ExpectFail("Able to set disallowed key")
		})

		It("Tests multi-get from a disallowed and allowed keys set", func() {
			By("Setting value to both keys")
			r := setKeyBinary("allowed", "value")
			r.ExpectSuccess("Unable to set allowed value")
			r = setKeyBinary("disallowed", "value")
			r.ExpectSuccess("Unable to set disallowed value")

			By("Importing key-specific policy")
			_, err := vm.PolicyImportAndWait(vm.GetFullPath("Policies-memcache-allow-key-get.json"), helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Failed to import policy")

			By("Getting multiple keys")
			code := "print(client.get_multi([\"allowed\", \"disallowed\"]))"
			r = runWithClientBinary(code)

			r.ExpectFail("Able to get multiple keys with disallowed")
		})
	})

	setKeyText := func(key, value string) *helpers.CmdRes {
		logger.Infof("Setting %s as %s", key, value)
		cmd := fmt.Sprintf(
			`sh -c 'echo -en "set %s 0 500 %d\r\n%s\r\nquit\r\n" | nc %s 11211'`, key, len(value), value, memcacheIP)
		res := vm.ContainerExec("memcache-text-client", cmd)
		return res
	}

	getKeyText := func(key string) *helpers.CmdRes {
		logger.Infof("Getting %s", key)
		res := vm.ContainerExec("memcache-text-client", fmt.Sprintf(
			`sh -c 'echo -en "get %s\r\nquit\r\n" | nc %s 11211'`, key, memcacheIP))
		return res
	}

	Context("Testing text memcache", func() {
		It("Tests basic memcache operation", func() {
			key := "test1"
			value := "value1"
			By("Setting memcache value")
			r := setKeyText(key, value)
			r.ExpectSuccess("Unable to set key %s", key)
			r.ExpectContains("STORED", "value not stored")

			By("getting memcache value")
			r = getKeyText(key)
			r.ExpectSuccess("Unable to get key %s", key)
			r.ExpectContains(value, "Value mismatch on get")
			r.ExpectContains("VALUE", "Did not have text VALUE header")
		})

		It("Tests policy allowing all actions", func() {
			_, err := vm.PolicyImportAndWait(vm.GetFullPath("Policies-memcache-allow.json"), helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Failed to import policy")

			key := "test2"
			value := "value2"
			By("Setting memcache value")
			r := setKeyText(key, value)
			r.ExpectSuccess("Unable to set key, %s", key)
			r.ExpectContains("STORED", "value not stored")

			By("getting memcache value")
			r = getKeyText(key)
			r.ExpectSuccess("Unable to get key, %s", key)
			r.ExpectContains(value, "memcache key %s value mismatch", key)
			r.ExpectContains("VALUE", "Did not have text VALUE header")
		})

		It("Tests policy disallowing set action", func() {
			By("Setting key before disallowing set")
			keyBeforePolicy := "before"
			valBeforePolicy := "beforeval"
			r := setKeyText(keyBeforePolicy, valBeforePolicy)
			r.ExpectSuccess("Unable to set key %q without policy loaded", keyBeforePolicy)
			r.ExpectContains("STORED", "value not stored")

			By("Importing policy disallowing set")
			_, err := vm.PolicyImportAndWait(vm.GetFullPath("Policies-memcache-disallow-set.json"), helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Failed to import policy")

			By("Trying to set new key")
			key := "keyAfterPolicy"
			value := "valAfterPolicy"

			By("Setting memcache value")
			r = setKeyText(key, value)
			r.ExpectSuccess("Unable to set key %s", key)
			r.ExpectContains("access denied", "did not get access denied message")

			By("getting memcache value")
			r = getKeyText(keyBeforePolicy)
			r.ExpectSuccess("Unable to get key set before applying policy")
			r.ExpectContains(valBeforePolicy, "Value mismatch on get")
		})

		It("Tests policy allowing actions only for allowed key", func() {
			By("Importing key-specific policy")
			_, err := vm.PolicyImportAndWait(vm.GetFullPath("Policies-memcache-allow-key.json"), helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Failed to import policy")

			key := "allowed"
			value := "value"
			By("Setting memcache allowed key")
			r := setKeyText(key, value)
			r.ExpectSuccess("Unable to set allowed key")
			By("Getting memcache allowed key")
			r = getKeyText(key)
			r.ExpectSuccess("Unable to get allowed key")

			key = "disallowed"
			By("Setting memcache disallowed key")
			r = setKeyText(key, value)
			r.ExpectSuccess("Unable to set key %s", key)
			r.ExpectContains("access denied", "did not get access denied message")
		})
	})
})
