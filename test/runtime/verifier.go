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

	"github.com/cilium/cilium/test/config"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

const (
	script = "bpf/verifier-test.sh"
)

var _ = Describe("RuntimeVerifier", func() {
	var vm *helpers.SSHMeta

	BeforeAll(func() {
		vm = helpers.InitRuntimeHelper(helpers.Runtime, logger)
		ExpectCiliumReady(vm)

		By("Stopping Cilium")
		res := vm.ExecWithSudo("systemctl stop cilium")
		res.ExpectSuccess()
		ExpectCiliumNotRunning(vm)
		res = vm.ExecWithSudo("rm -f /sys/fs/bpf/tc/globals/cilium*")
		res.ExpectSuccess()
		cmd := fmt.Sprintf("make -C %s/../bpf clean V=0", helpers.BasePath)
		res = vm.Exec(cmd)
		res.ExpectSuccess("Expected cleaning the bpf/ tree to succeed")
	})

	AfterFailed(func() {
		if config.CiliumTestConfig.HoldEnvironment {
			GinkgoPrint("Skipped gathering logs (-cilium.holdEnvironment=true)\n")
			return
		}

		GinkgoPrint("===================== TEST FAILED =====================")
		commands := []string{"clang --version", "uname -a"}
		for _, cmd := range commands {
			res := vm.ExecWithSudo(fmt.Sprintf("%s", cmd))
			GinkgoPrint(res.GetDebugMessage())
		}
		GinkgoPrint("===================== EXITING REPORT GENERATION =====================\n")
	})

	AfterAll(func() {
		err := vm.RestartCilium()
		Expect(err).Should(BeNil(), "restarting Cilium failed")
		vm.CloseSSHClient()
	})

	It("runs the kernel verifier against the tree copy of the BPF datapath", func() {
		By("Building BPF objects from the tree")
		cmd := fmt.Sprintf("make -C %s/../bpf V=0", helpers.BasePath)
		res := vm.Exec(cmd)
		res.ExpectSuccess("Expected compilation of the BPF objects to succeed")

		By("Running the verifier test script")
		cmd = fmt.Sprintf("%s/%s", helpers.BasePath, script)
		res = vm.ExecWithSudo(cmd)
		res.ExpectSuccess("Expected the kernel verifier to pass for BPF programs")
	})
})
