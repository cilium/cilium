// Copyright 2020 Authors of Cilium
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

package k8sTest

import (
	"fmt"
	"strings"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

const (
	script      = "bpf/verifier-test.sh"
	podName     = "test-verifier"
	podManifest = "test-verifier.yaml"
)

// This test tries to compile BPF programs with a set of options that maximize
// size & complexity (as defined in bpf/Makefile). Programs are then loaded in
// the kernel by test-verifier.sh to detect complexity & other verifier-related
// regressions.
//
// In our K8s test pipelines, we can only access VMs through kubeconfig. Thus,
// to be able to compile and load the BPF programs on the VM, we define a new
// privileged Pod (test-verifier) which mounts the bpffs and the Cilium source
// directory. All test commands are executed in this privileged Pod after
// uninstalling Cilium from the cluster.
var _ = Describe("K8sVerifier", func() {
	var kubectl *helpers.Kubectl

	collectObjectFiles := func() {
		testPath, err := helpers.CreateReportDirectory()
		if err != nil {
			GinkgoPrint(fmt.Sprintf("Cannot create test results directory %s", testPath))
			return
		}
		res := kubectl.Exec("kubectl exec test-verifier -- ls bpf/")
		for _, file := range strings.Split(strings.TrimSuffix(res.Stdout(), "\n"), "\n") {
			if strings.HasSuffix(file, ".o") {
				cmd := fmt.Sprintf("kubectl cp %s:bpf/%s \"%s/%s\"", podName, file, testPath, file)
				res = kubectl.Exec(cmd)
				if !res.WasSuccessful() {
					GinkgoPrint(fmt.Sprintf("Failed to cp BPF object file: %s\n%s", cmd, res.Stderr()))
				}
			}
		}
	}
	BeforeAll(func() {
		SkipIfIntegration(helpers.CIIntegrationGKE)

		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		// We don't check the returned error because Cilium could
		// already be removed (e.g., first test to run).
		kubectl.DeleteResource("ds", fmt.Sprintf("-n %s cilium", helpers.CiliumNamespace))
		ExpectCiliumNotRunning(kubectl)

		testVerifierManifest := helpers.ManifestGet(kubectl.BasePath(), podManifest)
		res := kubectl.ApplyDefault(testVerifierManifest)
		res.ExpectSuccess("Unable to apply %s", testVerifierManifest)
		err := kubectl.WaitForSinglePod(helpers.DefaultNamespace, podName, helpers.HelperTimeout)
		Expect(err).Should(BeNil(), fmt.Sprintf("%s pod not ready after timeout", podName))

		res = kubectl.ExecPodCmd(helpers.DefaultNamespace, podName, "make -C bpf clean V=0")
		res.ExpectSuccess("Failed to clean up bpf/ tree")
	})

	AfterFailed(func() {
		res := kubectl.Exec("kubectl describe nodes")
		GinkgoPrint(res.CombineOutput().String())
		res = kubectl.Exec("kubectl describe pods")
		GinkgoPrint(res.CombineOutput().String())

		By("Collecting bpf_*.o artifacts")
		collectObjectFiles()
	})

	AfterAll(func() {
		kubectl.DeleteResource("pod", podName)
	})

	It("Runs the kernel verifier against Cilium's BPF datapath", func() {
		By("Building BPF objects from the tree")
		kernel := "49"
		switch {
		case helpers.RunsOnNetNextKernel():
			kernel = "netnext"
		case helpers.RunsOn419Kernel():
			kernel = "419"
		case helpers.RunsOn54Kernel():
			kernel = "54"
		}
		cmd := fmt.Sprintf("make -C bpf KERNEL=%s", kernel)
		res := kubectl.ExecPodCmd(helpers.DefaultNamespace, podName, cmd)
		res.ExpectSuccess("Expected compilation of the BPF objects to succeed")
		res = kubectl.ExecPodCmd(helpers.DefaultNamespace, podName, "make -C tools/maptool/")
		res.ExpectSuccess("Expected compilation of maptool to succeed")

		if helpers.RunsOn419Kernel() {
			// On 4.19, we need to remove global data sections before loading
			// those programs. The libbpf version used in our bpftool (which
			// loads these two programs), rejects global data.
			By("Remove global data section")
			for _, prog := range []string{"bpf/sockops/bpf_sockops.o", "bpf/sockops/bpf_redir.o"} {
				cmd := "llvm-objcopy --remove-section=.debug_info --remove-section=.BTF --remove-section=.data /cilium/%s /cilium/%s"
				res := kubectl.ExecPodCmd(helpers.DefaultNamespace, podName,
					fmt.Sprintf(cmd, prog, prog))
				res.ExpectSuccess(fmt.Sprintf("Expected deletion of object file sections from %s to succeed.", prog))
			}
		}

		By("Running the verifier test script")
		cmd = fmt.Sprintf("test/%s", script)
		res = kubectl.ExecPodCmd(helpers.DefaultNamespace, podName, cmd)
		res.ExpectSuccess("Expected the kernel verifier to pass for BPF programs")
	})
})
