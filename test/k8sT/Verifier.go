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
	"bufio"
	"fmt"
	"os"
	"strings"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

const (
	script      = "bpf/verifier-test.sh"
	podName     = "test-verifier"
	podManifest = "test-verifier.yaml"

	HookTC     = "TC"
	HookCgroup = "CG"
	HookXDP    = "XDP"
)

type BPFProgram struct {
	name      string
	hook      string
	macroName string
}

var (
	bpfPrograms = []BPFProgram{
		{
			name:      "bpf_lxc",
			hook:      HookTC,
			macroName: "MAX_LXC_OPTIONS",
		},
		{
			name:      "bpf_host",
			hook:      HookTC,
			macroName: "MAX_HOST_OPTIONS",
		},
		{
			name:      "bpf_xdp",
			hook:      HookXDP,
			macroName: "MAX_XDP_OPTIONS",
		},
		{
			name:      "bpf_overlay",
			hook:      HookTC,
			macroName: "MAX_OVERLAY_OPTIONS",
		},
		{
			name:      "bpf_sock",
			hook:      HookCgroup,
			macroName: "MAX_LB_OPTIONS",
		},
	}
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

	getKernel := func() string {
		kernel := "49"
		switch {
		case helpers.RunsOnNetNextKernel():
			kernel = "netnext"
		case helpers.RunsOn419Kernel():
			kernel = "419"
		case helpers.RunsOn54Kernel():
			kernel = "54"
		}
		return kernel
	}

	getDatapathConfigFile := func(bpfProgram string) string {
		return fmt.Sprintf("../bpf/complexity-tests/%s/%s.txt", getKernel(), bpfProgram)
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
		res := kubectl.ExecPodCmd(helpers.DefaultNamespace, podName, "make -C tools/maptool/")
		res.ExpectSuccess("Expected compilation of maptool to succeed")

		for _, bpfProgram := range bpfPrograms {
			file, err := os.Open(getDatapathConfigFile(bpfProgram.name))
			Expect(err).Should(BeNil(), fmt.Sprintf("Unable to open list of datapath configurations for %s", bpfProgram.name))
			defer file.Close()

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				datapathConfig := scanner.Text()

				By("Cleaning %s build files", bpfProgram.name)
				cmd := fmt.Sprintf("make -C bpf clean")
				res := kubectl.ExecPodCmd(helpers.DefaultNamespace, podName, cmd)
				res.ExpectSuccess("Expected clean target to succeed")

				By("Building %s object file", bpfProgram.name)
				cmd = fmt.Sprintf("make -C bpf %s.o KERNEL=%s %s=%q", bpfProgram.name, getKernel(), bpfProgram.macroName, datapathConfig)
				res = kubectl.ExecPodCmd(helpers.DefaultNamespace, podName, cmd)
				res.ExpectSuccess(fmt.Sprintf("Expected the compilation of %s to succeed", bpfProgram.name))

				By("Running the verifier test script with %s", bpfProgram.name)
				cmd = fmt.Sprintf("env TC_PROGS=\"\" XDP_PROGS=\"\" CG_PROGS=\"\" %s_PROGS=%q ./test/%s", bpfProgram.hook, bpfProgram.name, script)
				res = kubectl.ExecPodCmd(helpers.DefaultNamespace, podName, cmd)
				res.ExpectSuccess(fmt.Sprintf("Failed to load BPF program %s with datapath configuration:\n%s", bpfProgram.name, datapathConfig))
			}

			err = scanner.Err()
			Expect(err).Should(BeNil(), fmt.Sprintf("Error while reading list of datapath configurations for %s", bpfProgram.name))
		}
	})
})
