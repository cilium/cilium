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
		res := kubectl.Exec("kubectl describe pod")
		GinkgoPrint(res.CombineOutput().String())
	})

	AfterAll(func() {
		kubectl.DeleteResource("pod", podName)
	})

	SkipItIf(helpers.RunsOnNetNextOr419Kernel, "Runs the kernel verifier against Cilium's BPF datapath", func() {
		By("Building BPF objects from the tree")
		res := kubectl.ExecPodCmd(helpers.DefaultNamespace, podName, "make -C bpf V=0")
		res.ExpectSuccess("Expected compilation of the BPF objects to succeed")
		res = kubectl.ExecPodCmd(helpers.DefaultNamespace, podName, "make -C tools/maptool/")
		res.ExpectSuccess("Expected compilation of maptool to succeed")

		By("Running the verifier test script")
		cmd := fmt.Sprintf("test/%s", script)
		res = kubectl.ExecPodCmd(helpers.DefaultNamespace, podName, cmd)
		res.ExpectSuccess("Expected the kernel verifier to pass for BPF programs")
	})
})
