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

package k8sTest

import (
	"fmt"
	"time"

	"github.com/cilium/cilium/test/config"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	. "github.com/onsi/gomega"
)

var longTimeout = 10 * time.Minute

// ExpectKubeDNSReady is a wrapper around helpers/WaitKubeDNS. It asserts that
// the error returned by that function is nil.
func ExpectKubeDNSReady(vm *helpers.Kubectl) {
	By("Waiting for kube-dns to be ready")
	err := vm.WaitKubeDNS()
	ExpectWithOffset(1, err).Should(BeNil(), "kube-dns was not able to get into ready state")

	By("Running kube-dns preflight check")
	err = vm.KubeDNSPreFlightCheck()
	ExpectWithOffset(1, err).Should(BeNil(), "kube-dns service not ready")
}

// ExpectCiliumReady is a wrapper around helpers/WaitForPods. It asserts that
// the error returned by that function is nil.
func ExpectCiliumReady(vm *helpers.Kubectl) {
	err := vm.WaitforPods(helpers.CiliumNamespace, "-l k8s-app=cilium", longTimeout)
	ExpectWithOffset(1, err).Should(BeNil(), "cilium was not able to get into ready state")

	err = vm.CiliumPreFlightCheck()
	ExpectWithOffset(1, err).Should(BeNil(), "cilium pre-flight checks failed")
}

// ExpectCiliumOperatorReady is a wrapper around helpers/WaitForPods. It asserts that
// the error returned by that function is nil.
func ExpectCiliumOperatorReady(vm *helpers.Kubectl) {
	By("Waiting for cilium-operator to be ready")
	err := vm.WaitforPods(helpers.CiliumNamespace, "-l name=cilium-operator", longTimeout)
	ExpectWithOffset(1, err).Should(BeNil(), "Cilium operator was not able to get into ready state")
}

// ExpectCiliumRunning is a wrapper around helpers/WaitForNPods. It
// asserts the cilium pods are running on all nodes (but not yet ready!).
func ExpectCiliumRunning(vm *helpers.Kubectl) {
	err := vm.WaitforNPodsRunning(helpers.CiliumNamespace, "-l k8s-app=cilium", vm.GetNumCiliumNodes(), longTimeout)
	ExpectWithOffset(1, err).Should(BeNil(), "cilium was not able to get into ready state")

}

// ExpectAllPodsTerminated is a wrapper around helpers/WaitCleanAllTerminatingPods.
// It asserts that the error returned by that function is nil.
func ExpectAllPodsTerminated(vm *helpers.Kubectl) {
	err := vm.WaitCleanAllTerminatingPods(helpers.HelperTimeout)
	ExpectWithOffset(1, err).To(BeNil(), "terminating containers are not deleted after timeout")
}

// ExpectETCDOperatorReady is a wrapper around helpers/WaitForNPods. It asserts
// the error returned by that function is nil.
func ExpectETCDOperatorReady(vm *helpers.Kubectl) {
	// Etcd operator creates 5 nodes (1 cilium-etcd-operator + 1 etcd-operator + 3 etcd nodes),
	// the new pods are added when the previous is ready,
	// so we need to wait until 5 pods are in ready state.
	// This is to avoid cases where a few pods are ready, but the
	// new one is not created yet.
	By("Waiting for all etcd-operator pods to be ready")

	err := vm.WaitforNPods(helpers.CiliumNamespace, "-l io.cilium/app=etcd-operator", 5, longTimeout)
	warningMessage := ""
	if err != nil {
		res := vm.Exec(fmt.Sprintf(
			"%s -n %s get pods -l io.cilium/app=etcd-operator",
			helpers.KubectlCmd, helpers.CiliumNamespace))
		warningMessage = res.Output().String()
	}
	Expect(err).To(BeNil(), "etcd-operator is not ready after timeout, pods status:\n %s", warningMessage)
}

// ExpectCiliumPreFlightInstallReady is a wrapper around helpers/WaitForNPods.
// It asserts the error returned by that function is nil.
func ExpectCiliumPreFlightInstallReady(vm *helpers.Kubectl) {
	By("Waiting for all cilium pre-flight pods to be ready")

	err := vm.WaitforPods(helpers.CiliumNamespace, "-l k8s-app=cilium-pre-flight-check", longTimeout)
	warningMessage := ""
	if err != nil {
		res := vm.Exec(fmt.Sprintf(
			"%s -n %s get pods -l k8s-app=cilium-pre-flight-check",
			helpers.KubectlCmd, helpers.CiliumNamespace))
		warningMessage = res.Output().String()
	}
	Expect(err).To(BeNil(), "cilium pre-flight check is not ready after timeout, pods status:\n %s", warningMessage)
}

// DeployCiliumAndDNS deploys DNS and cilium into the kubernetes cluster
func DeployCiliumAndDNS(vm *helpers.Kubectl, ciliumFilename string) {
	DeployCiliumOptionsAndDNS(vm, ciliumFilename, map[string]string{})
}

// DeployCiliumOptionsAndDNS deploys DNS and cilium with options into the kubernetes cluster
func DeployCiliumOptionsAndDNS(vm *helpers.Kubectl, ciliumFilename string, options map[string]string) {
	By("Installing Cilium")
	err := vm.CiliumInstall(ciliumFilename, options)
	Expect(err).To(BeNil(), "Cilium cannot be installed")

	ExpectCiliumRunning(vm)

	By("Installing DNS Deployment")
	_ = vm.ApplyDefault(helpers.DNSDeployment(vm.BasePath()))

	switch helpers.GetCurrentIntegration() {
	case helpers.CIIntegrationFlannel:
		By("Installing Flannel")
		vm.ApplyDefault(vm.GetFilePath("../examples/kubernetes/addons/flannel/flannel.yaml"))
	default:
	}

	ExpectCiliumReady(vm)
	ExpectCiliumOperatorReady(vm)
	ExpectKubeDNSReady(vm)
}

// SkipIfBenchmark will skip the test if benchmark is not specified
func SkipIfBenchmark() {
	if !config.CiliumTestConfig.Benchmarks {
		Skip("Benchmarks are skipped, specify -cilium.Benchmarks")
	}
}

// SkipIfIntegration will skip a test if it's running with any of the specified
// integration.
func SkipIfIntegration(integration string) {
	if helpers.IsIntegration(integration) {
		Skip(fmt.Sprintf(
			"This feature is not supported in Cilium %q mode. Skipping test.",
			integration))
	}
}

// SkipItIfNoKubeProxy will skip It if kube-proxy is disabled (= NodePort BPF is
// enabled)
func SkipItIfNoKubeProxy() {
	if !helpers.RunsWithKubeProxy() {
		Skip("kube-proxy is disabled (NodePort BPF is enabled). Skipping test.")
	}
}

func deleteETCDOperator(kubectl *helpers.Kubectl) {
	// Do not assert on success in AfterEach intentionally to avoid
	// incomplete teardown.
	_ = kubectl.DeleteResource("deploy", fmt.Sprintf("-n %s -l io.cilium/app=etcd-operator", helpers.CiliumNamespace))
	_ = kubectl.DeleteResource("pod", fmt.Sprintf("-n %s -l io.cilium/app=etcd-operator", helpers.CiliumNamespace))
	_ = kubectl.WaitCleanAllTerminatingPods(helpers.HelperTimeout)
}
