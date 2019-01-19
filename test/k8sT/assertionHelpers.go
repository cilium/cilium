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

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	. "github.com/onsi/gomega"
)

var longTimeout = 10 * time.Minute

// ExpectKubeDNSReady is a wrapper around helpers/WaitKubeDNS. It asserts that
// the error returned by that function is nil.
func ExpectKubeDNSReady(vm *helpers.Kubectl) {
	err := vm.WaitKubeDNS()
	ExpectWithOffset(1, err).Should(BeNil(), "kube-dns was not able to get into ready state")

	err = vm.KubeDNSPreFlightCheck()
	ExpectWithOffset(1, err).Should(BeNil(), "kube-dns service not ready")
}

// ExpectCiliumReady is a wrapper around helpers/WaitForPods. It asserts that
// the error returned by that function is nil.
func ExpectCiliumReady(vm *helpers.Kubectl) {
	err := vm.WaitforPods(helpers.KubeSystemNamespace, "-l k8s-app=cilium", longTimeout)
	ExpectWithOffset(1, err).Should(BeNil(), "cilium was not able to get into ready state")

	err = vm.CiliumPreFlightCheck()
	ExpectWithOffset(1, err).Should(BeNil(), "cilium pre-flight checks failed")
}

// ExpectCiliumRunning is a wrapper around helpers/WaitForPodsRunning. It
// asserts the cilium pods are running on all nodes.
func ExpectCiliumRunning(vm *helpers.Kubectl) {
	err := vm.WaitForPodsRunning(helpers.KubeSystemNamespace, "-l k8s-app=cilium", vm.GetNumNodes(), longTimeout)
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
	By("Waiting for all etcd-operator pods are ready")

	err := vm.WaitforNPods(helpers.KubeSystemNamespace, "-l io.cilium/app=etcd-operator", 5, longTimeout)
	warningMessage := ""
	if err != nil {
		res := vm.Exec(fmt.Sprintf(
			"%s -n %s get pods -l io.cilium/app=etcd-operator",
			helpers.KubectlCmd, helpers.KubeSystemNamespace))
		warningMessage = res.Output().String()
	}
	Expect(err).To(BeNil(), "etcd-operator is not ready after timeout, pods status:\n %s", warningMessage)
}

// ExpectCiliumPreFlightInstallReady is a wrapper around helpers/WaitForNPods.
// It asserts the error returned by that function is nil.
func ExpectCiliumPreFlightInstallReady(vm *helpers.Kubectl) {
	By("Waiting for all cilium pre-flight pods to be ready")

	err := vm.WaitforPods(helpers.KubeSystemNamespace, "-l k8s-app=cilium-pre-flight-check", longTimeout)
	warningMessage := ""
	if err != nil {
		res := vm.Exec(fmt.Sprintf(
			"%s -n %s get pods -l k8s-app=cilium-pre-flight-check",
			helpers.KubectlCmd, helpers.KubeSystemNamespace))
		warningMessage = res.Output().String()
	}
	Expect(err).To(BeNil(), "cilium pre-flight check is not ready after timeout, pods status:\n %s", warningMessage)
}

// ProvisionInfraPods deploys DNS, etcd-operator, and cilium into the kubernetes
// cluster of which vm is a member.
func ProvisionInfraPods(vm *helpers.Kubectl) {
	By("Installing DNS Deployment")
	_ = vm.Apply(helpers.DNSDeployment())

	By("Deploying etcd-operator")
	err := vm.DeployETCDOperator()
	Expect(err).To(BeNil(), "Unable to deploy etcd operator")

	By("Installing Cilium")
	err = vm.CiliumInstall(helpers.CiliumDefaultDSPatch, helpers.CiliumConfigMapPatch)
	Expect(err).To(BeNil(), "Cilium cannot be installed")

	switch helpers.GetCurrentIntegration() {
	case helpers.CIIntegrationFlannel:
		ExpectCiliumRunning(vm)
		vm.Apply(helpers.GetFilePath("../examples/kubernetes/addons/flannel/flannel.yaml"))
	default:
	}

	ExpectCiliumReady(vm)
	ExpectETCDOperatorReady(vm)
	ExpectKubeDNSReady(vm)
}
