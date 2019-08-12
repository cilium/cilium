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
	"context"
	"fmt"
	"time"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
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
	err := vm.WaitforPods(helpers.KubeSystemNamespace, "-l k8s-app=cilium", longTimeout)
	ExpectWithOffset(1, err).Should(BeNil(), "cilium was not able to get into ready state")

	err = vm.CiliumPreFlightCheck()
	ExpectWithOffset(1, err).Should(BeNil(), "cilium pre-flight checks failed")
}

// ExpectCiliumOperatorReady is a wrapper around helpers/WaitForPods. It asserts that
// the error returned by that function is nil.
func ExpectCiliumOperatorReady(vm *helpers.Kubectl) {
	By("Waiting for cilium-operator to be ready")
	err := vm.WaitforPods(helpers.KubeSystemNamespace, "-l name=cilium-operator", longTimeout)
	ExpectWithOffset(1, err).Should(BeNil(), "Cilium operator was not able to get into ready state")
}

// ExpectCiliumRunning is a wrapper around helpers/WaitForNPods. It
// asserts the cilium pods are running on all nodes (but not yet ready!).
func ExpectCiliumRunning(vm *helpers.Kubectl) {
	err := vm.WaitforNPodsRunning(helpers.KubeSystemNamespace, "-l k8s-app=cilium", vm.GetNumNodes(), longTimeout)
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

// DeployCiliumAndDNS deploys DNS and cilium into the kubernetes cluster
func DeployCiliumAndDNS(vm *helpers.Kubectl) {
	DeployCiliumOptionsAndDNS(vm, []string{})
}

// DeployCiliumOptionsAndDNS deploys DNS and cilium with options into the kubernetes cluster
func DeployCiliumOptionsAndDNS(vm *helpers.Kubectl, options []string) {
	By("Installing Cilium")
	err := vm.CiliumInstall(options)
	Expect(err).To(BeNil(), "Cilium cannot be installed")

	ExpectCiliumRunning(vm)

	By("Installing DNS Deployment")
	_ = vm.Apply(helpers.DNSDeployment())

	switch helpers.GetCurrentIntegration() {
	case helpers.CIIntegrationFlannel:
		By("Installing Flannel")
		vm.Apply(helpers.GetFilePath("../examples/kubernetes/addons/flannel/flannel.yaml"))
	default:
	}

	ExpectCiliumReady(vm)
	ExpectCiliumOperatorReady(vm)
	ExpectKubeDNSReady(vm)
}

// SkipIfFlannel will skip the test if it's running over Flannel datapath mode.
func SkipIfFlannel() {
	if helpers.GetCurrentIntegration() == helpers.CIIntegrationFlannel {
		Skip(fmt.Sprintf(
			"This feature is not supported in Cilium %q mode. Skipping test.",
			helpers.CIIntegrationFlannel))
	}
}

func deleteCiliumDS(kubectl *helpers.Kubectl) {
	// Do not assert on success in AfterEach intentionally to avoid
	// incomplete teardown.
	_ = kubectl.DeleteResource("ds", fmt.Sprintf("-n %s cilium", helpers.KubeSystemNamespace))
	Expect(waitToDeleteCilium(kubectl, logger)).To(BeNil(), "timed out deleting Cilium pods")
}

func waitToDeleteCilium(kubectl *helpers.Kubectl, logger *logrus.Entry) error {
	var (
		pods []string
		err  error
	)

	ctx, cancel := context.WithTimeout(context.Background(), helpers.HelperTimeout)
	defer cancel()

	status := 1
	for status > 0 {

		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting to delete Cilium: pods still remaining: %s", pods)
		default:
		}

		pods, err = kubectl.GetCiliumPodsContext(ctx, helpers.KubeSystemNamespace)
		status := len(pods)
		logger.Infof("Cilium pods terminating '%d' err='%v' pods='%v'", status, err, pods)
		if status == 0 {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return nil
}
