// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8sTest

import (
	"fmt"
	"time"

	. "github.com/onsi/gomega"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
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
	vm.WaitForCiliumReadiness(0, "Timeout while waiting for Cilium to become ready")

	err := vm.CiliumPreFlightCheck()
	ExpectWithOffset(1, err).Should(BeNil(), "cilium pre-flight checks failed")
}

func ExpectCiliumNotRunning(vm *helpers.Kubectl) {
	err := vm.WaitTerminatingPodsInNsWithFilter(helpers.CiliumNamespace, "-l name=cilium-operator", helpers.HelperTimeout)
	ExpectWithOffset(1, err).To(BeNil(), "terminating cilium-operator pod is not deleted after timeout")
	err = vm.WaitTerminatingPodsInNsWithFilter(helpers.CiliumNamespace, "-l k8s-app=cilium", helpers.HelperTimeout)
	ExpectWithOffset(1, err).To(BeNil(), "terminating cilium pods are not deleted after timeout")
}

// ExpectCiliumOperatorReady is a wrapper around helpers/WaitForPods. It asserts that
// the error returned by that function is nil.
func ExpectCiliumOperatorReady(vm *helpers.Kubectl) {
	By("Waiting for cilium-operator to be ready")
	var err error
	if vm.NumNodes() < 2 {
		err = vm.WaitforNPods(helpers.CiliumNamespace, "-l name=cilium-operator", 1, longTimeout)
	} else {
		err = vm.WaitforPods(helpers.CiliumNamespace, "-l name=cilium-operator", longTimeout)
	}
	ExpectWithOffset(1, err).Should(BeNil(), "Cilium operator was not able to get into ready state")
}

// ExpectHubbleCLIReady is a wrapper around helpers/WaitForPods. It asserts
// that the error returned by that function is nil.
func ExpectHubbleCLIReady(vm *helpers.Kubectl, ns string) {
	By("Waiting for hubble-cli to be ready")
	err := vm.WaitforPods(ns, "-l k8s-app=hubble-cli", longTimeout)
	ExpectWithOffset(1, err).Should(BeNil(), "hubble-cli was not able to get into ready state")
}

// ExpectHubbleRelayReady is a wrapper around helpers/WaitForPods. It asserts
// that the error returned by that function is nil.
func ExpectHubbleRelayReady(vm *helpers.Kubectl, ns string) {
	By("Waiting for hubble-relay to be ready")
	err := vm.WaitforPods(ns, "-l k8s-app=hubble-relay", longTimeout)
	ExpectWithOffset(1, err).Should(BeNil(), "hubble-relay was not able to get into ready state")
}

// ExpectAllPodsTerminated is a wrapper around helpers/WaitTerminatingPods.
// It asserts that the error returned by that function is nil.
func ExpectAllPodsTerminated(vm *helpers.Kubectl) {
	err := vm.WaitTerminatingPods(helpers.HelperTimeout)
	ExpectWithOffset(1, err).To(BeNil(), "terminating containers are not deleted after timeout")
}

// ExpectAllPodsInNsTerminated is a wrapper around helpers/WaitTerminatingPods.
// It asserts that the error returned by that function is nil.
func ExpectAllPodsInNsTerminated(vm *helpers.Kubectl, ns string) {
	err := vm.WaitTerminatingPodsInNs(ns, helpers.HelperTimeout)
	ExpectWithOffset(1, err).To(BeNil(), "terminating containers are not deleted after timeout")
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
		warningMessage = res.Stdout()
	}
	Expect(err).To(BeNil(), "cilium pre-flight check is not ready after timeout, pods status:\n %s", warningMessage)
}

// DeployCiliumAndDNS deploys DNS and cilium into the kubernetes cluster
func DeployCiliumAndDNS(vm *helpers.Kubectl, ciliumFilename string) {
	DeployCiliumOptionsAndDNS(vm, ciliumFilename, map[string]string{})
}

func redeployCilium(vm *helpers.Kubectl, ciliumFilename string, options map[string]string) {
	By("Installing Cilium")
	err := vm.CiliumInstall(ciliumFilename, options)
	Expect(err).To(BeNil(), "Cilium cannot be installed")

	vm.WaitForCiliumReadiness(0, "Timeout while waiting for Cilium to become ready")
}

// RedeployCilium reinstantiates the Cilium DS and ensures it is running.
//
// This helper is only appropriate for reconfiguring Cilium in the middle of
// an existing testsuite that calls DeployCiliumAndDNS(...).
func RedeployCilium(vm *helpers.Kubectl, ciliumFilename string, options map[string]string) {
	redeployCilium(vm, ciliumFilename, options)
	err := vm.CiliumPreFlightCheck()
	ExpectWithOffset(1, err).Should(BeNil(), "cilium pre-flight checks failed")
	ExpectCiliumOperatorReady(vm)
}

// UninstallCiliumFromManifest uninstall a deployed Cilium configuration from the
// provided manifest file.
// Treat this as a cleanup function for RedeployCilium/Redeploy/DeployCiliumAndDNS/CiliumInstall.
func UninstallCiliumFromManifest(vm *helpers.Kubectl, ciliumFilename string) {
	By("Removing Cilium installation using generated helm manifest")

	Expect(vm.DeleteAndWait(ciliumFilename, true).GetError()).
		To(BeNil(), "Error removing cilium from installed manifest")
}

// RedeployCiliumWithMerge merges the configuration passed as "from" into
// "options", allowing the caller to preserve the previous Cilium
// configuration, along with passing new configuration. This function behaves
// equivalently to RedeployCilium. Note that "options" is deep copied, meaning
// it will NOT be modified. Any modifications will be local to this function.
func RedeployCiliumWithMerge(vm *helpers.Kubectl,
	ciliumFilename string,
	from, options map[string]string) {

	// Merge configuration
	newOpts := make(map[string]string, len(options))
	for k, v := range from {
		newOpts[k] = v
	}
	for k, v := range options {
		newOpts[k] = v
	}

	RedeployCilium(vm, ciliumFilename, newOpts)
}

// optionChangeRequiresPodRedeploy returns true if the difference between the
// specified options requires redeployment of all pods to ensure that the
// datapath is operating consistently.
func optionChangeRequiresPodRedeploy(prev, next map[string]string) bool {
	// See GH-16717, as of v1.10.x Cilium does not support migrating
	// between endpointRoutes modes without restarting pods.
	// Also, the default setting for endpointRoutes is disabled.
	// If either of these properties change, this logic needs updating!
	a := "false"
	if opt, ok := prev["endpointRoutes.enabled"]; ok {
		a = opt
	}
	b := "false"
	if opt, ok := next["endpointRoutes.enabled"]; ok {
		b = opt
	}

	if a != b {
		return true
	}

	// Switching on and off KPR affects who is handling service traffic.
	// E.g., off => on some traffic might be handled by iptables. For existing
	// connections it might not have enough of state information which could
	// lead to connection interruptions. To avoid it, restart the pods to restart
	// such connections.
	a = "disabled"
	if opt, ok := prev["kubeProxyReplacement"]; ok {
		a = opt
	}
	b = "disabled"
	if opt, ok := next["kubeProxyReplacement"]; ok {
		b = opt
	}

	if a != b {
		return true
	}

	return false
}

// DeployCiliumOptionsAndDNS deploys DNS and cilium with options into the kubernetes cluster
func DeployCiliumOptionsAndDNS(vm *helpers.Kubectl, ciliumFilename string, options map[string]string) {
	prevOptions := vm.CiliumOptions()

	redeployCilium(vm, ciliumFilename, options)

	vm.RestartUnmanagedPodsInNamespace(helpers.LogGathererNamespace)

	forceDNSRedeploy := optionChangeRequiresPodRedeploy(prevOptions, options)
	vm.RedeployKubernetesDnsIfNecessary(forceDNSRedeploy)

	switch helpers.GetCurrentIntegration() {
	case helpers.CIIntegrationGKE:
		if helpers.LogGathererNamespace != helpers.KubeSystemNamespace {
			vm.RestartUnmanagedPodsInNamespace(helpers.KubeSystemNamespace)
		}
	}

	err := vm.CiliumPreFlightCheck()
	ExpectWithOffset(1, err).Should(BeNil(), "cilium pre-flight checks failed")
	ExpectCiliumOperatorReady(vm)

	switch helpers.GetCurrentIntegration() {
	case helpers.CIIntegrationGKE:
		err := vm.WaitforPods(helpers.KubeSystemNamespace, "", longTimeout)
		ExpectWithOffset(1, err).Should(BeNil(), "kube-system pods were not able to get into ready state after restart")
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
