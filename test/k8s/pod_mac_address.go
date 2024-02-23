// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8sTest

import (
	"fmt"

	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/pkg/annotation"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
)

// The 5.4 CI job is intended to catch BPF complexity regressions and as such
// doesn't need to execute this test suite.
var _ = SkipDescribeIf(func() bool { return helpers.RunsOn54Kernel() && helpers.DoesNotRunOnAKS() }, "K8sSpecificMACAddressTests", func() {
	var (
		kubectl        *helpers.Kubectl
		ciliumFilename string
	)

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
	})

	AfterAll(func() {
		UninstallCiliumFromManifest(kubectl, ciliumFilename)
		kubectl.CloseSSHClient()
	})

	AfterFailed(func() {
		kubectl.CiliumReport("cilium-dbg endpoint list -o jsonpath='{range [*]}{@.id}{\"=\"}{@.status.networking.mac}{\"\\n\"}{end}'")
	})

	SkipContextIf(func() bool { return helpers.RunsOnAKS() }, "Check whether the pod is created", func() {
		const specificMACAddress = "specific-mac-address=specific-mac-address"
		var podYAML string

		BeforeAll(func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{})
			podYAML = helpers.ManifestGet(kubectl.BasePath(), "pod_mac_address.yaml")
			res := kubectl.ApplyDefault(podYAML)
			res.ExpectSuccess("Unable to apply %s", podYAML)
			err := kubectl.WaitforPods(helpers.DefaultNamespace, fmt.Sprintf("-l %s", specificMACAddress), helpers.HelperTimeout)
			Expect(err).Should(BeNil())
		})

		AfterAll(func() {
			_ = kubectl.Delete(podYAML)
			ExpectAllPodsTerminated(kubectl)
		})
		It("Checks the pod's mac address", func() {
			var demoPods v1.PodList
			kubectl.GetPods(helpers.DefaultNamespace, fmt.Sprintf("-l %s", specificMACAddress)).Unmarshal(&demoPods)
			Expect(demoPods.Items).To(HaveLen(1))
			By("Checking the pod's mac address")
			kubectl.ExecPodCmd(helpers.DefaultNamespace, demoPods.Items[0].Name,
				fmt.Sprintf("ip link show |grep \"%s\" | wc -l", demoPods.Items[0].Annotations[annotation.PodAnnotationMAC])).
				ExpectSuccess("cannot find configured mac address %s in 'ip link show' output from pod %s",
					demoPods.Items[0].Annotations[annotation.PodAnnotationMAC], demoPods.Items[0].Name)
		})
	})

})
