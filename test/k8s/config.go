// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8sTest

import (
	"context"
	"fmt"
	"os"

	. "github.com/onsi/gomega"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
)

// Some basic checks of the CiliumNodeConfig plumbing.
//
// This bit is an end-to-end test to ensure that the Helm
// chart is working as intended. There is more complicated
// tests of the logic in unit tests.
//
// It creates a CiliumNodeConfig, ensure it doesn't apply,
// then labels one node and ensure that, yes, it did apply
var _ = SkipDescribeIf(func() bool {
	// right now, the 5.4 job is the fastest, so use only that
	// but only if we're on jenkins
	return helpers.DoesNotRunOn54Kernel() && helpers.RunsOnJenkins()
}, "K8sAgentPerNodeConfigTest", func() {
	var (
		kubectl *helpers.Kubectl

		ciliumFilename string
	)
	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		res := kubectl.ExecShort("kubectl label --overwrite --all node io.cilium.testing-")
		Expect(res.GetErr("unlabel node")).To(BeNil())

		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
		RedeployCilium(kubectl, ciliumFilename, map[string]string{})
	})

	AfterAll(func() {
		res := kubectl.ExecShort("kubectl label --overwrite --all node io.cilium.testing-")
		Expect(res.GetErr("unlabel node")).To(BeNil())
		UninstallCiliumFromManifest(kubectl, ciliumFilename)
		kubectl.CloseSSHClient()
	})

	It("Correctly computes config overrides", func() {
		pods, err := kubectl.GetPodsNodes(helpers.CiliumNamespace, helpers.CiliumSelector)
		Expect(err).To(BeNil(), "error finding cilium pods")

		// pick a node
		var nodeName string
		for _, v := range pods {
			nodeName = v
			break
		}
		if nodeName == "" {
			Fail("No cilium pods were found")
		}

		recreatePods := func() {
			By("Deleting all cilium pods")
			kubectl.DeleteResource("-n kube-system pod", "-l "+helpers.CiliumAgentLabel)
			// Wait for pods to be up and running
			kubectl.WaitForCiliumReadiness(0, "not all cilium pods returned")
		}

		// returns a map of nodename -> config key
		getNodeConfigKeys := func(key string) map[string]string {
			podtonode, err := kubectl.GetPodsNodes(helpers.CiliumNamespace, helpers.CiliumSelector)
			Expect(err).To(BeNil(), "error finding cilium pods")

			ress, err := kubectl.ExecInPods(context.TODO(), helpers.CiliumNamespace, helpers.CiliumSelector,
				fmt.Sprintf("/bin/sh -c 'cat /tmp/cilium/config-map/%s || true'", key))
			Expect(err).NotTo(HaveOccurred())
			out := map[string]string{}
			for p, res := range ress {
				Expect(res.GetErr(p)).NotTo((HaveOccurred()))
				out[podtonode[p]] = res.Stdout()
			}
			return out
		}

		By("Creating a CiliumNodeConfig")
		// Create a CiliumNodeConfig that does not apply to any nodes
		cnc := `
apiVersion: cilium.io/v2alpha1
kind: CiliumNodeConfig
metadata:
  namespace: kube-system
  name: testing
spec:
  nodeSelector:
    matchLabels:
      io.cilium.testing: foo
  defaults:
    test-key: foo
`
		f, err := os.CreateTemp("", "pernodeconfig-")
		Expect(err).Should(BeNil())
		defer os.Remove(f.Name())

		_, err = f.WriteString(cnc)
		Expect(err).Should(BeNil())

		res := kubectl.Apply(helpers.ApplyOptions{
			FilePath:  f.Name(),
			Namespace: "kube-system",
		})
		Expect(res.GetErr("apply")).To(BeNil())

		// ensure no pods have this key
		recreatePods()
		nodeConfigKeys := getNodeConfigKeys("test-key")
		Expect(nodeConfigKeys).To(HaveKey(nodeName))
		Expect(nodeConfigKeys).To(HaveEach("")) //ensure that all elements are ""

		// Now, label 1 node and check the only it gets this config key
		By("Labeling node %s with io.cilium.testing=foo", nodeName)
		res = kubectl.ExecShort(fmt.Sprintf("kubectl label node %s io.cilium.testing=foo", nodeName))
		Expect(res.GetErr("label node")).To(BeNil())
		recreatePods()
		By("Ensuring only node %s has the config override", nodeName)
		nodeConfigKeys = getNodeConfigKeys("test-key")
		// ensure it is zero
		Expect(nodeConfigKeys).To(HaveKeyWithValue(nodeName, "foo"))
		// If there are other nodes, make sure it doesn't have the config key
		if len(nodeConfigKeys) > 1 {
			delete(nodeConfigKeys, nodeName)
			Expect(nodeConfigKeys).To(HaveEach(""))
		}

	})
})
