// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package k8sTest

import (
	"fmt"

	. "github.com/onsi/gomega"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
)

var _ = Describe("K8sNode", func() {
	var (
		kubectl        *helpers.Kubectl
		ciliumFilename string
	)

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
		DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{})

		_, err := kubectl.CiliumNodesWait()
		ExpectWithOffset(1, err).Should(BeNil(), "Failure while waiting for k8s nodes to be annotated by Cilium")
	})

	AfterAll(func() {
		UninstallCiliumFromManifest(kubectl, ciliumFilename)
	})

	It("Node labels updates are reflected in CiliumNode objects", func() {
		k8s1NodeName, err := kubectl.GetNodeNameByLabel(helpers.K8s1)
		Expect(err).Should(BeNil(), "Can not retrieve %s node name", helpers.K8s1)

		res := kubectl.Patch(helpers.DefaultNamespace, "node", k8s1NodeName, `{"metadata":{"labels":{"test-label":"test-value"}}}`)
		Expect(res).Should(helpers.CMDSuccess(), "Error patching %s Node labels", k8s1NodeName)

		var cn cilium_v2.CiliumNode
		err = kubectl.Get(helpers.DefaultNamespace, fmt.Sprintf("ciliumnode %s", k8s1NodeName)).Unmarshal(&cn)
		Expect(err).Should(BeNil(), "Can not retrieve %s CiliumNode %s", k8s1NodeName)

		Expect(cn.ObjectMeta.Labels["test-label"]).To(Equal("test-value"))

		res = kubectl.JsonPatch(helpers.DefaultNamespace, "node", k8s1NodeName, `[{"op": "remove", "path": "/metadata/labels/test-label"}]`)
		Expect(res).Should(helpers.CMDSuccess(), "Error patching %s Node labels", k8s1NodeName)

		var cn2 cilium_v2.CiliumNode
		err = kubectl.Get(helpers.DefaultNamespace, fmt.Sprintf("ciliumnode %s", k8s1NodeName)).Unmarshal(&cn2)
		Expect(err).Should(BeNil(), "Can not retrieve %s CiliumNode %s", k8s1NodeName)

		Expect(cn2.ObjectMeta.Labels["test-label"]).To(Equal(""))
	})
})
