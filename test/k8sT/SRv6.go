// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package k8sTest

import (
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
)

var _ = SkipDescribeIf(helpers.DoesNotExistNodeWithoutCilium, "K8sSRv6", func() {
	var (
		kubectl        *helpers.Kubectl
		ciliumFilename string
	)

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		deploymentManager.SetKubectl(kubectl)
		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
		DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
			"srv6.enabled":           "true",
			"bpf.monitorAggregation": "none",
		})
	})

	AfterAll(func() {
		UninstallCiliumFromManifest(kubectl, ciliumFilename)
	})

	It("SRv6 encapsulation", func() {
		helpers.HoldEnvironment("Testing...")
	})
})
