// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package k8sTest

import (
	"context"
	"fmt"

	. "github.com/onsi/gomega"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
)

var _ = Describe("NightlyPolicyStress", func() {

	var kubectl *helpers.Kubectl

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		deploymentManager.SetKubectl(kubectl)
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
	})

	AfterEach(func() {
		deploymentManager.DeleteAll()
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.CiliumNamespace,
			"cilium endpoint list")
	})

	AfterAll(func() {
		deploymentManager.DeleteCilium()
		kubectl.CloseSSHClient()
	})

	// Return a command string for bash loop.
	loopCommand := func(cmd, namespace string, count int) string {
		// Repeat 'cmd' 'count' times.
		// '${namespace} in 'cmd' will be replaced by 'namespace'.
		// '$i' in 'cmd' will be replaced by the loop counter, starting from 1.
		return fmt.Sprintf(`/bin/bash -c 'namespace=%s; for i in $(seq 1 %d); do %s; done'`,
			namespace, count, cmd)
	}

	Context("Identity Churn", func() {
		It("Run policy-stress-test manifest with identity churn", func() {
			deploymentManager.Deploy(helpers.CiliumNamespace, StatelessEtcd)
			deploymentManager.WaitUntilReady()

			host, port, err := kubectl.GetServiceHostPort(helpers.CiliumNamespace, "stateless-etcd")
			Expect(err).Should(BeNil(), "Unable to retrieve ClusterIP and port for stateless-etcd service")

			etcdService := fmt.Sprintf("http://%s:%d", host, port)
			opts := map[string]string{
				"etcd.enabled":                "true",
				"etcd.endpoints[0]":           etcdService,
				"identityAllocationMode":      "kvstore",
				"prometheus.enabled":          "true",
				"operator.prometheus.enabled": "true",
			}
			if helpers.ExistNodeWithoutCilium() {
				opts["synchronizeK8sNodes"] = "false"
			}
			deploymentManager.DeployCilium(opts, DeployCiliumOptionsAndDNS)

			randomNamespace := deploymentManager.DeployRandomNamespace(ConnectivityCheck)
			deploymentManager.WaitUntilReady()

			ciliumPod, err := kubectl.GetCiliumPodOnNode(helpers.K8s1)
			Expect(err).Should(BeNil(), "Unable to determine cilium pod on node %s", helpers.K8s1)

			By("Stressing Cilium policy engine by inserting 20000 identities into kvstore...")
			kubectl.CiliumExecMustSucceed(context.TODO(), ciliumPod, loopCommand(
				`cilium kvstore set --key "cilium/state/identities/v1/id/$((65535+$i))" --value "k8s:test-id=$((65535+$i));k8s:io.kubernetes.pod.namespace=default;"; `+
					`cilium kvstore set --key "cilium/state/identities/v1/id/$((75535+$i))" --value "k8s:manifest=policy-stress-test;k8s:test-id=$((75535+$i));k8s:io.kubernetes.pod.namespace=${namespace};"`,
				randomNamespace, 10000))
		})
	})
})
