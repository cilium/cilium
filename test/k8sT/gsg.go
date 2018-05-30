// Copyright 2018 Authors of Cilium
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
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("K8sValidatedGSG", func() {

	var (
		kubectl          *helpers.Kubectl
		logger           *logrus.Entry
		microscopeErr    error
		microscopeCancel func() error

		toDelete = []string{}
	)

	BeforeAll(func() {
		logger = log.WithFields(logrus.Fields{"testName": "K8sValidatedGSG"})
		logger.Info("Starting")
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		err := kubectl.CiliumInstall(helpers.CiliumDSPath)
		Expect(err).To(BeNil(), "Cilium cannot be installed")

		ExpectCiliumReady(kubectl)
		ExpectKubeDNSReady(kubectl)
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.KubeSystemNamespace,
			"cilium service list",
			"cilium endpoint list")
	})

	JustBeforeEach(func() {
		microscopeErr, microscopeCancel = kubectl.MicroscopeStart()
		Expect(microscopeErr).To(BeNil(), "Microscope cannot be started")
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsOnLogs(CurrentGinkgoTestDescription().Duration)
		Expect(microscopeCancel()).To(BeNil(), "cannot stop microscope")
	})

	AfterEach(func() {
		ExpectAllPodsTerminated(kubectl)
		for _, manifest := range toDelete {
			kubectl.Delete(manifest)
		}
	})

	It("GRPC example", func() {
		AppManifest := helpers.GetFilePath("../examples/kubernetes-grpc/cc-door-app.yaml")
		PolicyManifest := helpers.GetFilePath("../examples/kubernetes-grpc/cc-door-ingress-security.yaml")

		clientPod := "terminal-87"

		toDelete = append(toDelete, AppManifest)
		toDelete = append(toDelete, PolicyManifest)

		By("Testing the example config")
		kubectl.Apply(AppManifest).ExpectSuccess("cannot install the GRPC application")

		err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=grpcExample", 300)
		Expect(err).Should(BeNil(), "Pods are not ready after timeout")

		res := kubectl.ExecPodCmd(
			helpers.DefaultNamespace, clientPod,
			"python3 /cloudcity/cc_door_client.py GetName 1")
		res.ExpectSuccess("Client cannot get Name")

		res = kubectl.ExecPodCmd(
			helpers.DefaultNamespace, clientPod,
			"python3 /cloudcity/cc_door_client.py GetLocation 1")
		res.ExpectSuccess("Client cannot get Location")

		res = kubectl.ExecPodCmd(
			helpers.DefaultNamespace, clientPod,
			"python3 /cloudcity/cc_door_client.py SetAccessCode 1 999")
		res.ExpectSuccess("Client cannot set Accesscode")

		By("Testing with L7 policy")
		_, err = kubectl.CiliumPolicyAction(
			helpers.DefaultNamespace, PolicyManifest,
			helpers.KubectlApply, 300)
		Expect(err).To(BeNil(), "Cannot import GPRC policy")

		res = kubectl.ExecPodCmd(
			helpers.DefaultNamespace, clientPod,
			"python3 /cloudcity/cc_door_client.py GetName 1")
		res.ExpectSuccess("Client cannot get Name")

		res = kubectl.ExecPodCmd(
			helpers.DefaultNamespace, clientPod,
			"python3 /cloudcity/cc_door_client.py GetLocation 1")
		res.ExpectSuccess("Client cannot get Location")

		res = kubectl.ExecPodCmd(
			helpers.DefaultNamespace, clientPod,
			"python3 /cloudcity/cc_door_client.py SetAccessCode 1 999")
		res.ExpectFail("Client can set Accesscode and it shoud not")
	})

	It("Minikube intro", func() {
		AppManifest := helpers.GetFilePath("../examples/minikube/http-sw-app.yaml")
		L3Policy := helpers.GetFilePath("../examples/minikube/sw_l3_l4_policy.yaml")
		L7Policy := helpers.GetFilePath("../examples/minikube/sw_l3_l4_l7_policy.yaml")

		toDelete = append(toDelete, AppManifest)
		toDelete = append(toDelete, L3Policy)
		toDelete = append(toDelete, L7Policy)

		kubectl.Apply(AppManifest).ExpectSuccess("Cannot apply example manifest")

		err := kubectl.WaitforPods(helpers.DefaultNamespace, "", 300)
		Expect(err).Should(BeNil(), "Pods are not ready after timeout")

		res := kubectl.ExecPodCmd(helpers.DefaultNamespace, "xwing",
			helpers.CurlFail("-XPOST deathstar.default.svc.cluster.local/v1/request-landing"))
		res.ExpectSuccess("Xwing request landing did not work")

		res = kubectl.ExecPodCmd(helpers.DefaultNamespace, "tiefighter",
			helpers.CurlFail("-XPOST deathstar.default.svc.cluster.local/v1/request-landing"))
		res.ExpectSuccess("Tiefighter request landing did not work correctly")

		By("Testing by L3 Policy")
		_, err = kubectl.CiliumPolicyAction(
			helpers.KubeSystemNamespace, L3Policy, helpers.KubectlApply, 300)
		Expect(err).Should(BeNil(), "L3Policy cannot be applied")

		res = kubectl.ExecPodCmd(helpers.DefaultNamespace, "xwing",
			helpers.CurlFail("-XPOST deathstar.default.svc.cluster.local/v1/request-landing"))
		res.ExpectFail("Xwing should fail to connect to deathstar service")

		res = kubectl.ExecPodCmd(helpers.DefaultNamespace, "tiefighter",
			helpers.CurlFail("-XPOST deathstar.default.svc.cluster.local/v1/request-landing"))
		res.ExpectSuccess("Tiefighter request landing did not work correctly")

		By("Testing by L7 Policy")
		res = kubectl.ExecPodCmd(helpers.DefaultNamespace, "tiefighter",
			helpers.CurlWithHTTPCode("-XPUT deathstar.default.svc.cluster.local/v1/exhaust-port"))
		res.ExpectContains("503", "Tiefighter exhaust-port did not fail")

		_, err = kubectl.CiliumPolicyAction(
			helpers.KubeSystemNamespace, L7Policy, helpers.KubectlApply, 300)
		Expect(err).Should(BeNil(), "L7Policy cannot be applied")

		res = kubectl.ExecPodCmd(helpers.DefaultNamespace, "tiefighter",
			helpers.CurlFail("-XPUT deathstar.default.svc.cluster.local/v1/exhaust-port"))
		res.ExpectFail("Tiefighter exhaust-port did work when it should not")

		res = kubectl.ExecPodCmd(helpers.DefaultNamespace, "tiefighter",
			helpers.CurlFail("-XPOST deathstar.default.svc.cluster.local/v1/request-landing"))
		res.ExpectSuccess("Tiefighter request landing did not work correctly")
	})
})
