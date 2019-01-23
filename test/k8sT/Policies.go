// Copyright 2017-2019 Authors of Cilium
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

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	"github.com/sirupsen/logrus"
)

var _ = Describe("K8sPolicyTest", func() {

	var (
		kubectl              *helpers.Kubectl
		demoPath             = helpers.ManifestGet("demo.yaml")
		l3Policy             = helpers.ManifestGet("l3-l4-policy.yaml")
		l7Policy             = helpers.ManifestGet("l7-policy.yaml")
		l7PolicyKafka        = helpers.ManifestGet("l7-policy-kafka.yaml")
		serviceAccountPolicy = helpers.ManifestGet("service-account.yaml")
		knpDenyIngress       = helpers.ManifestGet("knp-default-deny-ingress.yaml")
		knpDenyEgress        = helpers.ManifestGet("knp-default-deny-egress.yaml")
		knpDenyIngressEgress = helpers.ManifestGet("knp-default-deny-ingress-egress.yaml")
		cnpDenyIngress       = helpers.ManifestGet("cnp-default-deny-ingress.yaml")
		cnpDenyEgress        = helpers.ManifestGet("cnp-default-deny-egress.yaml")
		knpAllowIngress      = helpers.ManifestGet("knp-default-allow-ingress.yaml")
		knpAllowEgress       = helpers.ManifestGet("knp-default-allow-egress.yaml")
		cnpMatchExpression   = helpers.ManifestGet("cnp-matchexpressions.yaml")
		app1Service          = "app1-service"
		microscopeErr        error
		microscopeCancel                        = func() error { return nil }
		backgroundCancel     context.CancelFunc = func() { return }
		backgroundError      error
		apps                 = []string{helpers.App1, helpers.App2, helpers.App3}
	)

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		ProvisionInfraPods(kubectl)
	})

	AfterEach(func() {
		ExpectAllPodsTerminated(kubectl)
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.KubeSystemNamespace,
			"cilium service list",
			"cilium endpoint list")
	})

	AfterAll(func() {
		ExpectAllPodsTerminated(kubectl)
	})

	JustBeforeEach(func() {
		microscopeErr, microscopeCancel = kubectl.MicroscopeStart()
		Expect(microscopeErr).To(BeNil(), "Microscope cannot be started")

		backgroundCancel, backgroundError = kubectl.BackgroundReport("uptime")
		Expect(backgroundError).To(BeNil(), "Cannot start background report process")
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
		Expect(microscopeCancel()).To(BeNil(), "cannot stop microscope")
		backgroundCancel()
	})

	Context("Basic Test", func() {
		var (
			ciliumPod string
			clusterIP string
			appPods   map[string]string
		)

		importPolicy := func(file, name string) {
			_, err := kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, file, helpers.KubectlApply, helpers.HelperTimeout)
			ExpectWithOffset(1, err).Should(BeNil(),
				"policy %s cannot be applied in %q namespace", file, helpers.DefaultNamespace)
		}

		// getMatcher returns a helper.CMDSucess() matcher for success or
		// failure situations.
		getMatcher := func(val bool) types.GomegaMatcher {
			if val {
				return helpers.CMDSuccess()
			}
			return Not(helpers.CMDSuccess())
		}

		validateConnectivity := func(expectWorldSuccess, expectClusterSuccess bool) {
			for _, pod := range []string{appPods[helpers.App2], appPods[helpers.App3]} {
				By("HTTP connectivity to google.com")
				res := kubectl.ExecPodCmd(
					helpers.DefaultNamespace, pod,
					helpers.CurlFail("http://www.google.com/"))

				ExpectWithOffset(1, res).To(getMatcher(expectWorldSuccess),
					"HTTP egress connectivity to google.com from pod %q", pod)

				By("ICMP connectivity to 8.8.8.8")
				res = kubectl.ExecPodCmd(
					helpers.DefaultNamespace, pod,
					helpers.Ping("8.8.8.8"))

				ExpectWithOffset(1, res).To(getMatcher(expectWorldSuccess),
					"ICMP egress connectivity to 8.8.8.8 from pod %q", pod)

				By("DNS lookup of google.com")
				res = kubectl.ExecPodCmd(
					helpers.DefaultNamespace, pod,
					"host www.google.com")

				// kube-dns is always whitelisted so this should always work
				ExpectWithOffset(1, res).To(getMatcher(expectWorldSuccess || expectClusterSuccess),
					"DNS connectivity of www.google.com from pod %q", pod)

				By("HTTP connectivity from pod to pod")
				res = kubectl.ExecPodCmd(
					helpers.DefaultNamespace, pod,
					helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))

				ExpectWithOffset(1, res).To(getMatcher(expectClusterSuccess),
					"HTTP connectivity to clusterIP %q of app1 from pod %q", clusterIP, appPods[helpers.App2])
			}
		}

		BeforeAll(func() {
			kubectl.Apply(demoPath)

			err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Test pods are not ready after timeout")

			ciliumPod, err = kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s1)
			Expect(err).Should(BeNil(), "cannot get CiliumPod")

			clusterIP, _, err = kubectl.GetServiceHostPort(helpers.DefaultNamespace, app1Service)
			Expect(err).To(BeNil(), "Cannot get service on %q namespace", helpers.DefaultNamespace)
			appPods = helpers.GetAppPods(apps, helpers.DefaultNamespace, kubectl, "id")
			logger.WithFields(logrus.Fields{
				"ciliumPod": ciliumPod,
				"clusterIP": clusterIP}).Info("Initial data")

		})

		AfterAll(func() {
			kubectl.Delete(demoPath)
		})

		BeforeEach(func() {
			status := kubectl.CiliumExec(
				ciliumPod, fmt.Sprintf("cilium config %s=%s",
					helpers.PolicyEnforcement, helpers.PolicyEnforcementDefault))
			status.ExpectSuccess()

			err := kubectl.CiliumEndpointWaitReady()
			Expect(err).To(BeNil(), "Endpoints are not ready after timeout")

			err = kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", helpers.HelperTimeout)
			Expect(err).Should(BeNil())

		})

		AfterEach(func() {
			cmd := fmt.Sprintf("%s delete --all cnp,netpol", helpers.KubectlCmd)
			_ = kubectl.Exec(cmd)
		})

		It("checks all kind of Kubernetes policies", func() {

			logger.Infof("PolicyRulesTest: cluster service ip '%s'", clusterIP)

			By("Testing L3/L4 rules")

			_, err := kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, l3Policy, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil())

			trace := kubectl.CiliumExec(ciliumPod, fmt.Sprintf(
				"cilium policy trace --src-k8s-pod default:%s --dst-k8s-pod default:%s --dport 80",
				appPods[helpers.App2], appPods[helpers.App1]))
			trace.ExpectSuccess(trace.CombineOutput().String())
			trace.ExpectContains("Final verdict: ALLOWED", "Policy trace output mismatch")

			trace = kubectl.CiliumExec(ciliumPod, fmt.Sprintf(
				"cilium policy trace --src-k8s-pod default:%s --dst-k8s-pod default:%s",
				appPods[helpers.App3], appPods[helpers.App1]))
			trace.ExpectSuccess(trace.CombineOutput().String())
			trace.ExpectContains("Final verdict: DENIED", "Policy trace output mismatch")

			res := kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectSuccess("%q cannot curl clusterIP %q", appPods[helpers.App2], clusterIP)

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("%q can curl to %q", appPods[helpers.App3], clusterIP)

			_, err = kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, l3Policy,
				helpers.KubectlDelete, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Cannot delete L3 Policy")

			By("Testing L7 Policy")

			_, err = kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, l7Policy, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Cannot install %q policy", l7Policy)

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				helpers.CurlFail("http://%s/public", clusterIP))
			res.ExpectSuccess("Cannot connect from %q to 'http://%s/public'",
				appPods[helpers.App2], clusterIP)

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/private", clusterIP)))
			res.ExpectFail("Unexpected connection from %q to 'http://%s/private'",
				appPods[helpers.App2], clusterIP)

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("Unexpected connection from %q to 'http://%s/public'",
				appPods[helpers.App3], clusterIP)

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App3],
				helpers.CurlFail("http://%s/private", clusterIP))
			res.ExpectFail("Unexpected connection from %q to 'http://%s/private'",
				appPods[helpers.App3], clusterIP)
		}, 500)

		It("ServiceAccount Based Enforcement", func() {
			// Load policy allowing serviceAccount of app2 to talk
			// to app1 on port 80 TCP
			_, err := kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, serviceAccountPolicy, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil())

			trace := kubectl.CiliumExec(ciliumPod, fmt.Sprintf(
				"cilium policy trace --src-k8s-pod default:%s --dst-k8s-pod default:%s --dport 80",
				appPods[helpers.App2], appPods[helpers.App1]))
			trace.ExpectSuccess(trace.CombineOutput().String())
			trace.ExpectContains("Final verdict: ALLOWED", "Policy trace output mismatch")

			trace = kubectl.CiliumExec(ciliumPod, fmt.Sprintf(
				"cilium policy trace --src-k8s-pod default:%s --dst-k8s-pod default:%s",
				appPods[helpers.App3], appPods[helpers.App1]))
			trace.ExpectSuccess(trace.CombineOutput().String())
			trace.ExpectContains("Final verdict: DENIED", "Policy trace output mismatch")

			res := kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectSuccess("%q cannot curl clusterIP %q", appPods[helpers.App2], clusterIP)

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("%q can curl to %q", appPods[helpers.App3], clusterIP)

		}, 500)

		It("CNP test MatchExpressions key", func() {
			_, err := kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, cnpMatchExpression, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "cannot install policy %s", cnpMatchExpression)

			res := kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectSuccess("%q cannot curl clusterIP %q", appPods[helpers.App2], clusterIP)

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("%q can curl to %q", appPods[helpers.App3], clusterIP)

		})

		It("Denies traffic with k8s default-deny ingress policy", func() {

			res := kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectSuccess("%q cannot curl clusterIP %q", appPods[helpers.App2], clusterIP)

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectSuccess("%q cannot curl to %q", appPods[helpers.App3], clusterIP)

			By("Installing knp ingress default-deny")

			// Import the policy and wait for all required endpoints to enforce the policy
			_, err := kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, knpDenyIngress, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(),
				"L3 deny-ingress Policy cannot be applied in %q namespace", helpers.DefaultNamespace)

			By("Testing connectivity with ingress default-deny policy loaded")

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("Ingress connectivity should be denied by policy")

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("Ingress connectivity should be denied by policy")
		})

		It("Denies traffic with k8s default-deny egress policy", func() {
			By("Installing knp egress default-deny")

			_, err := kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, knpDenyEgress, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(),
				"L3 deny-egress Policy cannot be applied in %q namespace", helpers.DefaultNamespace)

			By("Testing if egress policy enforcement is enabled on the endpoint")
			for _, pod := range []string{appPods[helpers.App2], appPods[helpers.App3]} {
				res := kubectl.ExecPodCmd(
					helpers.DefaultNamespace, pod,
					helpers.CurlFail("http://www.google.com/"))
				res.ExpectFail("Egress connectivity should be denied for pod %q", pod)

				res = kubectl.ExecPodCmd(
					helpers.DefaultNamespace, pod,
					helpers.Ping("8.8.8.8"))
				res.ExpectFail("Egress ping connectivity should be denied for pod %q", pod)

				res = kubectl.ExecPodCmd(
					helpers.DefaultNamespace, pod,
					"host www.google.com")
				res.ExpectFail("Egress DNS connectivity should be denied for pod %q", pod)
			}
		})

		It("Denies traffic with k8s default-deny ingress-egress policy", func() {
			By("Installing knp ingress-egress default-deny")

			_, err := kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, knpDenyIngressEgress, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(),
				"L3 deny-ingress-egress policy cannot be applied in %q namespace", helpers.DefaultNamespace)

			By("Testing if egress and ingress policy enforcement is enabled on the endpoint")
			for _, pod := range []string{appPods[helpers.App2], appPods[helpers.App3]} {
				res := kubectl.ExecPodCmd(
					helpers.DefaultNamespace, pod,
					helpers.CurlFail("http://www.google.com/"))
				res.ExpectFail("Egress connectivity should be denied for pod %q", pod)

				res = kubectl.ExecPodCmd(
					helpers.DefaultNamespace, pod,
					helpers.Ping("8.8.8.8"))
				res.ExpectFail("Egress ping connectivity should be denied for pod %q", pod)

				res = kubectl.ExecPodCmd(
					helpers.DefaultNamespace, pod,
					"host www.google.com")
				res.ExpectFail("Egress DNS connectivity should be denied for pod %q", pod)
			}

			By("Testing ingress connectivity with default-deny policy loaded")
			res := kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("Ingress connectivity should be denied by policy")

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("Ingress connectivity should be denied by policy")
		})

		It("Denies traffic with cnp default-deny ingress policy", func() {

			By("Installing cnp ingress default-deny")

			_, err := kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, cnpDenyIngress, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(),
				"L3 deny-ingress Policy cannot be applied in %q namespace", helpers.DefaultNamespace)

			By("Testing connectivity with ingress default-deny policy loaded")

			res := kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("Ingress connectivity should be denied by policy")

			By("Testing egress connnectivity works correctly")
			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				helpers.Ping("8.8.8.8"))
			res.ExpectSuccess("Egress ping connectivity should work")
		})

		It("Denies traffic with cnp default-deny egress policy", func() {

			By("Installing cnp egress default-deny")
			_, err := kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, cnpDenyEgress, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(),
				"L3 deny-egress Policy cannot be applied in %q namespace", helpers.DefaultNamespace)

			for _, pod := range apps {
				res := kubectl.ExecPodCmd(
					helpers.DefaultNamespace, pod,
					helpers.CurlFail("http://www.google.com/"))
				res.ExpectFail("Egress connectivity should be denied for pod %q", pod)

				res = kubectl.ExecPodCmd(
					helpers.DefaultNamespace, pod,
					helpers.Ping("8.8.8.8"))
				res.ExpectFail("Egress ping connectivity should be denied for pod %q", pod)

				res = kubectl.ExecPodCmd(
					helpers.DefaultNamespace, pod,
					"host www.google.com")
				res.ExpectFail("Egress DNS connectivity should be denied for pod %q", pod)
			}
		})

		It("Allows traffic with k8s default-allow ingress policy", func() {
			By("Installing ingress default-allow")
			_, err := kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, knpAllowIngress, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(),
				"L3 allow-ingress Policy cannot be applied in %q namespace", helpers.DefaultNamespace)

			By("Testing connectivity with ingress default-allow policy loaded")
			res := kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				helpers.CurlFail("http://%s/public", clusterIP))
			res.ExpectSuccess("Ingress connectivity should be allowed by policy")

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App3],
				helpers.CurlFail("http://%s/public", clusterIP))
			res.ExpectSuccess("Ingress connectivity should be allowed by policy")
		})

		It("Allows traffic with k8s default-allow egress policy", func() {
			By("Installing egress default-allow")
			_, err := kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, knpAllowEgress, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(),
				"L3 allow-egress Policy cannot be applied in %q namespace", helpers.DefaultNamespace)

			By("Checking connectivity between pods and external services after installing egress policy")

			for _, pod := range []string{appPods[helpers.App2], appPods[helpers.App3]} {
				res := kubectl.ExecPodCmd(
					helpers.DefaultNamespace, pod,
					helpers.CurlFail("http://www.google.com/"))
				res.ExpectSuccess("Egress connectivity should be allowed for pod %q", pod)

				res = kubectl.ExecPodCmd(
					helpers.DefaultNamespace, pod,
					helpers.Ping("8.8.8.8"))
				res.ExpectSuccess("Egress ping connectivity should be allowed for pod %q", pod)

				res = kubectl.ExecPodCmd(
					helpers.DefaultNamespace, pod,
					"host www.google.com")
				res.ExpectSuccess("Egress DNS connectivity should be allowed for pod %q", pod)
			}
		})

		Context("Validate to-entities policies", func() {
			const (
				WorldConnectivityDeny  = false
				WorldConnectivityAllow = true

				ClusterConnectivityDeny  = false
				ClusterConnectivityAllow = true
			)

			var (
				cnpToEntitiesAll     = helpers.ManifestGet("cnp-to-entities-all.yaml")
				cnpToEntitiesWorld   = helpers.ManifestGet("cnp-to-entities-world.yaml")
				cnpToEntitiesCluster = helpers.ManifestGet("cnp-to-entities-cluster.yaml")
				cnpToEntitiesHost    = helpers.ManifestGet("cnp-to-entities-host.yaml")
			)

			It("Validate toEntities All", func() {
				By("Installing toEntities All")
				importPolicy(cnpToEntitiesAll, "to-entities-all")

				By("Verifying policy correctness")
				validateConnectivity(WorldConnectivityAllow, ClusterConnectivityAllow)
			})

			It("Validate toEntities World", func() {
				By("Installing toEntities World")
				importPolicy(cnpToEntitiesWorld, "to-entities-world")

				By("Verifying policy correctness")
				validateConnectivity(WorldConnectivityAllow, ClusterConnectivityDeny)

			})

			It("Validate toEntities Cluster", func() {
				By("Installing toEntities Cluster")
				importPolicy(cnpToEntitiesCluster, "to-entities-cluster")

				By("Verifying policy correctness")
				validateConnectivity(WorldConnectivityDeny, ClusterConnectivityAllow)
			})

			It("Validate toEntities Host", func() {
				By("Installing toEntities Host")
				importPolicy(cnpToEntitiesHost, "to-entities-host")

				By("Verifying policy correctness")
				validateConnectivity(WorldConnectivityDeny, ClusterConnectivityDeny)
			})
		})

		Context("Validate CNP update", func() {
			const (
				allowAll     = true
				denyFromApp3 = false
			)

			var (
				cnpUpdateAllow        = helpers.ManifestGet("cnp-update-allow-all.yaml")
				cnpUpdateDeny         = helpers.ManifestGet("cnp-update-deny-ingress.yaml")
				cnpUpdateNoSpecs      = helpers.ManifestGet("cnp-update-no-specs.yaml")
				cnpUpdateDenyLabelled = helpers.ManifestGet("cnp-update-deny-ingress-labelled.yaml")
			)

			validateL3L4 := func(allowApp3 bool) {
				res := kubectl.ExecPodCmd(
					helpers.DefaultNamespace, appPods[helpers.App2],
					helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
				ExpectWithOffset(1, res).Should(helpers.CMDSuccess(),
					"%q cannot curl clusterIP %q",
					appPods[helpers.App2], clusterIP)

				res = kubectl.ExecPodCmd(
					helpers.DefaultNamespace, appPods[helpers.App3],
					helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
				ExpectWithOffset(1, res).To(getMatcher(allowApp3),
					"%q curl clusterIP %q (expected to allow: %t)",
					appPods[helpers.App3], clusterIP, allowApp3)
			}

			It("Enforces connectivity correctly when the same L3/L4 CNP is updated", func() {
				By("Applying default allow policy")
				_, err := kubectl.CiliumPolicyAction(
					helpers.KubeSystemNamespace, cnpUpdateAllow, helpers.KubectlApply, helpers.HelperTimeout)
				Expect(err).Should(BeNil(), "%q Policy cannot be applied", cnpUpdateAllow)

				validateL3L4(allowAll)

				By("Applying l3-l4 policy")
				_, err = kubectl.CiliumPolicyAction(
					helpers.KubeSystemNamespace, cnpUpdateDeny, helpers.KubectlApply, helpers.HelperTimeout)
				Expect(err).Should(BeNil(), "%q Policy cannot be applied", cnpUpdateDeny)

				validateL3L4(denyFromApp3)

				By("Applying no-specs policy")
				_, err = kubectl.CiliumPolicyAction(
					helpers.KubeSystemNamespace, cnpUpdateNoSpecs, helpers.KubectlApply, helpers.HelperTimeout)
				Expect(err).Should(BeNil(), "%q Policy cannot be applied", cnpUpdateAllow)

				validateL3L4(allowAll)

				By("Applying l3-l4 policy with user-specified labels")
				_, err = kubectl.CiliumPolicyAction(
					helpers.KubeSystemNamespace, cnpUpdateDenyLabelled, helpers.KubectlApply, helpers.HelperTimeout)
				Expect(err).Should(BeNil(), "%q Policy cannot be applied", cnpUpdateDeny)

				validateL3L4(denyFromApp3)

				By("Applying default allow policy (should remove policy with user labels)")
				_, err = kubectl.CiliumPolicyAction(
					helpers.KubeSystemNamespace, cnpUpdateAllow, helpers.KubectlApply, helpers.HelperTimeout)
				Expect(err).Should(BeNil(), "%q Policy cannot be applied", cnpUpdateAllow)

				validateL3L4(allowAll)
			})

			It("Verifies that a CNP with L7 HTTP rules can be replaced with L7 Kafka rules", func() {
				By("Installing L7 Policy")

				// This HTTP policy was already validated in the
				// test "checks all kind of Kubernetes policies".
				// Install it then move on.
				_, err := kubectl.CiliumPolicyAction(
					helpers.KubeSystemNamespace, l7Policy, helpers.KubectlApply, helpers.HelperTimeout)
				Expect(err).Should(BeNil(), "Cannot install %q policy", l7Policy)

				// Update existing policy on port 80 from http to kafka
				// to test ability to change L7 parser type of a port.
				// Traffic cannot flow but policy must be able to be
				// imported and applied to the endpoints.
				_, err = kubectl.CiliumPolicyAction(
					helpers.KubeSystemNamespace, l7PolicyKafka, helpers.KubectlApply, helpers.HelperTimeout)
				Expect(err).Should(BeNil(), "Cannot update L7 policy (%q) from parser http to kafka", l7PolicyKafka)

				res := kubectl.ExecPodCmd(
					helpers.DefaultNamespace, appPods[helpers.App3],
					helpers.CurlFail("http://%s/public", clusterIP))
				res.ExpectFail("Unexpected connection from %q to 'http://%s/public'",
					appPods[helpers.App3], clusterIP)

				res = kubectl.ExecPodCmd(
					helpers.DefaultNamespace, appPods[helpers.App2],
					helpers.CurlFail("http://%s/public", clusterIP))
				res.ExpectFail("Unexpected connection from %q to 'http://%s/public'",
					appPods[helpers.App2], clusterIP)
			})
		})

	})

	Context("GuestBook Examples", func() {
		var (
			deployment                = "guestbook_deployment.json"
			groupLabel                = "zgroup=guestbook"
			redisPolicy               = "guestbook-policy-redis.json"
			redisPolicyName           = "guestbook-policy-redis"
			redisPolicyDeprecated     = "guestbook-policy-redis-deprecated.json"
			redisPolicyDeprecatedName = "guestbook-redis-deprecated"
			webPolicy                 = "guestbook-policy-web.yaml"
			webPolicyName             = "guestbook-policy-web"
		)

		var ciliumPods []string
		var err error

		BeforeEach(func() {
			kubectl.Apply(helpers.ManifestGet(deployment))
			ciliumPods, err := kubectl.GetCiliumPods(helpers.KubeSystemNamespace)
			Expect(err).To(BeNil(), "cannot retrieve Cilium Pods")
			Expect(ciliumPods).ShouldNot(BeEmpty(), "cannot retrieve Cilium pods")
		})

		getPolicyCmd := func(policy string) string {
			return fmt.Sprintf("%s=%s %s=%s",
				helpers.KubectlPolicyNameLabel, policy,
				helpers.KubectlPolicyNameSpaceLabel, helpers.DefaultNamespace)
		}

		AfterEach(func() {

			kubectl.Delete(helpers.ManifestGet(webPolicy)).ExpectSuccess(
				"Web policy cannot be deleted")
			kubectl.Delete(helpers.ManifestGet(redisPolicyDeprecated)).ExpectSuccess(
				"Redis deprecated policy cannot be deleted")
			kubectl.Delete(helpers.ManifestGet(deployment)).ExpectSuccess(
				"Guestbook deployment cannot be deleted")

			// This policy shouldn't be there, but test can fail before delete
			// the policy and we want to make sure that it's deleted
			kubectl.Delete(helpers.ManifestGet(redisPolicy))
			for _, ciliumPod := range ciliumPods {
				err := kubectl.WaitPolicyDeleted(ciliumPod, getPolicyCmd(webPolicyName))
				Expect(err).To(
					BeNil(), "WebPolicy is not deleted")

				err = kubectl.WaitPolicyDeleted(ciliumPod, getPolicyCmd(redisPolicyName))
				Expect(err).To(
					BeNil(), "RedisPolicy is not deleted")
			}
			ExpectAllPodsTerminated(kubectl)
		})

		waitforPods := func() {

			err = kubectl.WaitforPods(
				helpers.DefaultNamespace,
				fmt.Sprintf("-l %s", groupLabel), helpers.HelperTimeout)
			ExpectWithOffset(1, err).Should(BeNil(), "Bookinfo pods are not ready after timeout")

			err := kubectl.WaitForServiceEndpoints(
				helpers.DefaultNamespace, "", "redis-master", helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "error waiting for redis-master service to be ready")

			err = kubectl.WaitForServiceEndpoints(
				helpers.DefaultNamespace, "", "redis-slave", helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "error waiting for redis-slave service to be ready")

		}

		policyCheckStatus := func(policyCheck string) {
			for _, ciliumPod := range ciliumPods {
				ExpectWithOffset(1, kubectl.CiliumIsPolicyLoaded(ciliumPod, policyCheck)).To(BeTrue(),
					"Policy %q is not in cilium pod %s", policyCheck, ciliumPod)
			}
		}

		testConnectivitytoRedis := func() {
			webPods, err := kubectl.GetPodsNodes(helpers.DefaultNamespace, "-l k8s-app.guestbook=web")
			Expect(err).To(BeNil(), "Cannot get web pods")

			serviceIP, port, err := kubectl.GetServiceHostPort(helpers.DefaultNamespace, "redis-master")
			Expect(err).To(BeNil(), "Cannot get hostPort of redis-master")

			serviceName := "redis-master"
			err = kubectl.WaitForKubeDNSEntry(serviceName, helpers.DefaultNamespace)
			Expect(err).To(BeNil(), "DNS entry is not ready after timeout")

			for pod := range webPods {

				redisMetadata := map[string]int{serviceIP: port, serviceName: port}
				for k, v := range redisMetadata {
					command := fmt.Sprintf(`nc %s %d <<EOF
PING
EOF`, k, v)
					res := kubectl.ExecPodCmd(helpers.DefaultNamespace, pod, command)
					ExpectWithOffset(1, res).To(helpers.CMDSuccess(),
						"Web pod %q cannot connect to redis-master on '%s:%d'", pod, k, v)
				}
			}
		}
		It("checks policy example", func() {

			waitforPods()

			By("Apply policy to web")
			_, err = kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, helpers.ManifestGet(webPolicy),
				helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Cannot apply web-policy")

			policyCheck := fmt.Sprintf("%s=%s %s=%s",
				helpers.KubectlPolicyNameLabel, webPolicyName,
				helpers.KubectlPolicyNameSpaceLabel, helpers.DefaultNamespace)
			policyCheckStatus(policyCheck)

			By("Apply policy to Redis")
			_, err = kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, helpers.ManifestGet(redisPolicy),
				helpers.KubectlApply, helpers.HelperTimeout)

			Expect(err).Should(BeNil(), "Cannot apply redis policy")

			policyCheck = fmt.Sprintf("%s=%s %s=%s",
				helpers.KubectlPolicyNameLabel, redisPolicyName,
				helpers.KubectlPolicyNameSpaceLabel, helpers.DefaultNamespace)
			policyCheckStatus(policyCheck)

			testConnectivitytoRedis()

			_, err = kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, helpers.ManifestGet(redisPolicy),
				helpers.KubectlDelete, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Cannot apply redis policy")

			By("Apply deprecated policy to Redis")

			_, err = kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, helpers.ManifestGet(redisPolicyDeprecated),
				helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Cannot apply redis deprecated policy err: %q", err)

			policyCheck = fmt.Sprintf("%s=%s %s=%s",
				helpers.KubectlPolicyNameLabel, redisPolicyDeprecatedName,
				helpers.KubectlPolicyNameSpaceLabel, helpers.DefaultNamespace)
			policyCheckStatus(policyCheck)

			testConnectivitytoRedis()
		})
	})

	Context("Namespaces policies", func() {

		var (
			err               error
			secondNS          = "second"
			appPods           map[string]string
			appPodsNS         map[string]string
			clusterIP         string
			secondNSclusterIP string

			demoPath           = helpers.ManifestGet("demo.yaml")
			l3L4Policy         = helpers.ManifestGet("l3-l4-policy.yaml")
			cnpSecondNS        = helpers.ManifestGet("cnp-second-namespaces.yaml")
			netpolNsSelector   = fmt.Sprintf("%s -n %s", helpers.ManifestGet("netpol-namespace-selector.yaml"), secondNS)
			l3l4PolicySecondNS = fmt.Sprintf("%s -n %s", l3L4Policy, secondNS)
			demoManifest       = fmt.Sprintf("%s -n %s", demoPath, secondNS)
		)

		BeforeAll(func() {

			res := kubectl.NamespaceCreate(secondNS)
			res.ExpectSuccess("unable to create namespace %q", secondNS)

			res = kubectl.Exec(fmt.Sprintf("kubectl label namespaces/%[1]s nslabel=%[1]s", secondNS))
			res.ExpectSuccess("cannot create namespace labels")

			res = kubectl.Apply(demoManifest)
			res.ExpectSuccess("unable to apply manifest")

			res = kubectl.Apply(demoPath)
			res.ExpectSuccess("unable to apply manifest")

			err := kubectl.WaitforPods(secondNS, "-l zgroup=testapp", helpers.HelperTimeout)
			Expect(err).To(BeNil(),
				"testapp pods are not ready after timeout in namspace %q", secondNS)

			err = kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", helpers.HelperTimeout)
			Expect(err).To(BeNil(),
				"testapp pods are not ready after timeout in %q namespace", helpers.DefaultNamespace)

			appPods = helpers.GetAppPods(apps, helpers.DefaultNamespace, kubectl, "id")
			appPodsNS = helpers.GetAppPods(apps, secondNS, kubectl, "id")

			clusterIP, _, err = kubectl.GetServiceHostPort(helpers.DefaultNamespace, app1Service)
			Expect(err).To(BeNil(), "Cannot get service on %q namespace", helpers.DefaultNamespace)

			secondNSclusterIP, _, err = kubectl.GetServiceHostPort(secondNS, app1Service)
			Expect(err).To(BeNil(), "Cannot get service on %q namespace", secondNS)

		})

		AfterEach(func() {
			// Explicitly do not check results to avoid incomplete teardown of test.
			_ = kubectl.Delete(l3l4PolicySecondNS)
			_ = kubectl.Delete(l3L4Policy)
			_ = kubectl.Delete(netpolNsSelector)

		})

		AfterAll(func() {
			_ = kubectl.Delete(demoPath)
			_ = kubectl.Delete(demoManifest)
			_ = kubectl.NamespaceDelete(secondNS)
			_ = kubectl.NamespaceDelete(cnpSecondNS)
		})

		It("Tests the same Policy in different namespaces", func() {
			// Tests that the same policy(name,labels) can enforce based on the
			// namespace and all works as expected.
			By("Applying Policy in %q namespace", secondNS)
			_, err = kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, l3l4PolicySecondNS, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(),
				"%q Policy cannot be applied in %q namespace", l3l4PolicySecondNS, secondNS)

			By("Applying Policy in default namespace")
			_, err = kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, l3L4Policy, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(),
				"%q Policy cannot be applied in %q namespace", l3L4Policy, helpers.DefaultNamespace)

			By("Testing connectivity in %q namespace", secondNS)

			res := kubectl.ExecPodCmd(
				secondNS, appPodsNS[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", secondNSclusterIP)))
			res.ExpectSuccess("%q cannot curl service", appPods[helpers.App2])

			res = kubectl.ExecPodCmd(
				secondNS, appPodsNS[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", secondNSclusterIP)))
			res.ExpectFail("%q can curl to service", appPods[helpers.App3])

			By("Testing connectivity in 'default' namespace")

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectSuccess("%q cannot curl clusterIP %q", appPods[helpers.App2], clusterIP)

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("%q can curl to %q", appPods[helpers.App3], clusterIP)
		})

		It("Kubernetes Network Policy by namespace selector", func() {
			// Use namespace selector using Kubernetes Network Policy to make
			// sure that it is translated correctly to Cilium and applies the
			// policies to the right endpoints.
			// KNP reference:
			// https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.10/#networkpolicyspec-v1-networking-k8s-io
			By("Testing connectivity across Namespaces without policy")
			for _, pod := range []string{helpers.App2, helpers.App3} {
				res := kubectl.ExecPodCmd(
					helpers.DefaultNamespace, appPods[pod],
					helpers.CurlFail(fmt.Sprintf("http://%s/public", secondNSclusterIP)))
				res.ExpectSuccess("%q cannot curl service", appPods[pod])

				res = kubectl.ExecPodCmd(
					secondNS, appPodsNS[pod],
					helpers.CurlFail(fmt.Sprintf("http://%s/public", secondNSclusterIP)))
				res.ExpectSuccess("%q cannot curl service", appPodsNS[pod])
			}

			By("Applying Policy in %q namespace", secondNS)
			_, err = kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, netpolNsSelector, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Policy cannot be applied")

			for _, pod := range []string{helpers.App2, helpers.App3} {
				// Make sure that the Default namespace can NOT connect to
				// second namespace.
				res := kubectl.ExecPodCmd(
					helpers.DefaultNamespace, appPods[pod],
					helpers.CurlFail(fmt.Sprintf("http://%s/public", secondNSclusterIP)))
				res.ExpectFail("%q can curl to service, policy is not blocking"+
					"communication to %q namespace", appPods[pod], secondNS)

				// Second namespace pods can connect to the same namespace based on policy.
				res = kubectl.ExecPodCmd(
					secondNS, appPodsNS[pod],
					helpers.CurlFail(fmt.Sprintf("http://%s/public", secondNSclusterIP)))
				res.ExpectSuccess("%q cannot curl service", appPodsNS[pod])
			}

			By("Delete Kubernetes Network Policies in %q namespace", secondNS)
			_, err = kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, netpolNsSelector, helpers.KubectlDelete, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Policy %q cannot be deleted", netpolNsSelector)

			for _, pod := range []string{helpers.App2, helpers.App3} {
				res := kubectl.ExecPodCmd(
					helpers.DefaultNamespace, appPods[pod],
					helpers.CurlFail(fmt.Sprintf("http://%s/public", secondNSclusterIP)))
				res.ExpectSuccess("%q cannot curl service", appPods[pod])

				res = kubectl.ExecPodCmd(
					secondNS, appPodsNS[pod],
					helpers.CurlFail(fmt.Sprintf("http://%s/public", secondNSclusterIP)))
				res.ExpectSuccess("%q cannot curl service", appPodsNS[pod])
			}
		})

		It("Cilium Network policy using namespace label and L7", func() {

			_, err := kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, cnpSecondNS, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "%q Policy cannot be applied", cnpSecondNS)

			By("Testing connectivity in %q namespace", secondNS)
			res := kubectl.ExecPodCmd(
				secondNS, appPodsNS[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectSuccess("Cannot curl service in %s ns", helpers.DefaultNamespace)

			res = kubectl.ExecPodCmd(
				secondNS, appPodsNS[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectSuccess("Cannot curl service in %s ns", helpers.DefaultNamespace)

			By("Testing connectivity from 'default' namespace")

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("Can connect when it should not")

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("Can connect when it should not")
		})

	})
})
