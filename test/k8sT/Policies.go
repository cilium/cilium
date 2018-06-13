// Copyright 2017-2018 Authors of Cilium
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

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("K8sValidatedPolicyTest", func() {

	var (
		kubectl              *helpers.Kubectl
		demoPath             = helpers.ManifestGet("demo.yaml")
		l3Policy             = helpers.ManifestGet("l3_l4_policy.yaml")
		l7Policy             = helpers.ManifestGet("l7_policy.yaml")
		serviceAccountPolicy = helpers.ManifestGet("service_account.yaml")
		knpDenyIngress       = helpers.ManifestGet("knp-default-deny-ingress.yaml")
		knpDenyEgress        = helpers.ManifestGet("knp-default-deny-egress.yaml")
		knpDenyIngressEgress = helpers.ManifestGet("knp-default-deny-ingress-egress.yaml")
		cnpDenyIngress       = helpers.ManifestGet("cnp-default-deny-ingress.yaml")
		cnpDenyEgress        = helpers.ManifestGet("cnp-default-deny-egress.yaml")
		knpAllowIngress      = helpers.ManifestGet("knp-default-allow-ingress.yaml")
		knpAllowEgress       = helpers.ManifestGet("knp-default-allow-egress.yaml")
		logger               *logrus.Entry
		app1Service          = "app1-service"
		microscopeErr        error
		microscopeCancel     = func() error { return nil }

		podFilter = "k8s:zgroup=testapp"
		apps      = []string{helpers.App1, helpers.App2, helpers.App3}
	)

	BeforeAll(func() {
		logger = log.WithFields(logrus.Fields{"testName": "K8sPolicyTest"})
		logger.Info("Starting")
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		err := kubectl.CiliumInstall(helpers.CiliumDSPath)
		Expect(err).To(BeNil(), "Cilium cannot be installed")

		ExpectCiliumReady(kubectl)
		ExpectKubeDNSReady(kubectl)
	})

	AfterEach(func() {
		ExpectAllPodsTerminated(kubectl)
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

	Context("Basic Test", func() {
		var (
			ciliumPod string
			clusterIP string
			appPods   map[string]string
		)

		BeforeAll(func() {
			kubectl.Apply(demoPath)

			err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", 300)
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

			err = kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", 300)
			Expect(err).Should(BeNil())

		})

		AfterEach(func() {
			// TO make sure that are not in place, so no assert messages here
			kubectl.Delete(l3Policy)
			kubectl.Delete(l7Policy)
			kubectl.Delete(serviceAccountPolicy)
			kubectl.Delete(knpDenyIngress)
			kubectl.Delete(knpDenyEgress)
			kubectl.Delete(knpDenyIngressEgress)
			kubectl.Delete(cnpDenyIngress)
			kubectl.Delete(cnpDenyEgress)
			kubectl.Delete(knpAllowEgress)
			kubectl.Delete(knpAllowIngress)
		})

		It("tests PolicyEnforcement updates", func() {
			By("Waiting for cilium pod and endpoints on K8s1 to be ready")
			_, endpoints := kubectl.WaitCiliumEndpointReady(podFilter, helpers.K8s1)
			policyStatus := endpoints.GetPolicyStatus()
			// default mode with no policy, all endpoints must be in allow all
			Expect(policyStatus[models.EndpointPolicyEnabledNone]).Should(Equal(4))
			Expect(policyStatus[models.EndpointPolicyEnabledIngress]).Should(Equal(0))
			Expect(policyStatus[models.EndpointPolicyEnabledEgress]).Should(Equal(0))
			Expect(policyStatus[models.EndpointPolicyEnabledBoth]).Should(Equal(0))

			By("Set PolicyEnforcement to always")

			status := kubectl.CiliumExec(
				ciliumPod, fmt.Sprintf("cilium config %s=%s",
					helpers.PolicyEnforcement, helpers.PolicyEnforcementAlways))
			status.ExpectSuccess()

			err := kubectl.CiliumEndpointWaitReady()
			Expect(err).To(BeNil(), "Endpoints are not ready after timeout")

			endpoints, err = kubectl.CiliumEndpointsListByLabel(ciliumPod, podFilter)
			Expect(err).Should(BeNil())
			Expect(endpoints.AreReady()).Should(BeTrue())
			policyStatus = endpoints.GetPolicyStatus()
			// Always-on mode with no policy, all endpoints must be in default deny
			Expect(policyStatus[models.EndpointPolicyEnabledNone]).Should(Equal(0))
			Expect(policyStatus[models.EndpointPolicyEnabledIngress]).Should(Equal(0))
			Expect(policyStatus[models.EndpointPolicyEnabledEgress]).Should(Equal(0))
			Expect(policyStatus[models.EndpointPolicyEnabledBoth]).Should(Equal(4))

			By("Return PolicyEnforcement to default")

			status = kubectl.CiliumExec(
				ciliumPod, fmt.Sprintf("cilium config %s=%s",
					helpers.PolicyEnforcement, helpers.PolicyEnforcementDefault))
			status.ExpectSuccess()

			err = kubectl.CiliumEndpointWaitReady()
			Expect(err).To(BeNil(), "Endpoints are not ready after timeout")

			endpoints, err = kubectl.CiliumEndpointsListByLabel(ciliumPod, podFilter)
			Expect(err).Should(BeNil())
			Expect(endpoints.AreReady()).Should(BeTrue())
			policyStatus = endpoints.GetPolicyStatus()
			// Default mode with no policy, all endpoints must still be in default allow
			Expect(policyStatus[models.EndpointPolicyEnabledNone]).Should(Equal(4))
			Expect(policyStatus[models.EndpointPolicyEnabledIngress]).Should(Equal(0))
			Expect(policyStatus[models.EndpointPolicyEnabledEgress]).Should(Equal(0))
			Expect(policyStatus[models.EndpointPolicyEnabledBoth]).Should(Equal(0))
		}, 500)

		It("checks all kind of Kubernetes policies", func() {
			logger.Infof("PolicyRulesTest: cluster service ip '%s'", clusterIP)

			By("Testing L3/L4 rules")

			_, err := kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, l3Policy, helpers.KubectlApply, 300)
			Expect(err).Should(BeNil())

			endpoints, err := kubectl.CiliumEndpointsListByLabel(ciliumPod, podFilter)
			policyStatus := endpoints.GetPolicyStatus()
			// only the two app1 replicas should be in default-deny at ingress
			Expect(policyStatus[models.EndpointPolicyEnabledNone]).Should(Equal(2))
			Expect(policyStatus[models.EndpointPolicyEnabledIngress]).Should(Equal(2))
			Expect(policyStatus[models.EndpointPolicyEnabledEgress]).Should(Equal(0))
			Expect(policyStatus[models.EndpointPolicyEnabledBoth]).Should(Equal(0))

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
				helpers.KubeSystemNamespace, l7Policy, helpers.KubectlApply, 300)
			Expect(err).Should(BeNil(), "Cannot install %q policy", l7Policy)

			endpoints, err = kubectl.CiliumEndpointsListByLabel(ciliumPod, podFilter)
			policyStatus = endpoints.GetPolicyStatus()
			// only the two app1 replicas should be in default-deny at ingress
			Expect(policyStatus[models.EndpointPolicyEnabledNone]).Should(Equal(2))
			Expect(policyStatus[models.EndpointPolicyEnabledIngress]).Should(Equal(2))
			Expect(policyStatus[models.EndpointPolicyEnabledEgress]).Should(Equal(0))
			Expect(policyStatus[models.EndpointPolicyEnabledBoth]).Should(Equal(0))

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

			_, err = kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, l7Policy,
				helpers.KubectlDelete, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Cannot delete L7 Policy")

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App3],
				helpers.CurlFail("http://%s/public", clusterIP))
			res.ExpectSuccess("%q cannot curl to %q public", appPods[helpers.App3], clusterIP)

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				helpers.CurlFail("http://%s/public", clusterIP))
			res.ExpectSuccess("%q cannot curl to %q public", appPods[helpers.App2], clusterIP)
		}, 500)

		It("ServiceAccount Based Enforcement", func() {
			// Load policy allowing serviceAccount of app2 to talk
			// to app1 on port 80 TCP
			_, err := kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, serviceAccountPolicy, helpers.KubectlApply, 300)
			Expect(err).Should(BeNil())

			endpoints, err := kubectl.CiliumEndpointsListByLabel(ciliumPod, podFilter)
			policyStatus := endpoints.GetPolicyStatus()
			// only the two app1 replicas should be in default-deny at ingress
			Expect(policyStatus[models.EndpointPolicyEnabledNone]).Should(Equal(2))
			Expect(policyStatus[models.EndpointPolicyEnabledIngress]).Should(Equal(2))
			Expect(policyStatus[models.EndpointPolicyEnabledEgress]).Should(Equal(0))
			Expect(policyStatus[models.EndpointPolicyEnabledBoth]).Should(Equal(0))

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
				helpers.KubeSystemNamespace, serviceAccountPolicy,
				helpers.KubectlDelete, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Cannot delete service account policy")
		}, 500)

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

			eps := kubectl.CiliumEndpointPolicyVersion(ciliumPod)

			_, err := kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, knpDenyIngress, helpers.KubectlApply, 300)
			Expect(err).Should(BeNil(),
				"L3 deny-ingress Policy cannot be applied in %q namespace", helpers.DefaultNamespace)

			err = helpers.WaitUntilEndpointUpdates(ciliumPod, eps, 4, kubectl)
			Expect(err).To(BeNil(), "Waiting for endpoint updates on %s", ciliumPod)

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
			if helpers.GetCurrentK8SEnv() == "1.7" {
				log.Info("K8s 1.7 doesn't offer a default deny for egress")
				return
			}

			By("Installing knp egress default-deny")

			_, err := kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, knpDenyEgress, helpers.KubectlApply, 300)
			Expect(err).Should(BeNil(),
				"L3 deny-egress Policy cannot be applied in %q namespace", helpers.DefaultNamespace)

			By("Testing if egress policy enforcement is enabled on the endpoint")

			var epList []models.Endpoint
			err = kubectl.CiliumEndpointsList(ciliumPod).Unmarshal(&epList)
			Expect(err).To(BeNil(), "Getting a list of endpoints from %s", ciliumPod)

			epsWithEgress := 0
			for _, ep := range epList {
				for _, lbls := range ep.Status.Labels.SecurityRelevant {
					if lbls == "k8s:io.kubernetes.pod.namespace="+helpers.DefaultNamespace {
						switch ep.Status.Policy.Realized.PolicyEnabled {
						case models.EndpointPolicyEnabledBoth, models.EndpointPolicyEnabledEgress:
							epsWithEgress++
						}
					}
				}
			}
			Expect(epsWithEgress).To(Equal(4), "All endpoints should have egress policy enabled")
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
			if helpers.GetCurrentK8SEnv() == "1.7" {
				log.Info("K8s 1.7 doesn't offer a default deny for egress")
				return
			}

			By("Installing knp ingress-egress default-deny")

			_, err := kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, knpDenyIngressEgress, helpers.KubectlApply, 300)
			Expect(err).Should(BeNil(),
				"L3 deny-ingress-egress policy cannot be applied in %q namespace", helpers.DefaultNamespace)

			By("Testing if egress policy enforcement is enabled on the endpoint")

			var epList []models.Endpoint
			err = kubectl.CiliumEndpointsList(ciliumPod).Unmarshal(&epList)
			Expect(err).To(BeNil(), "Getting a list of endpoints from %s", ciliumPod)

			epsWithEgress := 0
			for _, ep := range epList {
				for _, lbls := range ep.Status.Labels.SecurityRelevant {
					if lbls == "k8s:io.kubernetes.pod.namespace="+helpers.DefaultNamespace {
						switch ep.Status.Policy.Realized.PolicyEnabled {
						case models.EndpointPolicyEnabledBoth, models.EndpointPolicyEnabledEgress:
							epsWithEgress++
						}
					}
				}
			}
			Expect(epsWithEgress).To(Equal(4), "All endpoints should have egress policy enabled")
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

			res := kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectSuccess("%q cannot curl clusterIP %q", appPods[helpers.App2], clusterIP)

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectSuccess("%q cannot curl to %q", appPods[helpers.App3], clusterIP)

			By("Installing cnp ingress default-deny")

			_, err := kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, cnpDenyIngress, helpers.KubectlApply, 300)
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

		It("Denies traffic with cnp default-deny egress policy", func() {

			By("Installing cnp egress default-deny")

			eps := kubectl.CiliumEndpointPolicyVersion(ciliumPod)

			_, err := kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, cnpDenyEgress, helpers.KubectlApply, 300)
			Expect(err).Should(BeNil(),
				"L3 deny-egress Policy cannot be applied in %q namespace", helpers.DefaultNamespace)

			err = helpers.WaitUntilEndpointUpdates(ciliumPod, eps, 4, kubectl)
			Expect(err).To(BeNil(), "Waiting for endpoint updates on %s", ciliumPod)

			By("Testing if egress policy enforcement is enabled on the endpoint")

			var epList []models.Endpoint
			err = kubectl.CiliumEndpointsList(ciliumPod).Unmarshal(&epList)
			Expect(err).To(BeNil(), "Getting a list of endpoints from %s", ciliumPod)

			epsWithEgress := 0
			for _, ep := range epList {
				for _, lbls := range ep.Status.Labels.SecurityRelevant {
					if lbls == "k8s:io.kubernetes.pod.namespace="+helpers.DefaultNamespace {
						switch ep.Status.Policy.Realized.PolicyEnabled {
						case models.EndpointPolicyEnabledBoth, models.EndpointPolicyEnabledEgress:
							epsWithEgress++
						}
					}
				}
			}
			Expect(epsWithEgress).To(Equal(4), "All endpoints should have egress policy enabled")
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

		It("Allows traffic with k8s default-allow ingress policy", func() {
			By("Installing ingress default-allow")
			_, err := kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, knpAllowIngress, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(),
				"L3 allow-ingress Policy cannot be applied in %q namespace", helpers.DefaultNamespace)

			By("Checking that all endpoints have ingress enforcement enabled")
			endpoints, err := kubectl.CiliumEndpointsListByLabel(ciliumPod, podFilter)
			Expect(err).Should(BeNil())
			Expect(endpoints.AreReady()).Should(BeTrue())
			policyStatus := endpoints.GetPolicyStatus()
			// Always-on mode with no policy, all endpoints must be in default deny
			Expect(policyStatus[models.EndpointPolicyEnabledNone]).Should(Equal(0))
			Expect(policyStatus[models.EndpointPolicyEnabledIngress]).Should(Equal(4))
			Expect(policyStatus[models.EndpointPolicyEnabledEgress]).Should(Equal(0))
			Expect(policyStatus[models.EndpointPolicyEnabledBoth]).Should(Equal(0))

			By("Testing connectivity with ingress default-allow policy loaded")

			res := kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				helpers.CurlWithHTTPCode("http://%s/public", clusterIP))
			res.ExpectSuccess("Ingress connectivity should be allowed by policy")

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App3],
				helpers.CurlWithHTTPCode("http://%s/public", clusterIP))
			res.ExpectSuccess("Ingress connectivity should be allowed by policy")
		})

		It("Allows traffic with k8s default-allow egress policy", func() {

			if helpers.GetCurrentK8SEnv() == "1.7" {
				log.Info("K8s 1.7 doesn't offer a default allow for egress")
				return
			}

			By("Installing egress default-allow")
			_, err := kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, knpAllowEgress, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(),
				"L3 allow-egress Policy cannot be applied in %q namespace", helpers.DefaultNamespace)

			By("Checking that all endpoints have egress enforcement enabled")
			endpoints, err := kubectl.CiliumEndpointsListByLabel(ciliumPod, podFilter)
			Expect(err).Should(BeNil())
			Expect(endpoints.AreReady()).Should(BeTrue())
			policyStatus := endpoints.GetPolicyStatus()
			// Always-on mode with no policy, all endpoints must be in default deny
			Expect(policyStatus[models.EndpointPolicyEnabledNone]).Should(Equal(0))
			Expect(policyStatus[models.EndpointPolicyEnabledIngress]).Should(Equal(0))
			Expect(policyStatus[models.EndpointPolicyEnabledEgress]).Should(Equal(4))
			Expect(policyStatus[models.EndpointPolicyEnabledBoth]).Should(Equal(0))

			By("Checking connectivity between pods and external services after installing egress policy")

			for _, pod := range []string{appPods[helpers.App2], appPods[helpers.App3]} {
				res := kubectl.ExecPodCmd(
					helpers.DefaultNamespace, pod,
					helpers.CurlWithHTTPCode("http://www.google.com/"))
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
	})

	Context("GuestBook Examples", func() {
		var (
			deployment                = "guestbook_deployment.json"
			groupLabel                = "zgroup=guestbook"
			redisPolicy               = "guestbook-policy-redis.json"
			redisPolicyName           = "guestbook-redis"
			redisPolicyDeprecated     = "guestbook-policy-redis-deprecated.json"
			redisPolicyDeprecatedName = "guestbook-redis-deprecated"
			webPolicy                 = "guestbook-policy-web.yaml"
			webPolicyName             = "guestbook-web"
		)

		var ciliumPod, ciliumPod2 string
		var err error

		BeforeEach(func() {
			kubectl.Apply(helpers.ManifestGet(deployment))

			ciliumPod, err = kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s1)
			Expect(err).Should(BeNil())

			ciliumPod2, err = kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s2)
			Expect(err).Should(BeNil())
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

			Expect(kubectl.CiliumIsPolicyLoaded(ciliumPod, getPolicyCmd(webPolicyName))).To(
				BeFalse(), "WebPolicy is not deleted")
			Expect(kubectl.CiliumIsPolicyLoaded(ciliumPod, getPolicyCmd(redisPolicyName))).To(
				BeFalse(), "RedisPolicyName is not deleted")

			ExpectAllPodsTerminated(kubectl)
		})

		waitforPods := func() {
			port := "6379"
			err := kubectl.WaitForServiceEndpoints(
				helpers.DefaultNamespace, "", "redis-master", port, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "error waiting for redis-master service to be ready on port %s", port)

			err = kubectl.WaitForServiceEndpoints(
				helpers.DefaultNamespace, "", "redis-slave", port, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "error waiting for redis-slave service to be ready on port %s", port)

			err = kubectl.WaitforPods(
				helpers.DefaultNamespace,
				fmt.Sprintf("-l %s", groupLabel), 300)
			ExpectWithOffset(1, err).Should(BeNil())
		}

		testConnectivitytoRedis := func() {
			webPods, err := kubectl.GetPodsNodes(helpers.DefaultNamespace, "-l k8s-app.guestbook=web")
			Expect(err).To(BeNil(), "Cannot get web pods")

			serviceIP, port, err := kubectl.GetServiceHostPort(helpers.DefaultNamespace, "redis-master")

			serviceName := "redis-master.default.svc.cluster.local"
			err = kubectl.WaitForKubeDNSEntry(serviceName)
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
				helpers.KubectlApply, 300)
			Expect(err).Should(BeNil(), "Cannot apply web-policy")

			policyCheck := fmt.Sprintf("cilium policy get %s=%s %s=%s",
				helpers.KubectlPolicyNameLabel, webPolicyName,
				helpers.KubectlPolicyNameSpaceLabel, helpers.DefaultNamespace)
			kubectl.CiliumExec(ciliumPod, policyCheck).ExpectSuccess(
				"Policy %q is not in cilium", webPolicyName)
			kubectl.CiliumExec(ciliumPod2, policyCheck).ExpectSuccess(
				"Policy %q is not in cilium", webPolicyName)

			By("Apply policy to Redis")
			_, err = kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, helpers.ManifestGet(redisPolicy),
				helpers.KubectlApply, 300)

			Expect(err).Should(BeNil(), "Cannot apply redis policy")

			policyCheck = fmt.Sprintf("%s=%s %s=%s",
				helpers.KubectlPolicyNameLabel, redisPolicyName,
				helpers.KubectlPolicyNameSpaceLabel, helpers.DefaultNamespace)
			Expect(kubectl.CiliumIsPolicyLoaded(ciliumPod, policyCheck)).To(BeTrue(),
				"Policy %q is not in cilium", redisPolicyName)
			Expect(kubectl.CiliumIsPolicyLoaded(ciliumPod2, policyCheck)).To(BeTrue(),
				"Policy %q is not in cilium", redisPolicyName)

			testConnectivitytoRedis()

			_, err = kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, helpers.ManifestGet(redisPolicy),
				helpers.KubectlDelete, 300)
			Expect(err).Should(BeNil(), "Cannot apply redis policy")

			By("Apply deprecated policy to Redis")

			_, err = kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, helpers.ManifestGet(redisPolicyDeprecated),
				helpers.KubectlApply, 300)
			Expect(err).Should(BeNil(), "Cannot apply redis deprecated policy err: %q", err)

			policyCheck = fmt.Sprintf("%s=%s %s=%s",
				helpers.KubectlPolicyNameLabel, redisPolicyDeprecatedName,
				helpers.KubectlPolicyNameSpaceLabel, helpers.DefaultNamespace)
			Expect(kubectl.CiliumIsPolicyLoaded(ciliumPod, policyCheck)).To(BeTrue(),
				"Policy %q is not in cilium", redisPolicyName)
			Expect(kubectl.CiliumIsPolicyLoaded(ciliumPod2, policyCheck)).To(BeTrue(),
				"Policy %q is not in cilium", redisPolicyName)

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
			l3L4Policy         = helpers.ManifestGet("l3_l4_policy.yaml")
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

			err := kubectl.WaitforPods(secondNS, "-l zgroup=testapp", 300)
			Expect(err).To(BeNil(),
				"testapp pods are not ready after timeout in namspace %q", secondNS)

			err = kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", 300)
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
			_ = kubectl.Delete(demoManifest)
			_ = kubectl.NamespaceDelete(secondNS)
		})

		It("Tests the same Policy in different namespaces", func() {
			// Tests that the same policy(name,labels) can enforce based on the
			// namespace and all works as expected.
			By("Applying Policy in %q namespace", secondNS)
			_, err = kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, l3l4PolicySecondNS, helpers.KubectlApply, 300)
			Expect(err).Should(BeNil(),
				"%q Policy cannot be applied in %q namespace", l3l4PolicySecondNS, secondNS)

			By("Applying Policy in default namespace")
			_, err = kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, l3L4Policy, helpers.KubectlApply, 300)
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
				helpers.KubeSystemNamespace, netpolNsSelector, helpers.KubectlApply, 300)
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
				helpers.KubeSystemNamespace, netpolNsSelector, helpers.KubectlDelete, 300)
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
	})
})

var _ = Describe("K8sValidatedPolicyTestAcrossNamespaces", func() {

	var (
		namespace        = "namespace"
		qaNs             = "qa"
		developmentNs    = "development"
		resources        = []string{"1-frontend.json", "2-backend-server.json", "3-backend.json"}
		kubectl          *helpers.Kubectl
		logger           *logrus.Entry
		cnpL7Stresstest  = helpers.ManifestGet("cnp-l7-stresstest.yaml")
		cnpAnyNamespace  = helpers.ManifestGet("cnp-any-namespace.yaml")
		microscopeErr    error
		microscopeCancel = func() error { return nil }
	)

	namespaceAction := func(ns string, action string) {
		switch action {
		case helpers.Create:
			kubectl.CreateResource(namespace, ns).ExpectSuccess(
				"cannot create namespace %s", ns)

		case helpers.Delete:
			kubectl.DeleteResource(namespace, ns).ExpectSuccess(
				"cannot delete namespace %s", ns)
		}
	}

	BeforeAll(func() {
		logger = log.WithFields(logrus.Fields{"testName": "K8sPolicyTestAcrossNamespaces"})
		logger.Info("Starting")
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		err := kubectl.CiliumInstall(helpers.CiliumDSPath)
		Expect(err).To(BeNil(), "Cilium cannot be installed")

		ExpectCiliumReady(kubectl)
		ExpectKubeDNSReady(kubectl)
	})

	BeforeEach(func() {
		namespaceAction(qaNs, helpers.Create)
		namespaceAction(developmentNs, helpers.Create)

		for _, resource := range resources {
			resourcePath := helpers.ManifestGet(resource)
			res := kubectl.Create(resourcePath)
			res.ExpectSuccess()
		}
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
		for _, resource := range resources {
			resourcePath := helpers.ManifestGet(resource)
			// Do not check result of deletion of resources because we do not
			// want to perform assertions in AfterEach.
			_ = kubectl.Delete(resourcePath)
		}

		_ = kubectl.Delete(cnpL7Stresstest)
		_ = kubectl.Delete(cnpAnyNamespace)

		namespaceAction(qaNs, helpers.Delete)
		namespaceAction(developmentNs, helpers.Delete)

		ExpectAllPodsTerminated(kubectl)
	})

	checkCiliumPoliciesDeleted := func(ciliumPod, policyCmd string) {
		By("Checking that all policies were deleted in Cilium pod %q", ciliumPod)
		ExpectWithOffset(1, kubectl.CiliumIsPolicyLoaded(ciliumPod, policyCmd)).To(BeFalse(),
			"policies should be deleted from Cilium: policies found: %s", policyCmd)
	}

	It("Policies Across Namespaces", func() {
		podNameFilter := "{.items[*].metadata.name}"

		policyDeleteAndCheck := func(ciliumPods []string, policyPath, policyCmd string) {
			_, err := kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, policyPath,
				helpers.KubectlDelete, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Error deleting resource %s", policyPath)

			for _, pod := range ciliumPods {
				checkCiliumPoliciesDeleted(pod, policyCmd)
			}
		}

		testConnectivity := func(frontendPod, backendIP string) {
			By("Testing connectivity from %q to %q", frontendPod, backendIP)

			kubectl.Exec("netstat -ltn") // To keep the info in the log

			By("running curl '%s:80' from pod %q (should work)", backendIP, frontendPod)

			res := kubectl.ExecPodCmd(
				qaNs, frontendPod, helpers.CurlFail("http://%s:80", backendIP))
			res.ExpectSuccess("Unable to connect between front and backend:80/")

			By("running curl '%s:80/health' from pod %s (shouldn't work)", backendIP, frontendPod)

			res = kubectl.ExecPodCmd(
				qaNs, frontendPod, helpers.CurlWithHTTPCode("http://%s:80/health", backendIP))
			res.ExpectContains("403", "Unexpected response code,wanted HTTP 403")
		}

		ciliumPods, err := kubectl.GetCiliumPods(helpers.KubeSystemNamespace)
		Expect(err).To(BeNil(), "cannot get cilium pods")

		By("Waiting for endpoints to be ready on cilium")

		err = kubectl.CiliumEndpointWaitReady()
		Expect(err).To(BeNil(), "Endpoints are not ready after timeout")

		err = kubectl.WaitForServiceEndpoints(
			developmentNs, "", "backend", "80", helpers.HelperTimeout)
		Expect(err).Should(BeNil())

		frontendPod, err := kubectl.GetPods(qaNs, "-l id=client").Filter(podNameFilter)
		Expect(err).Should(BeNil())

		backendSvcIP, _, err := kubectl.GetServiceHostPort(developmentNs, "backend")
		Expect(err).Should(BeNil(), "Backend service cannot be retrieved")

		By("Running tests WITHOUT Policy / Proxy loaded")

		By("running curl '%s:80' from pod %q (should work)", backendSvcIP, frontendPod)
		res := kubectl.ExecPodCmd(
			qaNs, frontendPod.String(),
			helpers.CurlFail("http://%s:80/", backendSvcIP))
		res.ExpectSuccess("Unable to connect between %s and %s:80/", frontendPod, backendSvcIP)

		By("Loading L7 Policies into Cilium", func() {
			policyCmd := "cilium policy get io.cilium.k8s.policy.name=l7-stresstest"

			_, err = kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, cnpL7Stresstest,
				helpers.KubectlCreate, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Error creating resource %s", cnpL7Stresstest)

			By("Running tests WITH Policy / Proxy loaded")
			testConnectivity(frontendPod.String(), backendSvcIP)
			policyDeleteAndCheck(ciliumPods, cnpL7Stresstest, policyCmd)
		})
		By("Testing Cilium NetworkPolicy enforcement from any namespace", func() {
			policyCmd := "cilium policy get io.cilium.k8s.policy.name=l7-stresstest"

			_, err = kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, cnpAnyNamespace,
				helpers.KubectlCreate, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Error creating resource %s", cnpAnyNamespace)

			By("Running tests WITH Policy / Proxy loaded")
			testConnectivity(frontendPod.String(), backendSvcIP)
			policyDeleteAndCheck(ciliumPods, cnpAnyNamespace, policyCmd)
		})
	}, 300)

})
