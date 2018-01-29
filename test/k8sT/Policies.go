// Copyright 2017 Authors of Cilium
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
	"sync"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/test/helpers"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("K8sPolicyTest", func() {

	var demoPath string
	var once sync.Once
	var kubectl *helpers.Kubectl
	var l3Policy, l7Policy string
	var logger *logrus.Entry
	var path string
	var podFilter string

	initialize := func() {
		logger = log.WithFields(logrus.Fields{"testName": "K8sPolicyTest"})
		logger.Info("Starting")
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		podFilter = "k8s:zgroup=testapp"

		//Manifest paths
		demoPath = kubectl.ManifestGet("demo.yaml")
		l3Policy = kubectl.ManifestGet("l3_l4_policy.yaml")
		l7Policy = kubectl.ManifestGet("l7_policy.yaml")

		path = kubectl.ManifestGet("cilium_ds.yaml")
		kubectl.Apply(path)
		status, err := kubectl.WaitforPods(helpers.KubeSystemNamespace, "-l k8s-app=cilium", 300)
		Expect(status).Should(BeTrue())
		Expect(err).Should(BeNil())
		err = kubectl.WaitKubeDNS()
		Expect(err).Should(BeNil())
	}

	BeforeEach(func() {
		once.Do(initialize)
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			ciliumPod, _ := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s1)
			kubectl.CiliumReport(helpers.KubeSystemNamespace, ciliumPod, []string{
				"cilium bpf tunnel list",
				"cilium endpoint list"})
		}
	})

	waitUntilEndpointUpdates := func(pod string, eps map[string]int64, min int) error {
		body := func() bool {
			updated := 0
			newEps := kubectl.CiliumEndpointPolicyVersion(pod)
			for k, v := range newEps {
				if eps[k] < v {
					logger.Infof("Endpoint %s had version %d now %d", k, eps[k], v)
					updated++
				}
			}
			return updated >= min
		}
		err := helpers.WithTimeout(body, "No new version applied",
			&helpers.TimeoutConfig{Timeout: 100})
		return err
	}

	Context("Basic Test", func() {

		BeforeEach(func() {
			kubectl.Apply(demoPath)
			_, err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", 300)
			Expect(err).Should(BeNil())
		})

		AfterEach(func() {
			kubectl.Delete(demoPath)
			// TO make sure that are not in place
			kubectl.Delete(l3Policy)
			kubectl.Delete(l7Policy)
		})

		getAppPods := func(namespace string) map[string]string {
			appPods := make(map[string]string)
			apps := []string{helpers.App1, helpers.App2, helpers.App3}
			for _, v := range apps {
				res, err := kubectl.GetPodNames(namespace, fmt.Sprintf("id=%s", v))
				Expect(err).Should(BeNil())
				appPods[v] = res[0]
				logger.Infof("PolicyRulesTest: pod=%q assigned to %q", res[0], v)
			}
			return appPods
		}

		It("PolicyEnforcement Changes", func() {
			// This is a small test that checks that basic policy enforcement
			// changes are working in k8s. All the policy enforcement
			// changes/combinations are tested in runtime/Policies.go
			ciliumPod, err := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s1)
			Expect(err).Should(BeNil())

			status := kubectl.CiliumExec(
				ciliumPod, fmt.Sprintf("cilium config %s=%s",
					helpers.PolicyEnforcement, helpers.PolicyEnforcementDefault))
			status.ExpectSuccess()
			helpers.Sleep(5)
			kubectl.CiliumEndpointWait(ciliumPod)

			epsStatus := helpers.WithTimeout(func() bool {
				endpoints, err := kubectl.CiliumEndpointsListByLabel(ciliumPod, podFilter)
				if err != nil {
					return false
				}
				return endpoints.AreReady()
			}, "Could not get endpoints", &helpers.TimeoutConfig{Timeout: 100})
			Expect(epsStatus).Should(BeNil())

			endpoints, err := kubectl.CiliumEndpointsListByLabel(ciliumPod, podFilter)
			Expect(err).Should(BeNil())
			Expect(endpoints.AreReady()).Should(BeTrue())
			policyStatus := endpoints.GetPolicyStatus()
			// default mode with no policy, all endpoints must be in allow all
			Expect(policyStatus[models.EndpointPolicyEnabledNone]).Should(Equal(4))
			Expect(policyStatus[models.EndpointPolicyEnabledIngress]).Should(Equal(0))
			Expect(policyStatus[models.EndpointPolicyEnabledEgress]).Should(Equal(0))
			Expect(policyStatus[models.EndpointPolicyEnabledBoth]).Should(Equal(0))

			By("Set PolicyEnforcement to always")

			status = kubectl.CiliumExec(
				ciliumPod, fmt.Sprintf("cilium config %s=%s",
					helpers.PolicyEnforcement, helpers.PolicyEnforcementAlways))
			status.ExpectSuccess()

			kubectl.CiliumEndpointWait(ciliumPod)

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

			kubectl.CiliumEndpointWait(ciliumPod)

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

		It("Policies", func() {
			appPods := getAppPods(helpers.DefaultNamespace)
			service := "app1-service"
			clusterIP, _, err := kubectl.GetServiceHostPort(helpers.DefaultNamespace, service)
			logger.Infof("PolicyRulesTest: cluster service ip '%s'", clusterIP)
			Expect(err).Should(BeNil(), "Cannot get service %q", service)

			ciliumPod, err := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s1)
			Expect(err).Should(BeNil())

			status := kubectl.CiliumExec(
				ciliumPod, fmt.Sprintf("cilium config %s=%s",
					helpers.PolicyEnforcement, helpers.PolicyEnforcementDefault))
			status.ExpectSuccess()

			kubectl.CiliumEndpointWait(ciliumPod)

			By("Testing L3/L4 rules")

			eps := kubectl.CiliumEndpointPolicyVersion(ciliumPod)
			_, err = kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, l3Policy, helpers.KubectlApply, 300)
			Expect(err).Should(BeNil())

			err = waitUntilEndpointUpdates(ciliumPod, eps, 4)
			Expect(err).Should(BeNil())
			epsStatus := helpers.WithTimeout(func() bool {
				endpoints, err := kubectl.CiliumEndpointsListByLabel(ciliumPod, podFilter)
				if err != nil {
					return false
				}
				return endpoints.AreReady()
			}, "could not get endpoints", &helpers.TimeoutConfig{Timeout: 100})

			Expect(epsStatus).Should(BeNil())
			appPods = getAppPods(helpers.DefaultNamespace)

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
			Expect(trace.Output().String()).Should(ContainSubstring("Final verdict: ALLOWED"))

			trace = kubectl.CiliumExec(ciliumPod, fmt.Sprintf(
				"cilium policy trace --src-k8s-pod default:%s --dst-k8s-pod default:%s",
				appPods[helpers.App3], appPods[helpers.App1]))
			trace.ExpectSuccess(trace.CombineOutput().String())
			Expect(trace.Output().String()).Should(ContainSubstring("Final verdict: DENIED"))

			_, err = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				fmt.Sprintf("curl http://%s/public", clusterIP))
			Expect(err).Should(BeNil())

			_, err = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			Expect(err).Should(HaveOccurred())

			eps = kubectl.CiliumEndpointPolicyVersion(ciliumPod)
			status = kubectl.Delete(l3Policy)
			status.ExpectSuccess()
			kubectl.CiliumEndpointWait(ciliumPod)

			//Only 1 endpoint is affected by L7 rule
			err = waitUntilEndpointUpdates(ciliumPod, eps, 4)
			Expect(err).Should(BeNil())

			By("Testing L7 Policy")
			//All Monkey testing in this section is on runtime

			eps = kubectl.CiliumEndpointPolicyVersion(ciliumPod)
			_, err = kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, l7Policy, helpers.KubectlApply, 300)
			Expect(err).Should(BeNil())
			err = waitUntilEndpointUpdates(ciliumPod, eps, 4)
			Expect(err).Should(BeNil())

			appPods = getAppPods(helpers.DefaultNamespace)

			_, err = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				fmt.Sprintf("curl http://%s/public", clusterIP))
			Expect(err).Should(BeNil())

			msg, err := kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				fmt.Sprintf("curl --fail -s http://%s/private", clusterIP))
			Expect(err).Should(HaveOccurred(), msg)

			_, err = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App3],
				fmt.Sprintf("curl --fail -s http://%s/public", clusterIP))
			Expect(err).Should(HaveOccurred())

			msg, err = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App3],
				fmt.Sprintf("curl --fail -s http://%s/private", clusterIP))
			Expect(err).Should(HaveOccurred(), msg)

			eps = kubectl.CiliumEndpointPolicyVersion(ciliumPod)
			status = kubectl.Delete(l7Policy)
			status.ExpectSuccess()

			//Only 1 endpoint is affected by L7 rule
			err = waitUntilEndpointUpdates(ciliumPod, eps, 4)
			Expect(err).Should(BeNil())

			_, err = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App3],
				fmt.Sprintf("curl --fail -s http://%s/public", clusterIP))
			Expect(err).Should(BeNil())
		}, 500)

		It("Same Policy in the different namespaces", func() {
			namespace := "second"
			policy := fmt.Sprintf("%s -n %s", l3Policy, namespace)
			demoManifest := fmt.Sprintf("%s -n %s", demoPath, namespace)
			kubectl.NamespaceCreate(namespace)
			kubectl.Apply(demoManifest)
			defer func() {
				kubectl.Delete(demoManifest).ExpectSuccess()
				kubectl.Delete(policy).ExpectSuccess()
				kubectl.NamespaceDelete(namespace).ExpectSuccess()

			}()

			pods, err := kubectl.WaitforPods(
				namespace,
				"-l zgroup=testapp", 300)
			Expect(pods).To(BeTrue(), "testapp pods are not ready after timeout")
			Expect(err).To(BeNil(), "testapp pods are not ready after timeout")

			ciliumPod, err := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s1)
			Expect(err).Should(BeNil())

			By("Applying Policy in namespace")
			eps := kubectl.CiliumEndpointPolicyVersion(ciliumPod)
			_, err = kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, policy, helpers.KubectlApply, 300)
			Expect(err).Should(BeNil(), "L3 Policy cannot be applied in %q namespace", namespace)

			err = waitUntilEndpointUpdates(ciliumPod, eps, 4)
			Expect(err).Should(BeNil())

			By("Applying Policy in default namespace")
			eps = kubectl.CiliumEndpointPolicyVersion(ciliumPod)
			_, err = kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, l3Policy, helpers.KubectlApply, 300)
			Expect(err).Should(BeNil(), "L3 Policy cannot be applied in %q namespace", helpers.DefaultNamespace)
			err = waitUntilEndpointUpdates(ciliumPod, eps, 4)
			Expect(err).Should(BeNil(), "Endpoints timeout on namespaces %q", helpers.DefaultNamespace)

			By(fmt.Sprintf("Testing %s namespace", namespace))
			clusterIP, _, err := kubectl.GetServiceHostPort(namespace, "app1-service")
			Expect(err).To(BeNil(), "Cannot get service on %q namespace", namespace)
			appPods := getAppPods(namespace)
			_, err = kubectl.ExecPodCmd(
				namespace, appPods[helpers.App2],
				fmt.Sprintf("curl http://%s/public", clusterIP))
			Expect(err).Should(BeNil())

			_, err = kubectl.ExecPodCmd(
				namespace, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			Expect(err).Should(HaveOccurred())

			By("Testing default namespace")
			clusterIP, _, err = kubectl.GetServiceHostPort(helpers.DefaultNamespace, "app1-service")
			Expect(err).To(BeNil(), "Cannot get service on default namespace")

			appPods = getAppPods(helpers.DefaultNamespace)
			_, err = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				fmt.Sprintf("curl http://%s/public", clusterIP))
			Expect(err).Should(BeNil())

			_, err = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			Expect(err).Should(HaveOccurred())
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
			kubectl.Apply(kubectl.ManifestGet(deployment))

			ciliumPod, err = kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s1)
			Expect(err).Should(BeNil())

			ciliumPod2, err = kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s2)
			Expect(err).Should(BeNil())
		})

		AfterEach(func() {
			kubectl.Delete(kubectl.ManifestGet(deployment)).ExpectSuccess(
				"Guestbook deployment cannot be deleted")
			kubectl.Delete(kubectl.ManifestGet(webPolicy)).ExpectSuccess(
				"Web policy cannot be deleted")
			kubectl.Delete(kubectl.ManifestGet(redisPolicyDeprecated)).ExpectSuccess(
				"Redis deprecated policy cannot be deleted")

			// This policy shouldn't be there, but test can fail before delete
			// the policy and we want to make sure that it's deleted
			kubectl.Delete(kubectl.ManifestGet(redisPolicy))
		})

		waitforPods := func() {
			pods, err := kubectl.WaitforPods(
				helpers.DefaultNamespace,
				fmt.Sprintf("-l %s", groupLabel), 300)
			ExpectWithOffset(1, pods).Should(BeTrue())
			ExpectWithOffset(1, err).Should(BeNil())
		}

		testConnectivitytoRedis := func() {
			webPods, err := kubectl.GetPodsNodes(helpers.DefaultNamespace, "-l k8s-app.guestbook=web")
			Expect(err).To(BeNil(), "Cannot get web pods")

			for pod := range webPods {
				command := `nc redis-master 6379 <<EOF
							PING
							EOF`
				_, err := kubectl.ExecPodCmd(helpers.DefaultNamespace, pod, command)
				ExpectWithOffset(1, err).To(BeNil(), "Web pod %q cannot connect to redis", pod)
			}
		}
		It("checks policy example", func() {
			waitforPods()

			By("Apply policy to web")
			eps := kubectl.CiliumEndpointPolicyVersion(ciliumPod)
			_, err := kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, kubectl.ManifestGet(webPolicy),
				helpers.KubectlApply, 300)
			Expect(err).Should(BeNil(), "Cannot apply web-policy")

			err = waitUntilEndpointUpdates(ciliumPod, eps, 3)
			Expect(err).To(BeNil(), "Pods are not ready after timeout")

			policyCheck := fmt.Sprintf("cilium policy get %s=%s %s=%s",
				helpers.KubectlPolicyNameLabel, webPolicyName,
				helpers.KubectlPolicyNameSpaceLabel, helpers.DefaultNamespace)
			kubectl.CiliumExec(ciliumPod, policyCheck).ExpectSuccess(
				"Policy %q is not in cilium", webPolicyName)
			kubectl.CiliumExec(ciliumPod2, policyCheck).ExpectSuccess(
				"Policy %q is not in cilium", webPolicyName)

			By("Apply policy to Redis")
			eps = kubectl.CiliumEndpointPolicyVersion(ciliumPod)
			_, err = kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, kubectl.ManifestGet(redisPolicy),
				helpers.KubectlApply, 300)

			Expect(err).Should(BeNil(), "Cannot apply redis policy")

			err = waitUntilEndpointUpdates(ciliumPod, eps, 1)
			Expect(err).To(BeNil(), "Pods are not ready after timeout")

			policyCheck = fmt.Sprintf("cilium policy get %s=%s %s=%s",
				helpers.KubectlPolicyNameLabel, redisPolicyName,
				helpers.KubectlPolicyNameSpaceLabel, helpers.DefaultNamespace)

			kubectl.CiliumExec(ciliumPod, policyCheck).ExpectSuccess(
				"Policy %q is not in cilium", redisPolicyName)
			kubectl.CiliumExec(ciliumPod2, policyCheck).ExpectSuccess(
				"Policy %q is not in cilium", redisPolicyName)

			testConnectivitytoRedis()

			kubectl.Delete(kubectl.ManifestGet(redisPolicy)).ExpectSuccess(
				"Cannot delete the redis policy")

			By("Apply deprecated policy to Redis")

			eps = kubectl.CiliumEndpointPolicyVersion(ciliumPod)
			_, err = kubectl.CiliumPolicyAction(
				helpers.KubeSystemNamespace, kubectl.ManifestGet(redisPolicyDeprecated),
				helpers.KubectlApply, 300)
			Expect(err).Should(BeNil(), "Cannot apply redis deprecated policy err: %q", err)

			err = waitUntilEndpointUpdates(ciliumPod, eps, 1)
			Expect(err).To(BeNil(), "Pods are not ready after timeout")

			policyCheck = fmt.Sprintf("cilium policy get %s=%s %s=%s",
				helpers.KubectlPolicyNameLabel, redisPolicyDeprecatedName,
				helpers.KubectlPolicyNameSpaceLabel, helpers.DefaultNamespace)
			kubectl.CiliumExec(ciliumPod, policyCheck).ExpectSuccess(
				"Policy %q is not in cilium", redisPolicyName)
			kubectl.CiliumExec(ciliumPod2, policyCheck).ExpectSuccess(
				"Policy %q is not in cilium", redisPolicyName)

			testConnectivitytoRedis()
		})
	})
})

var _ = Describe("K8sValidatedPolicyTestAcrossNamespaces", func() {

	var kubectl *helpers.Kubectl
	var logger *logrus.Entry
	var once sync.Once
	var path string

	initialize := func() {
		logger = log.WithFields(logrus.Fields{"testName": "K8sPolicyTestAcrossNamespaces"})
		logger.Info("Starting")
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		path = kubectl.ManifestGet("cilium_ds.yaml")
		kubectl.Apply(path)
		status, err := kubectl.WaitforPods(helpers.KubeSystemNamespace, "-l k8s-app=cilium", 300)
		Expect(status).Should(BeTrue())
		Expect(err).Should(BeNil())

		err = kubectl.WaitKubeDNS()
		Expect(err).Should(BeNil())
	}

	BeforeEach(func() {
		once.Do(initialize)
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			ciliumPod, _ := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s1)
			kubectl.CiliumReport(helpers.KubeSystemNamespace, ciliumPod, []string{
				"cilium bpf tunnel list",
				"cilium endpoint list"})
		}
	})
	It("Policies Across Namespaces", func() {

		namespace := "namespace"
		qaNs := "qa"
		developmentNs := "development"
		podNameFilter := "{.items[*].metadata.name}"

		checkCiliumPoliciesDeleted := func(ciliumPod, policyCmd string) {
			By(fmt.Sprintf("Checking that all policies were deleted in Cilium pod %s", ciliumPod))
			output, err := kubectl.ExecPodCmd(helpers.KubeSystemNamespace, ciliumPod, policyCmd)
			Expect(err).Should(Not(BeNil()), "policies should be deleted from Cilium: policies found: %s", output)
		}

		// formatLabelArgument formats the provided key-value pairs as labels for use in
		// querying Kubernetes.
		formatLabelArgument := func(firstKey, firstValue string, nextLabels ...string) string {
			baseString := fmt.Sprintf("-l %s=%s", firstKey, firstValue)
			if nextLabels == nil {
				return baseString
			} else if len(nextLabels)%2 != 0 {
				panic("must provide even number of arguments for label key-value pairings")
			} else {
				for i := 0; i < len(nextLabels); i += 2 {
					baseString = fmt.Sprintf("%s,%s=%s", baseString, nextLabels[i], nextLabels[i+1])
				}
			}
			return baseString
		}

		logInfo := func(cmd string) {
			res := kubectl.Exec(cmd)
			log.Infof("%s", res.GetStdOut())
		}

		policyDeleteAndCheck := func(ciliumPods []string, policyPath, policyCmd string) {
			_, err := kubectl.CiliumPolicyAction(helpers.KubeSystemNamespace, policyPath, helpers.KubectlDelete, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), fmt.Sprintf("Error deleting resource %s: %s", policyPath, err))

			for _, pod := range ciliumPods {
				checkCiliumPoliciesDeleted(pod, policyCmd)
			}
		}

		testConnectivity := func(frontendPod, backendIP string) {
			By(fmt.Sprintf("Testing connectivity from %s to %s", frontendPod, backendIP))
			By("netstat output")

			res := kubectl.Exec("netstat -ltn")
			By(fmt.Sprintf("%s", res.GetStdOut()))

			By(fmt.Sprintf("running curl %s:80 from pod %s (should work)", backendIP, frontendPod))
			returnCode := kubectl.Exec(fmt.Sprintf("kubectl exec -n qa -i %s -- curl -s -o /dev/null -w \"%%{http_code}\" http://%s:80/", frontendPod, backendIP)).GetStdOut()

			Expect(returnCode).Should(Equal("200"), "Unable to connect between front and backend:80/")

			By(fmt.Sprintf("running curl %s:80/health from pod %s (shouldn't work)", backendIP, frontendPod))

			returnCode = kubectl.Exec(fmt.Sprintf("kubectl exec -n qa -i %s -- curl --connect-timeout 20 -s -o /dev/null -w \"%%{http_code}\" http://%s:80/health", frontendPod, backendIP)).GetStdOut()

			Expect(returnCode).Should(Equal("403"), fmt.Sprintf("Unexpected connection between frontend and backend; wanted HTTP 403, got: HTTP %s", returnCode))
		}

		ciliumPodK8s1, err := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s1)
		Expect(err).Should(BeNil())

		ciliumPodK8s2, err := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s2)
		Expect(err).Should(BeNil())

		ciliumPods := []string{ciliumPodK8s1, ciliumPodK8s2}

		// Set debug mode to false for both cilium pods.
		for _, ciliumPod := range ciliumPods {
			out, err := kubectl.ExecPodCmd(helpers.KubeSystemNamespace, ciliumPod, "cilium config Debug=false")
			Expect(err).Should(BeNil(), fmt.Sprintf("error disabling debug mode for cilium pod %s: %s", ciliumPod, out))
		}

		By("Creating Kubernetes namespace qa")
		res := kubectl.CreateResource(namespace, qaNs)
		defer func() {
			kubectl.NamespaceDelete(qaNs).ExpectSuccess()
		}()
		res.ExpectSuccess()

		By("Creating Kubernetes namespace development")

		res = kubectl.NamespaceCreate(developmentNs)
		defer func() {
			kubectl.NamespaceDelete(developmentNs).ExpectSuccess()
		}()
		res.ExpectSuccess()

		resources := []string{"1-frontend.json", "2-backend-server.json", "3-backend.json"}
		for _, resource := range resources {
			resourcePath := kubectl.ManifestGet(resource)
			res = kubectl.Create(resourcePath)
			defer kubectl.Delete(resourcePath)
			res.ExpectSuccess()
		}

		By("Waiting for endpoints to be ready on k8s-2 node")
		areEndpointsReady := kubectl.CiliumEndpointWait(ciliumPodK8s2)
		Expect(areEndpointsReady).Should(BeTrue())

		pods, err := kubectl.WaitForServiceEndpoints(developmentNs, "", "backend", "80", helpers.HelperTimeout)
		Expect(err).Should(BeNil())
		Expect(pods).Should(BeTrue())

		By("Getting K8s services")
		logInfo("kubectl get svc --all-namespaces")

		By("Getting information about pods in qa namespace")
		logInfo("kubectl get pods -n qa -o wide")

		By("Getting information about pods in development namespace")
		logInfo("kubectl get pods -n development -o wide")

		By("Getting information about backend service in development namespace")
		logInfo("kubectl describe svc -n development backend")

		frontendPod, err := kubectl.GetPods(qaNs, formatLabelArgument("id", "client")).Filter(podNameFilter)
		Expect(err).Should(BeNil())

		By(fmt.Sprintf("%s", frontendPod))

		backendPod, err := kubectl.GetPods(developmentNs, formatLabelArgument("id", "server")).Filter(podNameFilter)
		Expect(err).Should(BeNil())

		By(fmt.Sprintf("%s", backendPod))

		backendSvcIP, err := kubectl.Exec("kubectl get svc -n development -o json").Filter("{.items[*].spec.clusterIP}")
		Expect(err).Should(BeNil())

		By(fmt.Sprintf("Backend Service IP: %s", backendSvcIP.String()))

		By("Running tests WITHOUT Policy / Proxy loaded")

		By(fmt.Sprintf("running curl %s:80 from pod %s (should work)", backendSvcIP, frontendPod))
		returnCode := kubectl.Exec(fmt.Sprintf("kubectl exec -n qa -i %s -- curl -s -o /dev/null -w \"%%{http_code}\" http://%s:80/", frontendPod, backendSvcIP)).GetStdOut()

		Expect(returnCode).Should(Equal("200"), "Unable to connect between %s and %s:80/", frontendPod, backendSvcIP)

		basicConnectivity := func() {
			By("Loading Policies into Cilium")
			policyPath := kubectl.ManifestGet("cnp-l7-stresstest.yaml")
			policyCmd := "cilium policy get io.cilium.k8s-policy-name=l7-stresstest"

			_, err = kubectl.CiliumPolicyAction(helpers.KubeSystemNamespace, policyPath, helpers.KubectlCreate, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), fmt.Sprintf("Error creating resource %s: %s", policyPath, err))

			defer policyDeleteAndCheck(ciliumPods, policyPath, policyCmd)

			output, err := kubectl.ExecPodCmd(helpers.KubeSystemNamespace, ciliumPodK8s1, "cilium policy get")
			Expect(err).Should(BeNil(), fmt.Sprintf("output of \"cilium policy get\": %s", output))

			By("Running tests WITH Policy / Proxy loaded")
			testConnectivity(frontendPod.String(), backendSvcIP.String())
		}

		basicConnectivity()

		crossNamespaceTest := func() {
			By("Testing Cilium NetworkPolicy enforcement from any namespace")

			policyPath := kubectl.ManifestGet("cnp-any-namespace.yaml")
			policyCmd := "cilium policy get io.cilium.k8s-policy-name=l7-stresstest"

			_, err = kubectl.CiliumPolicyAction(helpers.KubeSystemNamespace, policyPath, helpers.KubectlCreate, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), fmt.Sprintf("Error creating resource %s: %s", policyPath, err))

			defer policyDeleteAndCheck(ciliumPods, policyPath, policyCmd)

			output, err := kubectl.ExecPodCmd(helpers.KubeSystemNamespace, ciliumPodK8s1, "cilium policy get")
			Expect(err).Should(BeNil(), fmt.Sprintf("output of \"cilium policy get\": %s", output))

			By("Running tests WITH Policy / Proxy loaded")

			testConnectivity(frontendPod.String(), backendSvcIP.String())

		}

		crossNamespaceTest()

	}, 300)

})
