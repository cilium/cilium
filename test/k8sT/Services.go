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
	"net"
	"time"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	"github.com/asaskevich/govalidator"
	. "github.com/onsi/gomega"
	"k8s.io/api/core/v1"
)

var _ = Describe("K8sServicesTest", func() {
	var (
		kubectl          *helpers.Kubectl
		serviceName      = "app1-service"
		microscopeErr    error
		microscopeCancel                    = func() error { return nil }
		backgroundCancel context.CancelFunc = func() { return }
		backgroundError  error
		ciliumPodK8s1    string
		testDSClient     = "zgroup=testDSClient"
		testDS           = "zgroup=testDS"
	)

	applyPolicy := func(path string) {
		By(fmt.Sprintf("Applying policy %s", path))
		_, err := kubectl.CiliumPolicyAction(helpers.KubeSystemNamespace, path, helpers.KubectlApply, helpers.HelperTimeout)
		ExpectWithOffset(1, err).Should(BeNil(), fmt.Sprintf("Error creating resource %s: %s", path, err))
	}

	BeforeAll(func() {
		var err error

		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		ProvisionInfraPods(kubectl)

		ciliumPodK8s1, err = kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s1)
		Expect(err).Should(BeNil(), "Cannot get cilium pod on k8s1")
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.KubeSystemNamespace,
			"cilium service list",
			"cilium endpoint list")
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

	AfterEach(func() {
		ExpectAllPodsTerminated(kubectl)
	})

	testHTTPRequest := func(url string) {
		pods, err := kubectl.GetPodNames(helpers.DefaultNamespace, testDSClient)
		ExpectWithOffset(1, err).Should(BeNil(), "cannot retrieve pod names by filter %q", testDSClient)
		// A DS with client is running in each node. So we try from each node
		// that can connect to the service.  To make sure that the cross-node
		// service connectivity is correct we tried 10 times, so balance in the
		// two nodes
		for _, pod := range pods {
			By("Making ten HTTP requests from %q to %q", pod, url)
			for i := 1; i <= 10; i++ {
				res := kubectl.ExecPodCmd(
					helpers.DefaultNamespace, pod,
					helpers.CurlFail(url))
				ExpectWithOffset(1, res).Should(helpers.CMDSuccess(),
					"Pod %q can not connect to service %q", pod, url)
			}
		}
	}

	waitPodsDs := func() {
		groups := []string{testDS, testDSClient}
		for _, pod := range groups {
			err := kubectl.WaitforPods(helpers.DefaultNamespace, fmt.Sprintf("-l %s", pod), helpers.HelperTimeout)
			ExpectWithOffset(1, err).Should(BeNil())
		}
	}

	Context("Checks ClusterIP Connectivity", func() {

		var (
			demoYAML = helpers.ManifestGet("demo.yaml")
		)

		BeforeEach(func() {
			res := kubectl.Apply(demoYAML)
			res.ExpectSuccess("unable to apply %s", demoYAML)
		})

		AfterEach(func() {
			// Explicitly ignore result of deletion of resources to avoid incomplete
			// teardown if any step fails.
			_ = kubectl.Delete(demoYAML)
		})

		It("Checks service on same node", func() {
			err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", helpers.HelperTimeout)
			Expect(err).Should(BeNil())
			clusterIP, _, err := kubectl.GetServiceHostPort(helpers.DefaultNamespace, serviceName)
			Expect(err).Should(BeNil(), "Cannot get service %s", serviceName)
			Expect(govalidator.IsIP(clusterIP)).Should(BeTrue(), "ClusterIP is not an IP")

			By("testing connectivity via cluster IP %s", clusterIP)
			status := kubectl.Exec(helpers.CurlFail("http://%s/", clusterIP))
			status.ExpectSuccess("cannot curl to service IP from host")
			ciliumPods, err := kubectl.GetCiliumPods(helpers.KubeSystemNamespace)
			Expect(err).To(BeNil(), "Cannot get cilium pods")
			for _, pod := range ciliumPods {
				service := kubectl.CiliumExec(pod, "cilium service list")
				service.ExpectSuccess("Cannot retrieve services on cilium Pod")
				service.ExpectContains(clusterIP, "ClusterIP is not present in the cilium service list")
			}
		}, 300)
	})

	Context("Checks service across nodes", func() {

		var (
			demoYAML = helpers.ManifestGet("demo_ds.yaml")
		)

		BeforeAll(func() {
			res := kubectl.Apply(demoYAML)
			res.ExpectSuccess("Unable to apply %s", demoYAML)
		})

		AfterAll(func() {
			// Explicitly ignore result of deletion of resources to avoid incomplete
			// teardown if any step fails.
			_ = kubectl.Delete(demoYAML)
		})

		It("Checks ClusterIP Connectivity", func() {
			waitPodsDs()
			service := "testds-service"

			clusterIP, _, err := kubectl.GetServiceHostPort(helpers.DefaultNamespace, service)
			Expect(err).Should(BeNil(), "Cannot get service %s", service)
			Expect(govalidator.IsIP(clusterIP)).Should(BeTrue(), "ClusterIP is not an IP")

			url := fmt.Sprintf("http://%s/", clusterIP)
			testHTTPRequest(url)
		})

		testNodePort := func() {
			waitPodsDs()

			var data v1.Service
			err := kubectl.Get("default", "service test-nodeport").Unmarshal(&data)
			Expect(err).Should(BeNil(), "Can not retrieve service")
			url := fmt.Sprintf("http://%s",
				net.JoinHostPort(data.Spec.ClusterIP, fmt.Sprintf("%d", data.Spec.Ports[0].Port)))
			testHTTPRequest(url)

			// From host via localhost IP
			// TODO: IPv6
			url = fmt.Sprintf("http://%s",
				net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", data.Spec.Ports[0].NodePort)))
			By("Making ten HTTP requests from k8s1 to %q", url)
			for i := 1; i <= 10; i++ {
				res := kubectl.Exec(helpers.CurlFail(url))
				ExpectWithOffset(1, res).Should(helpers.CMDSuccess(),
					"k8s1 host can not connect to service %q", url)
			}

			// From pod via node IPs
			url = fmt.Sprintf("http://%s",
				net.JoinHostPort(helpers.K8s1Ip, fmt.Sprintf("%d", data.Spec.Ports[0].NodePort)))
			testHTTPRequest(url)
			url = fmt.Sprintf("http://%s",
				net.JoinHostPort(helpers.K8s2Ip, fmt.Sprintf("%d", data.Spec.Ports[0].NodePort)))
			testHTTPRequest(url)
		}

		It("Tests NodePort", func() {
			testNodePort()
		})

		Context("with L7 policy", func() {
			var (
				demoPolicy = helpers.ManifestGet("l7-policy-demo.yaml")
			)

			AfterAll(func() {
				// Explicitly ignore result of deletion of resources to avoid incomplete
				// teardown if any step fails.
				_ = kubectl.Delete(demoPolicy)
			})

			It("Tests NodePort with L7 Policy", func() {
				applyPolicy(demoPolicy)
				testNodePort()
			})
		})
	})

	//TODO: Check service with IPV6

	Context("External services", func() {

		var (
			expectedCIDR = "198.49.23.144/32"
			podName      = "toservices"

			endpointPath      = helpers.ManifestGet("external_endpoint.yaml")
			podPath           = helpers.ManifestGet("external_pod.yaml")
			policyPath        = helpers.ManifestGet("external-policy.yaml")
			policyLabeledPath = helpers.ManifestGet("external-policy-labeled.yaml")
			servicePath       = helpers.ManifestGet("external_service.yaml")
		)

		BeforeAll(func() {
			kubectl.Apply(servicePath).ExpectSuccess("cannot install external service")
			kubectl.Apply(podPath).ExpectSuccess("cannot install pod path")

			err := kubectl.WaitforPods(helpers.DefaultNamespace, "", helpers.HelperTimeout)
			Expect(err).To(BeNil(), "Pods are not ready after timeout")
		})

		AfterAll(func() {
			_ = kubectl.Delete(servicePath)
			_ = kubectl.Delete(podPath)

			ExpectAllPodsTerminated(kubectl)
		})

		AfterEach(func() {
			_ = kubectl.Delete(policyLabeledPath)
			_ = kubectl.Delete(policyPath)
			_ = kubectl.Delete(endpointPath)
		})

		validateEgress := func() {
			By("Checking that toServices CIDR is plumbed into CEP")
			Eventually(func() string {
				res := kubectl.Exec(fmt.Sprintf(
					"%s -n %s get cep %s -o json",
					helpers.KubectlCmd,
					helpers.DefaultNamespace,
					podName))
				ExpectWithOffset(1, res).Should(helpers.CMDSuccess(), "cannot get Cilium endpoint")
				data, err := res.Filter(`{.status.policy.egress}`)
				ExpectWithOffset(1, err).To(BeNil(), "unable to get endpoint %s metadata", podName)
				return data.String()
			}, 2*time.Minute, 2*time.Second).Should(ContainSubstring(expectedCIDR))
		}

		validateEgressAfterDeletion := func() {
			By("Checking that toServices CIDR is no longer plumbed into CEP")
			Eventually(func() string {
				res := kubectl.Exec(fmt.Sprintf(
					"%s -n %s get cep %s -o json",
					helpers.KubectlCmd,
					helpers.DefaultNamespace,
					podName))
				ExpectWithOffset(1, res).Should(helpers.CMDSuccess(), "cannot get Cilium endpoint")
				data, err := res.Filter(`{.status.policy.egress}`)
				ExpectWithOffset(1, err).To(BeNil(), "unable to get endpoint %s metadata", podName)
				return data.String()
			}, 2*time.Minute, 2*time.Second).ShouldNot(ContainSubstring(expectedCIDR))
		}

		It("To Services first endpoint creation", func() {
			res := kubectl.Apply(endpointPath)
			res.ExpectSuccess()

			applyPolicy(policyPath)
			validateEgress()

			kubectl.Delete(policyPath)
			kubectl.Delete(endpointPath)
			validateEgressAfterDeletion()
		})

		It("To Services first policy", func() {
			applyPolicy(policyPath)
			res := kubectl.Apply(endpointPath)
			res.ExpectSuccess()

			validateEgress()

			kubectl.Delete(policyPath)
			kubectl.Delete(endpointPath)
			validateEgressAfterDeletion()
		})

		It("To Services first endpoint creation match service by labels", func() {
			By("Creating Kubernetes Endpoint")
			res := kubectl.Apply(endpointPath)
			res.ExpectSuccess()

			applyPolicy(policyLabeledPath)

			validateEgress()

			kubectl.Delete(policyLabeledPath)
			kubectl.Delete(endpointPath)
			validateEgressAfterDeletion()
		})

		It("To Services first policy, match service by labels", func() {
			applyPolicy(policyLabeledPath)

			By("Creating Kubernetes Endpoint")
			res := kubectl.Apply(endpointPath)
			res.ExpectSuccess()

			validateEgress()

			kubectl.Delete(policyLabeledPath)
			kubectl.Delete(endpointPath)
			validateEgressAfterDeletion()
		})
	})

	Context("Bookinfo Demo", func() {

		var (
			bookinfoV1YAML, bookinfoV2YAML string
			resourceYAMLs                  []string
			policyPath                     string
		)

		BeforeEach(func() {

			bookinfoV1YAML = helpers.ManifestGet("bookinfo-v1.yaml")
			bookinfoV2YAML = helpers.ManifestGet("bookinfo-v2.yaml")
			policyPath = helpers.ManifestGet("cnp-specs.yaml")

			resourceYAMLs = []string{bookinfoV1YAML, bookinfoV2YAML}

			for _, resourcePath := range resourceYAMLs {
				By("Creating objects in file %q", resourcePath)
				res := kubectl.Create(resourcePath)
				res.ExpectSuccess("unable to create resource %q", resourcePath)
			}
		})

		AfterEach(func() {

			// Explicitly do not check result to avoid having assertions in AfterEach.
			_ = kubectl.Delete(policyPath)

			for _, resourcePath := range resourceYAMLs {
				By("Deleting resource %s", resourcePath)
				// Explicitly do not check result to avoid having assertions in AfterEach.
				_ = kubectl.Delete(resourcePath)
			}
		})

		It("Tests bookinfo demo", func() {

			// We use wget in this test because the Istio apps do not provide curl.
			wgetCommand := fmt.Sprintf("wget --tries=2 --connect-timeout %d", helpers.CurlConnectTimeout)

			version := "version"
			v1 := "v1"

			productPage := "productpage"
			reviews := "reviews"
			ratings := "ratings"
			details := "details"
			dnsChecks := []string{productPage, reviews, ratings, details}
			app := "app"
			health := "health"
			ratingsPath := "ratings/0"

			apiPort := "9080"

			podNameFilter := "{.items[*].metadata.name}"

			// shouldConnect asserts that srcPod can connect to dst.
			shouldConnect := func(srcPod, dst string) {
				By("Checking that %q can connect to %q", srcPod, dst)
				res := kubectl.ExecPodCmd(
					helpers.DefaultNamespace, srcPod, fmt.Sprintf("%s %s", wgetCommand, dst))
				res.ExpectSuccess("Unable to connect from %q to %q", srcPod, dst)
			}

			// shouldNotConnect asserts that srcPod cannot connect to dst.
			shouldNotConnect := func(srcPod, dst string) {
				By("Checking that %q cannot connect to %q", srcPod, dst)
				res := kubectl.ExecPodCmd(
					helpers.DefaultNamespace, srcPod, fmt.Sprintf("%s %s", wgetCommand, dst))
				res.ExpectFail("Was able to connect from %q to %q, but expected no connection: %s", srcPod, dst, res.CombineOutput())
			}

			// formatLabelArgument formats the provided key-value pairs as labels for use in
			// querying Kubernetes.
			formatLabelArgument := func(firstKey, firstValue string, nextLabels ...string) string {
				baseString := fmt.Sprintf("-l %s=%s", firstKey, firstValue)
				if nextLabels == nil {
					return baseString
				} else if len(nextLabels)%2 != 0 {
					Fail("must provide even number of arguments for label key-value pairings")
				} else {
					for i := 0; i < len(nextLabels); i += 2 {
						baseString = fmt.Sprintf("%s,%s=%s", baseString, nextLabels[i], nextLabels[i+1])
					}
				}
				return baseString
			}

			// formatAPI is a helper function which formats a URI to access.
			formatAPI := func(service, port, resource string) string {
				target := fmt.Sprintf(
					"%s.%s.svc.cluster.local:%s",
					service, helpers.DefaultNamespace, port)
				if resource != "" {
					return fmt.Sprintf("%s/%s", target, resource)
				}
				return target
			}

			By("Waiting for pods to be ready")
			err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=bookinfo", helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Pods are not ready after timeout")

			By("Waiting for services to be ready")
			for _, service := range []string{details, ratings, reviews, productPage} {
				err = kubectl.WaitForServiceEndpoints(
					helpers.DefaultNamespace, "", service,
					helpers.HelperTimeout)
				Expect(err).Should(BeNil(), "Service %q is not ready after timeout", service)
			}
			By("Validating DNS without Policy")
			for _, name := range dnsChecks {
				err = kubectl.WaitForKubeDNSEntry(name, helpers.DefaultNamespace)
				Expect(err).To(BeNil(), "DNS entry is not ready after timeout")
			}

			By("All pods should be able to connect without policy")

			reviewsPodV1, err := kubectl.GetPods(helpers.DefaultNamespace, formatLabelArgument(app, reviews, version, v1)).Filter(podNameFilter)
			Expect(err).Should(BeNil(), "cannot get reviewsV1 pods")
			productpagePodV1, err := kubectl.GetPods(helpers.DefaultNamespace, formatLabelArgument(app, productPage, version, v1)).Filter(podNameFilter)
			Expect(err).Should(BeNil(), "cannot get productpageV1 pods")

			shouldConnect(reviewsPodV1.String(), formatAPI(ratings, apiPort, health))
			shouldConnect(reviewsPodV1.String(), formatAPI(ratings, apiPort, ratingsPath))

			shouldConnect(productpagePodV1.String(), formatAPI(details, apiPort, health))
			shouldConnect(productpagePodV1.String(), formatAPI(ratings, apiPort, health))
			shouldConnect(productpagePodV1.String(), formatAPI(ratings, apiPort, ratingsPath))

			policyCmd := "cilium policy get io.cilium.k8s.policy.name=cnp-specs"

			By("Importing policy")

			_, err = kubectl.CiliumPolicyAction(helpers.KubeSystemNamespace, policyPath, helpers.KubectlCreate, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Error creating policy %q", policyPath)

			By("Checking that policies were correctly imported into Cilium")
			res := kubectl.ExecPodCmd(helpers.KubeSystemNamespace, ciliumPodK8s1, policyCmd)
			res.ExpectSuccess("Policy %s is not imported", policyCmd)

			By("Validating DNS with Policy loaded")
			for _, name := range dnsChecks {
				err = kubectl.WaitForKubeDNSEntry(name, helpers.DefaultNamespace)
				Expect(err).To(BeNil(), "DNS entry is not ready after timeout")
			}

			By("After policy import")
			shouldConnect(reviewsPodV1.String(), formatAPI(ratings, apiPort, health))
			shouldNotConnect(reviewsPodV1.String(), formatAPI(ratings, apiPort, ratingsPath))

			shouldConnect(productpagePodV1.String(), formatAPI(details, apiPort, health))

			shouldNotConnect(productpagePodV1.String(), formatAPI(ratings, apiPort, health))
			shouldNotConnect(productpagePodV1.String(), formatAPI(ratings, apiPort, ratingsPath))
		})
	})
})
