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
	"net"
	"strings"
	"time"

	"github.com/asaskevich/govalidator"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
)

var _ = Describe("K8sValidatedServicesTest", func() {
	var (
		kubectl          *helpers.Kubectl
		logger           *logrus.Entry
		serviceName      = "app1-service"
		microscopeErr    error
		microscopeCancel = func() error { return nil }
		ciliumPodK8s1    string
	)

	applyPolicy := func(path string) {
		_, err := kubectl.CiliumPolicyAction(helpers.KubeSystemNamespace, path, helpers.KubectlApply, helpers.HelperTimeout)
		Expect(err).Should(BeNil(), fmt.Sprintf("Error creating resource %s: %s", path, err))
	}

	BeforeAll(func() {
		var err error

		logger = log.WithFields(logrus.Fields{"testName": "K8sServiceTest"})
		logger.Info("Starting")

		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		err = kubectl.CiliumInstall(helpers.CiliumDSPath)
		Expect(err).To(BeNil(), "Cilium cannot be installed")

		ExpectCiliumReady(kubectl)

		ExpectKubeDNSReady(kubectl)

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
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsOnLogs(CurrentGinkgoTestDescription().Duration)
		Expect(microscopeCancel()).To(BeNil(), "cannot stop microscope")
	})

	AfterEach(func() {
		ExpectAllPodsTerminated(kubectl)
	})

	testHTTPRequest := func(url string) {
		output, err := kubectl.GetPods(helpers.DefaultNamespace, "-l zgroup=testDSClient").Filter("{.items[*].metadata.name}")
		ExpectWithOffset(1, err).Should(BeNil())
		pods := strings.Split(output.String(), " ")
		// A DS with client is running in each node. So we try from each node
		// that can connect to the service.  To make sure that the cross-node
		// service connectivity is correct we tried 10 times, so balance in the
		// two nodes
		for _, pod := range pods {
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
		groups := []string{"zgroup=testDS", "zgroup=testDSClient"}
		for _, pod := range groups {
			err := kubectl.WaitforPods(helpers.DefaultNamespace, fmt.Sprintf("-l %s", pod), 300)
			ExpectWithOffset(1, err).Should(BeNil())
		}
	}

	It("FailTest", func() {
		Expect(true).To(BeFalse())
	})

	Context("Checks ClusterIP Connectivity", func() {

		var (
			demoYAML = helpers.ManifestGet("demo.yaml")
		)

		BeforeEach(func() {
			res := kubectl.Apply(demoYAML)
			res.ExpectSuccess("unable to apply %s: %s", demoYAML, res.CombineOutput())
		})

		AfterEach(func() {
			// Explicitly ignore result of deletion of resources to avoid incomplete
			// teardown if any step fails.
			_ = kubectl.Delete(demoYAML)
		})

		It("Checks service on same node", func() {
			err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", 300)
			Expect(err).Should(BeNil())

			res, err := kubectl.Get(
				helpers.DefaultNamespace, fmt.Sprintf("service %s", serviceName)).Filter("{.spec.clusterIP}")
			Expect(err).Should(BeNil())
			Expect(govalidator.IsIP(res.String())).Should(BeTrue())

			svcIP := res.String()

			status := kubectl.Exec(fmt.Sprintf("curl http://%s/", svcIP))
			status.ExpectSuccess()

			ciliumPod, err := kubectl.GetCiliumPodOnNode(helpers.KubeSystemNamespace, helpers.K8s1)
			Expect(err).Should(BeNil())

			service := kubectl.CiliumExec(ciliumPod, "cilium service list")
			Expect(service.Output()).Should(ContainSubstring(svcIP))
			service.ExpectSuccess()

		}, 300)
	})

	Context("Checks service across nodes", func() {

		var (
			demoYAML = helpers.ManifestGet("demo_ds.yaml")
		)

		BeforeAll(func() {
			res := kubectl.Apply(demoYAML)
			res.ExpectSuccess("unable to apply %s: %s", demoYAML, res.CombineOutput())
		})

		AfterAll(func() {
			// Explicitly ignore result of deletion of resources to avoid incomplete
			// teardown if any step fails.
			_ = kubectl.Delete(demoYAML)
		})

		It("Checks ClusterIP Connectivity", func() {
			waitPodsDs()

			svcIP, err := kubectl.Get(
				helpers.DefaultNamespace, "service testds-service").Filter("{.spec.clusterIP}")
			Expect(err).Should(BeNil())
			log.Debugf("svcIP: %s", svcIP.String())
			Expect(govalidator.IsIP(svcIP.String())).Should(BeTrue())

			url := fmt.Sprintf("http://%s/", svcIP)
			testHTTPRequest(url)
		})

		It("Tests NodePort", func() {
			waitPodsDs()

			var data v1.Service
			err := kubectl.Get("default", "service test-nodeport").Unmarshal(&data)
			Expect(err).Should(BeNil(), "Can not retrieve service")
			url := fmt.Sprintf("http://%s",
				net.JoinHostPort(data.Spec.ClusterIP, fmt.Sprintf("%d", data.Spec.Ports[0].Port)))
			testHTTPRequest(url)

			url = fmt.Sprintf("http://%s",
				net.JoinHostPort(helpers.K8s1Ip, fmt.Sprintf("%d", data.Spec.Ports[0].NodePort)))
			testHTTPRequest(url)

			url = fmt.Sprintf("http://%s",
				net.JoinHostPort(helpers.K8s2Ip, fmt.Sprintf("%d", data.Spec.Ports[0].NodePort)))
			testHTTPRequest(url)
		})
	})

	//TODO: Check service with IPV6

	Context("External services", func() {

		var (
			expectedCIDR = "198.49.23.144/32"
			podName      = "toservices"

			endpointPath      = helpers.ManifestGet("external_endpoint.yaml")
			podPath           = helpers.ManifestGet("external_pod.yaml")
			policyPath        = helpers.ManifestGet("external_policy.yaml")
			policyLabeledPath = helpers.ManifestGet("external_policy_labeled.yaml")
			servicePath       = helpers.ManifestGet("external_service.yaml")
		)

		BeforeEach(func() {
			kubectl.Apply(servicePath).ExpectSuccess("cannot install external service")
			kubectl.Apply(podPath).ExpectSuccess("cannot install pod path")

			err := kubectl.WaitforPods(helpers.DefaultNamespace, "", 300)
			Expect(err).To(BeNil(), "Pods are not ready after timeout")
		})

		AfterEach(func() {
			_ = kubectl.Delete(policyPath)
			_ = kubectl.Delete(endpointPath)
			_ = kubectl.Delete(servicePath)
			_ = kubectl.Delete(podPath)

			kubectl.WaitCleanAllTerminatingPods()
		})

		validateEgress := func() {
			ExpectWithOffset(1, kubectl.WaitCEPReady()).To(BeNil(), "Cep is not ready after timeout")
			Eventually(func() string {
				res := kubectl.Exec(fmt.Sprintf(
					"%s -n %s get cep %s -o json",
					helpers.KubectlCmd,
					helpers.DefaultNamespace,
					podName))
				res.ExpectSuccess("cannot get Cilium Endpoint")
				data, err := res.Filter(`{.status.status.policy.realized.cidr-policy.egress}`)
				ExpectWithOffset(1, err).To(BeNil(), "unable to get endpoint %s metadata", podName)
				return data.String()
			}, 5*time.Minute, 10*time.Second).Should(ContainSubstring(expectedCIDR))
		}

		It("To Services first endpoint creation", func() {
			res := kubectl.Apply(endpointPath)
			res.ExpectSuccess()

			applyPolicy(policyPath)
			validateEgress()
		})

		It("To Services first policy", func() {
			applyPolicy(policyPath)
			res := kubectl.Apply(endpointPath)
			res.ExpectSuccess()

			validateEgress()
		})

		It("To Services first endpoint creation match service by labels", func() {
			res := kubectl.Apply(endpointPath)
			res.ExpectSuccess()

			applyPolicy(policyLabeledPath)

			validateEgress()
		})

		It("To Services first policy, match service by labels", func() {
			applyPolicy(policyLabeledPath)

			res := kubectl.Apply(endpointPath)
			res.ExpectSuccess()

			validateEgress()
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
				res.ExpectSuccess("unable to create resource %q: %s", resourcePath, res.CombineOutput())
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
				res.ExpectSuccess("Unable to connect from %q to %q: %s", srcPod, dst, res.CombineOutput())
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
					panic("must provide even number of arguments for label key-value pairings")
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
					apiPort, helpers.HelperTimeout)
				Expect(err).Should(BeNil(), "Service %q is not ready after timeout", service)
			}
			By("Validating DNS without Policy")
			for _, name := range dnsChecks {
				err = kubectl.WaitForKubeDNSEntry(fmt.Sprintf("%s.%s", name, helpers.DefaultNamespace))
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

			policyCmd := "cilium policy get io.cilium.k8s.policy.name=multi-rules"

			By("Importing policy")

			_, err = kubectl.CiliumPolicyAction(helpers.KubeSystemNamespace, policyPath, helpers.KubectlCreate, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Error creating policy %q", policyPath)

			By("Checking that policies were correctly imported into Cilium")
			res := kubectl.ExecPodCmd(helpers.KubeSystemNamespace, ciliumPodK8s1, policyCmd)
			res.ExpectSuccess("Policy %s is not imported", policyCmd)

			By("Validating DNS with Policy loaded")
			for _, name := range dnsChecks {
				err = kubectl.WaitForKubeDNSEntry(fmt.Sprintf("%s.%s", name, helpers.DefaultNamespace))
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
