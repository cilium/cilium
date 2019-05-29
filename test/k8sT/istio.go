// Copyright 2018-2019 Authors of Cilium
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
	"time"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

// This tests the Istio 1.1.7 integration, following the configuration
// instructions specified in the Istio Getting Started Guide in
// Documentation/gettingstarted/istio.rst.
// Changes to the Getting Started Guide may require re-generating or copying
// the following manifests:
// - istio-cilium.yaml
// - bookinfo-v1-istio.yaml
// - bookinfo-v2-istio.yaml
// - istio-sidecar-init-policy.yaml
// Cf. the comments below for each manifest.
var _ = Describe("K8sIstioTest", func() {

	var (
		// istioSystemNamespace is the default namespace into which Istio is
		// installed.
		istioSystemNamespace = "istio-system"

		// istioCRDYAMLPath is the file generated from istio-init during a
		// step in Documentation/gettingstarted/istio.rst to setup
		// Istio 1.1.7. In the GSG the file is directly piped to kubectl.
		istioCRDYAMLPath = helpers.ManifestGet("istio-crds.yaml")

		// istioYAMLPath is the istio-cilium.yaml file generated following the
		// instructions in Documentation/gettingstarted/istio.rst to setup
		// Istio 1.1.7. mTLS is enabled.
		istioYAMLPath = helpers.ManifestGet("istio-cilium.yaml")

		// istioServiceNames is the subset of Istio services in the Istio
		// namespace that are accessed from sidecar proxies.
		istioServiceNames = []string{
			// All the services created by Istio are listed here, but only
			// those that we care about are uncommented.
			// "istio-citadel",
			// "istio-galley",
			// "istio-egressgateway",
			"istio-ingressgateway",
			"istio-pilot",
			// "istio-policy",
			// "istio-telemetry",
			// "prometheus",
		}

		// wgetCommand is the command used in this test because the Istio apps
		// do not provide curl.
		wgetCommand = fmt.Sprintf("wget --tries=2 --connect-timeout %d", helpers.CurlConnectTimeout)

		kubectl          *helpers.Kubectl
		microscopeCancel = func() error { return nil }
		uptimeCancel     context.CancelFunc

		teardownTimeout = 10 * time.Minute
	)

	BeforeAll(func() {
		k8sVersion := helpers.GetCurrentK8SEnv()
		switch k8sVersion {
		case "1.7", "1.8", "1.9":
			Skip(fmt.Sprintf("Istio doesn't support K8S %s", k8sVersion))
		}

		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		ProvisionInfraPods(kubectl)

		By("Creating the istio-system namespace")
		res := kubectl.NamespaceCreate(istioSystemNamespace)
		res.ExpectSuccess("unable to create namespace %q", istioSystemNamespace)

		By("Creating the Istio resources")

		res = kubectl.Apply(istioCRDYAMLPath)
		res.ExpectSuccess("unable to create Istio CRDs")

		By("Waiting for Istio CRDs to be ready")
		err := kubectl.WaitForCRDCount("istio.io|certmanager.k8s.io", 53, helpers.HelperTimeout)
		Expect(err).To(BeNil(),
			"Istio CRDs are not ready after timeout")

		res = kubectl.Apply(istioYAMLPath)
		res.ExpectSuccess("unable to create Istio resources")

		// Ignore one-time jobs and Prometheus. All other pods in the
		// namespaces have an "istio" label.
		By("Waiting for Istio pods to be ready")
		err = kubectl.WaitforPods(istioSystemNamespace, "-l istio", helpers.HelperTimeout)
		Expect(err).To(BeNil(),
			"Istio pods are not ready after timeout in namespace %q", istioSystemNamespace)

		for _, name := range istioServiceNames {
			By("Waiting for Istio service %q to be ready", name)
			err = kubectl.WaitForServiceEndpoints(
				istioSystemNamespace, "", name, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Service %q is not ready after timeout", name)
		}

		for _, name := range istioServiceNames {
			By("Waiting for DNS to resolve Istio service %q", name)
			err = kubectl.WaitForKubeDNSEntry(name, istioSystemNamespace)
			Expect(err).To(BeNil(), "DNS entry is not ready after timeout")
		}
	})

	AfterAll(func() {
		By("Deleting the Istio resources")
		_ = kubectl.Delete(istioYAMLPath)

		By("Deleting the Istio CRDs")
		_ = kubectl.Delete(istioCRDYAMLPath)

		By("Deleting the istio-system namespace")
		_ = kubectl.NamespaceDelete(istioSystemNamespace)

		kubectl.WaitCleanAllTerminatingPods(teardownTimeout)
	})

	JustBeforeEach(func() {
		var err error
		err, microscopeCancel = kubectl.MicroscopeStart()
		Expect(err).To(BeNil(), "Microscope cannot be started")

		uptimeCancel, err = kubectl.BackgroundReport("uptime")
		Expect(err).To(BeNil(), "Cannot start background report process")
	})

	JustAfterEach(func() {
		Expect(microscopeCancel()).To(BeNil(), "Cannot stop microscope")
		uptimeCancel()

		kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.KubeSystemNamespace,
			"cilium endpoint list",
			"cilium bpf proxy list")
	})

	// This is a subset of Services's "Bookinfo Demo" test suite, with the pods
	// injected with Istio sidecar proxies and Istio mTLS enabled.
	Context("Istio Bookinfo Demo", func() {

		var (
			resourceYAMLPaths []string
			policyPaths       []string
		)

		BeforeEach(func() {
			// Those YAML files are the bookinfo-v1.yaml and bookinfo-v2.yaml
			// manifests injected with Istio sidecars using those commands:
			// istioctl kube-inject -f bookinfo-v1.yaml > bookinfo-v1-istio.yaml
			// istioctl kube-inject -f bookinfo-v2.yaml > bookinfo-v2-istio.yaml
			bookinfoV1YAML := helpers.ManifestGet("bookinfo-v1-istio.yaml")
			bookinfoV2YAML := helpers.ManifestGet("bookinfo-v2-istio.yaml")
			l7PolicyPath := helpers.ManifestGet("cnp-specs.yaml")

			// Create the L7 policy before creating the pods, in order to test
			// that the sidecar proxy mode doesn't deadlock on endpoint
			// creation in this case.
			policyPaths = []string{l7PolicyPath}
			for _, policyPath := range policyPaths {
				By("Creating policy in file %q", policyPath)
				_, err := kubectl.CiliumPolicyAction(helpers.KubeSystemNamespace, policyPath, helpers.KubectlApply, helpers.HelperTimeout)
				Expect(err).Should(BeNil(), "Unable to create policy %q", policyPath)
			}

			resourceYAMLPaths = []string{bookinfoV2YAML, bookinfoV1YAML}
			for _, resourcePath := range resourceYAMLPaths {
				By("Creating resources in file %q", resourcePath)
				res := kubectl.Create(resourcePath)
				res.ExpectSuccess("Unable to create resource %q", resourcePath)
			}
		})

		AfterEach(func() {
			for _, resourcePath := range resourceYAMLPaths {
				By("Deleting resource in file %q", resourcePath)
				// Explicitly do not check result to avoid having assertions in AfterEach.
				_ = kubectl.Delete(resourcePath)
			}

			for _, policyPath := range policyPaths {
				By("Deleting policy in file %q", policyPath)
				// Explicitly do not check result to avoid having assertions in AfterEach.
				_ = kubectl.Delete(policyPath)
			}
		})

		// shouldConnect checks that srcPod can connect to dstURI.
		shouldConnect := func(srcPod, dstURI string) bool {
			By("Checking that %q can connect to %q", srcPod, dstURI)
			res := kubectl.ExecPodCmd(
				helpers.DefaultNamespace, srcPod, fmt.Sprintf("%s %s", wgetCommand, dstURI))
			if !res.WasSuccessful() {
				GinkgoPrint("Unable to connect from %q to %q: %s", srcPod, dstURI, res.OutputPrettyPrint())
				return false
			}
			return true
		}

		// shouldNotConnect checks that srcPod cannot connect to dstURI.
		shouldNotConnect := func(srcPod, dstURI string) bool {
			By("Checking that %q cannot connect to %q", srcPod, dstURI)
			res := kubectl.ExecPodCmd(
				helpers.DefaultNamespace, srcPod, fmt.Sprintf("%s %s", wgetCommand, dstURI))
			if res.WasSuccessful() {
				GinkgoPrint("Was able to connect from %q to %q, but expected no connection: %s", srcPod, dstURI, res.OutputPrettyPrint())
				return false
			}
			return true
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

		It("Tests bookinfo inter-service connectivity", func() {
			var err error
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

			// Wait for pods and endpoints to be ready before creating the
			// next resources to reduce the load on the next pod creations,
			// in order to reduce the probability of regeneration timeout.
			By("Waiting for Bookinfo pods to be ready")
			err = kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=bookinfo", helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Pods are not ready after timeout")

			By("Waiting for Bookinfo endpoints to be ready")
			err = kubectl.CiliumEndpointWaitReady()
			Expect(err).Should(BeNil(), "Endpoints are not ready after timeout")

			for _, service := range []string{details, ratings, reviews, productPage} {
				By("Waiting for Bookinfo service %q to be ready", service)
				err = kubectl.WaitForServiceEndpoints(
					helpers.DefaultNamespace, "", service,
					helpers.HelperTimeout)
				Expect(err).Should(BeNil(), "Service %q is not ready after timeout", service)
			}

			for _, name := range dnsChecks {
				By("Waiting for DNS to resolve Bookinfo service %q", name)
				err = kubectl.WaitForKubeDNSEntry(name, helpers.DefaultNamespace)
				Expect(err).To(BeNil(), "DNS entry is not ready after timeout")
			}

			By("Testing L7 filtering")
			reviewsPodV1, err := kubectl.GetPods(helpers.DefaultNamespace, formatLabelArgument(app, reviews, version, v1)).Filter(podNameFilter)
			Expect(err).Should(BeNil(), "Cannot get reviewsV1 pods")
			productpagePodV1, err := kubectl.GetPods(helpers.DefaultNamespace, formatLabelArgument(app, productPage, version, v1)).Filter(podNameFilter)
			Expect(err).Should(BeNil(), "Cannot get productpageV1 pods")

			// Connectivity checks often need to be repeated because Pilot
			// is eventually consistent, i.e. it may take some time for a
			// sidecar proxy to get updated with the configuration for another
			// new endpoint and it rejects egress traffic with 503s in the
			// meantime.
			err = helpers.WithTimeout(func() bool {
				allGood := true

				allGood = shouldConnect(reviewsPodV1.String(), formatAPI(ratings, apiPort, health)) && allGood
				allGood = shouldNotConnect(reviewsPodV1.String(), formatAPI(ratings, apiPort, ratingsPath)) && allGood

				allGood = shouldConnect(productpagePodV1.String(), formatAPI(details, apiPort, health)) && allGood

				allGood = shouldNotConnect(productpagePodV1.String(), formatAPI(ratings, apiPort, health)) && allGood
				allGood = shouldNotConnect(productpagePodV1.String(), formatAPI(ratings, apiPort, ratingsPath)) && allGood

				return allGood
			}, "Istio sidecar proxies are not configured", &helpers.TimeoutConfig{Timeout: helpers.HelperTimeout})
			Expect(err).Should(BeNil(), "Cannot configure Istio sidecar proxies")
		})
	})
})
