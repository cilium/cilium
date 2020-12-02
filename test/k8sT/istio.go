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
	"runtime"
	"time"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

// This tests the Istio integration, following the configuration
// instructions specified in the Istio Getting Started Guide in
// Documentation/gettingstarted/istio.rst.
var _ = SkipContextIf(func() bool {
	return helpers.SkipQuarantined() && (helpers.GetCurrentK8SEnv() == "1.19" || helpers.GetCurrentK8SEnv() == "1.20")
}, "K8sIstioTest", func() {

	var (
		// istioSystemNamespace is the default namespace into which Istio is
		// installed.
		istioSystemNamespace = "istio-system"

		istioVersion = "1.5.9"

		// Modifiers for pre-release testing, normally empty
		prerelease     = "" // "-beta.1"
		istioctlParams = ""
		// Keeping these here in comments serve multiple purposes:
		// - remind how to test with prerelease images in future
		// - cause CI infra to prepull these images so that they do not
		//   need to be pulled on demand during the test
		// " --set values.pilot.image=docker.io/cilium/istio_pilot:1.5.9" +
		// " --set values.proxy.image=docker.io/cilium/istio_proxy:1.5.9" +
		// " --set values.proxy_init.image=docker.io/cilium/istio_proxy:1.5.9"
		ciliumOptions = map[string]string{
			// "proxy.sidecarImageRegex": "jrajahalme/istio_proxy",
		}

		// Map of tested runtimes for cilium-istioctl
		ciliumIstioctlOSes = map[string]string{
			"darwin": "osx",
			"linux":  "linux",
		}

		// istioServiceNames is the set of Istio services needed for the tests
		istioServiceNames = []string{
			"istio-ingressgateway",
			"istio-pilot",
		}

		// wgetCommand is the command used in this test because the Istio apps
		// do not provide curl.
		wgetCommand = fmt.Sprintf("wget --tries=2 --connect-timeout %d", helpers.CurlConnectTimeout)

		kubectl      *helpers.Kubectl
		uptimeCancel context.CancelFunc

		teardownTimeout = 10 * time.Minute

		ciliumFilename string
	)

	BeforeAll(func() {
		k8sVersion := helpers.GetCurrentK8SEnv()
		switch k8sVersion {
		case "1.7", "1.8", "1.9", "1.10", "1.11", "1.12", "1.13":
			Skip(fmt.Sprintf("Istio %s doesn't support K8S %s", istioVersion, k8sVersion))
		}

		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		By("Downloading cilium-istioctl")
		os := "linux"
		if kubectl.IsLocal() {
			// Use Ginkgo runtime OS instead when commands are executed in the local Ginkgo host
			os = ciliumIstioctlOSes[runtime.GOOS]
		}
		ciliumIstioctlURL := "https://github.com/cilium/istio/releases/download/" + istioVersion + prerelease + "/cilium-istioctl-" + istioVersion + "-" + os + ".tar.gz"
		res := kubectl.Exec(helpers.CurlWithRetries(fmt.Sprintf("curl -L %s | tar xz", ciliumIstioctlURL), 5, false))
		res.ExpectSuccess("unable to download %s", ciliumIstioctlURL)
		res = kubectl.ExecShort("./cilium-istioctl version")
		res.ExpectSuccess("unable to execute cilium-istioctl")

		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
		DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, ciliumOptions)

		By("Labeling default namespace for sidecar injection")
		res = kubectl.NamespaceLabel(helpers.DefaultNamespace, "istio-injection=enabled")
		res.ExpectSuccess("unable to label namespace %q", helpers.DefaultNamespace)

		By("Deploying Istio")
		res = kubectl.Exec("./cilium-istioctl manifest apply -y" + istioctlParams)
		res.ExpectSuccess("unable to deploy Istio")
	})

	AfterAll(func() {
		By("Deleting default namespace sidecar injection label")
		_ = kubectl.NamespaceLabel(helpers.DefaultNamespace, "istio-injection-")

		By("Deleting the Istio resources")
		_ = kubectl.Exec(fmt.Sprintf("./cilium-istioctl manifest generate | %s delete -f -", helpers.KubectlCmd))

		By("Waiting all terminating PODs to disappear")
		err := kubectl.WaitTerminatingPods(teardownTimeout)
		ExpectWithOffset(1, err).To(BeNil(), "terminating Istio PODs are not deleted after timeout")

		By("Deleting the istio-system namespace")
		_ = kubectl.NamespaceDelete(istioSystemNamespace)

		UninstallCiliumFromManifest(kubectl, ciliumFilename)
		kubectl.CloseSSHClient()
	})

	JustBeforeEach(func() {
		var err error
		uptimeCancel, err = kubectl.BackgroundReport("uptime")
		Expect(err).To(BeNil(), "Cannot start background report process")
	})

	JustAfterEach(func() {
		uptimeCancel()

		kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
	})

	AfterFailed(func() {
		kubectl.CiliumReport("cilium endpoint list")
	})

	// This is defined as a separate function to be called from the test below
	// so that we properly capture test artifacts if any of the assertions fail
	// (see https://github.com/cilium/cilium/pull/8508).
	waitIstioReady := func() {
		// Ignore one-time jobs and Prometheus. All other pods in the
		// namespaces have an "istio" label.
		By("Waiting for Istio pods to be ready")
		// First wait for at least one POD to get into running state so that WaitforPods
		// below does not succeed if there are no PODs with the "istio" label.
		err := kubectl.WaitforNPodsRunning(istioSystemNamespace, "-l istio", 1, helpers.HelperTimeout)
		ExpectWithOffset(1, err).To(BeNil(),
			"No Istio POD is Running after timeout in namespace %q", istioSystemNamespace)

		// Then wait for all the Istio PODs to get Ready
		// Note that this succeeds if there are no PODs matching the filter (-l istio -n istio-system).
		err = kubectl.WaitforPods(istioSystemNamespace, "-l istio", helpers.HelperTimeout)
		ExpectWithOffset(1, err).To(BeNil(),
			"Istio pods are not ready after timeout in namespace %q", istioSystemNamespace)

		for _, name := range istioServiceNames {
			By("Waiting for Istio service %q to be ready", name)
			err = kubectl.WaitForServiceEndpoints(
				istioSystemNamespace, "", name, helpers.HelperTimeout)
			ExpectWithOffset(1, err).Should(BeNil(), "Service %q is not ready after timeout", name)
		}

		for _, name := range istioServiceNames {
			By("Waiting for DNS to resolve Istio service %q", name)
			err = kubectl.WaitForKubeDNSEntry(name, istioSystemNamespace)
			ExpectWithOffset(1, err).To(BeNil(), "DNS entry is not ready after timeout")
		}
	}

	// This is a subset of Services's "Bookinfo Demo" test suite, with the pods
	// injected with Istio sidecar proxies and Istio mTLS enabled.
	SkipContextIf(func() bool { return ciliumIstioctlOSes[runtime.GOOS] == "" }, "Istio Bookinfo Demo", func() {

		var (
			resourceYAMLPaths []string
			policyPaths       []string
		)

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
		shouldConnect := func(srcPod, srcContainer, dstURI string) bool {
			By("Checking that %q can connect to %q", srcPod, dstURI)
			res := kubectl.ExecPodContainerCmd(
				helpers.DefaultNamespace, srcPod, srcContainer, fmt.Sprintf("%s %s", wgetCommand, dstURI))
			if !res.WasSuccessful() {
				GinkgoPrint("Unable to connect from %q to %q: %s", srcPod, dstURI, res.OutputPrettyPrint())
				return false
			}
			return true
		}

		// shouldNotConnect checks that srcPod cannot connect to dstURI.
		shouldNotConnect := func(srcPod, srcContainer, dstURI string) bool {
			By("Checking that %q cannot connect to %q", srcPod, dstURI)
			res := kubectl.ExecPodContainerCmd(
				helpers.DefaultNamespace, srcPod, srcContainer, fmt.Sprintf("%s %s", wgetCommand, dstURI))
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

			bookinfoV1YAML := helpers.ManifestGet(kubectl.BasePath(), "bookinfo-v1.yaml")
			bookinfoV2YAML := helpers.ManifestGet(kubectl.BasePath(), "bookinfo-v2.yaml")
			l7PolicyPath := helpers.ManifestGet(kubectl.BasePath(), "cnp-specs.yaml")

			waitIstioReady()

			// Create the L7 policy before creating the pods, in order to test
			// that the sidecar proxy mode doesn't deadlock on endpoint
			// creation in this case.
			policyPaths = []string{l7PolicyPath}
			for _, policyPath := range policyPaths {
				By("Creating policy in file %q", policyPath)
				_, err := kubectl.CiliumPolicyAction(helpers.DefaultNamespace, policyPath, helpers.KubectlApply, helpers.HelperTimeout)
				Expect(err).Should(BeNil(), "Unable to create policy %q", policyPath)
			}

			resourceYAMLPaths = []string{bookinfoV2YAML, bookinfoV1YAML}
			for _, resourcePath := range resourceYAMLPaths {
				By("Creating resources in file %q", resourcePath)
				res := kubectl.Create(resourcePath)
				res.ExpectSuccess("Unable to create resource %q", resourcePath)
			}

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

				allGood = shouldConnect(reviewsPodV1.String(), "reviews", formatAPI(ratings, apiPort, health)) && allGood
				allGood = shouldNotConnect(reviewsPodV1.String(), "reviews", formatAPI(ratings, apiPort, ratingsPath)) && allGood

				allGood = shouldConnect(productpagePodV1.String(), "productpage", formatAPI(details, apiPort, health)) && allGood

				allGood = shouldNotConnect(productpagePodV1.String(), "productpage", formatAPI(ratings, apiPort, health)) && allGood
				allGood = shouldNotConnect(productpagePodV1.String(), "productpage", formatAPI(ratings, apiPort, ratingsPath)) && allGood

				return allGood
			}, "Istio sidecar proxies are not configured", &helpers.TimeoutConfig{Timeout: helpers.HelperTimeout})
			Expect(err).Should(BeNil(), "Cannot configure Istio sidecar proxies")
		})
	})
})
