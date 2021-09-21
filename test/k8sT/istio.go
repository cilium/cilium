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
// The 5.4 CI job is intended to catch BPF complexity regressions and as such
// doesn't need to execute this test suite.
var _ = SkipDescribeIf(helpers.RunsOn54Kernel, "K8sIstioTest", func() {

	var (
		// istioSystemNamespace is the default namespace into which Istio is
		// installed.
		istioSystemNamespace = "istio-system"

		istioVersion = "1.10.4"

		// Modifiers for pre-release testing, normally empty
		prerelease     = "" // "-beta.1"
		istioctlParams = ""

		// Keeping these here in comments serve multiple purposes:
		// - remind how to test with prerelease images in future
		// - cause CI infra to prepull these images so that they do not
		//   need to be pulled on demand during the test
		// " --set values.pilot.image=quay.io/cilium/istio_pilot:1.10.4" + prerelease +
		// " --set values.global.proxy.image=quay.io/cilium/istio_proxy:1.10.4" + prerelease +
		// " --set values.global.proxy_init.image=quay.io/cilium/istio_proxy:1.10.4" + prerelease +
		// " --set values.global.proxy.logLevel=debug" +
		// " --set values.global.logging.level=debug"
		// " --set values.global.mtls.auto=false"
		ciliumOptions = map[string]string{
			// "proxy.sidecarImageRegex": "jrajahalme/istio_proxy",
			// "kubeProxyReplacement": "disabled",
			// "debug.enabled": "true",
			// "debug.verbose": "flow",
		}

		// Map for tested cilium-istioctl release targets if not GOOS-GOARCH
		ciliumIstioctlOSes = map[string]string{
			"darwin-amd64": "osx",
		}

		// istioServiceNames is the set of Istio services needed for the tests
		istioServiceNames = []string{
			"istio-ingressgateway",
			"istiod",
		}

		// wgetCommand is the command used in this test because some of the Istio apps
		// do not provide curl.
		wgetCommand = fmt.Sprintf("wget --tries=2 --connect-timeout %d", helpers.CurlConnectTimeout)
		curlCommand = fmt.Sprintf("curl --retry 2 --retry-connrefused --connect-timeout %d", helpers.CurlConnectTimeout)

		kubectl      *helpers.Kubectl
		uptimeCancel context.CancelFunc

		teardownTimeout = 10 * time.Minute

		ciliumFilename string
	)

	BeforeAll(func() {
		if helpers.SkipK8sVersions("<1.17.0") {
			Skip(fmt.Sprintf("Istio %s requires at least K8s version 1.17", istioVersion))
		}

		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		By("Downloading cilium-istioctl")
		kind := "linux-amd64"
		if kubectl.IsLocal() {
			// Use Ginkgo runtime OS-ARCH instead when commands are executed in the local Ginkgo host
			kind = runtime.GOOS + "-" + runtime.GOARCH
			if other, mapped := ciliumIstioctlOSes[kind]; mapped {
				kind = other
			}
		}
		ciliumIstioctlURL := "https://github.com/cilium/istio/releases/download/" + istioVersion + prerelease + "/cilium-istioctl-" + istioVersion + "-" + kind + ".tar.gz"
		res := kubectl.Exec(fmt.Sprintf("curl -s -L %s | tar xz", ciliumIstioctlURL))
		res.ExpectSuccess("unable to download %s", ciliumIstioctlURL)
		res = kubectl.ExecShort("./cilium-istioctl version")
		res.ExpectSuccess("unable to execute cilium-istioctl")

		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
		DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, ciliumOptions)

		By("Labeling default namespace for sidecar injection")
		res = kubectl.NamespaceLabel(helpers.DefaultNamespace, "istio-injection=enabled")
		res.ExpectSuccess("unable to label namespace %q", helpers.DefaultNamespace)

		By("Deploying Istio")
		res = kubectl.Exec("./cilium-istioctl install -y" + istioctlParams)
		res.ExpectSuccess("unable to deploy Istio")
		if !res.WasSuccessful() {
			// AfterAll() is not called if BeforeAll() fails, have to clean up here explicitly
			By("Deleting default namespace sidecar injection label")
			_ = kubectl.NamespaceLabel(helpers.DefaultNamespace, "istio-injection-")
			By("Deleting the Istio resources")
			_ = kubectl.Exec(fmt.Sprintf("./cilium-istioctl manifest generate | %s delete -f -", helpers.KubectlCmd))
			By("Deleting the istio-system namespace")
			_ = kubectl.NamespaceDelete(istioSystemNamespace)
		}
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
	Context("Istio Bookinfo Demo", func() {

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

		// shouldWgetConnect checks that srcPod can connect to dstURI.
		shouldWgetConnect := func(srcPod, srcContainer, dstURI string) bool {
			By("Checking that %q can connect to %q", srcPod, dstURI)
			res := kubectl.ExecPodContainerCmd(
				helpers.DefaultNamespace, srcPod, srcContainer, fmt.Sprintf("%s %s", wgetCommand, dstURI))
			if !res.WasSuccessful() {
				GinkgoPrint("Unable to connect from %q to %q: %s", srcPod, dstURI, res.OutputPrettyPrint())
				return false
			}
			return true
		}

		// shouldCurlConnect checks that srcPod can connect to dstURI.
		shouldCurlConnect := func(srcPod, srcContainer, dstURI string) bool {
			cmd := fmt.Sprintf("%s -v %s", curlCommand, dstURI)
			By("Checking that %q can connect to %q", srcPod, dstURI)
			res := kubectl.ExecPodContainerCmd(
				helpers.DefaultNamespace, srcPod, srcContainer, cmd)
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

		// formatLocalAPI is a helper function which formats a URI to access.
		formatLocalAPI := func(port, resource string) string {
			target := fmt.Sprintf("http://127.0.0.1:%s", port)
			if resource != "" {
				return fmt.Sprintf("%s/%s", target, resource)
			}
			return target
		}

		outbound := "outbound"
		inbound := "inbound"

		// shouldHaveService checks that srcPod has service properly configured.
		shouldHaveService := func(pod, service, port, direction string) bool {
			var target string
			if service != "" {
				target = fmt.Sprintf("%s.%s.svc.cluster.local", service, helpers.DefaultNamespace)
			}
			By("Checking that Istio proxy config at %q has service %q on port %q for %q", pod, target, port, direction)
			res := kubectl.Exec(fmt.Sprintf(`./cilium-istioctl proxy-config cluster %s | grep "%s.*%s.*%s"`, pod, target, port, direction))
			if !res.WasSuccessful() {
				GinkgoPrint("Service %q on port %s for %s not configured at %q", target, port, direction, pod)
				return false
			}
			return true
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

			By("Testing Istio service configuration")
			reviewsPodV1, err := kubectl.GetPods(helpers.DefaultNamespace, formatLabelArgument(app, reviews, version, v1)).Filter(podNameFilter)
			Expect(err).Should(BeNil(), "Cannot get reviewsV1 pods")
			ratingsPodV1, err := kubectl.GetPods(helpers.DefaultNamespace, formatLabelArgument(app, ratings, version, v1)).Filter(podNameFilter)
			Expect(err).Should(BeNil(), "Cannot get ratingsV1 pods")
			detailsPodV1, err := kubectl.GetPods(helpers.DefaultNamespace, formatLabelArgument(app, details, version, v1)).Filter(podNameFilter)
			Expect(err).Should(BeNil(), "Cannot get detailsV1 pods")
			productpagePodV1, err := kubectl.GetPods(helpers.DefaultNamespace, formatLabelArgument(app, productPage, version, v1)).Filter(podNameFilter)
			Expect(err).Should(BeNil(), "Cannot get productpageV1 pods")

			Eventually(func() bool {
				allGood := true

				allGood = shouldHaveService(reviewsPodV1.String(), ratings, apiPort, outbound) && allGood
				allGood = shouldHaveService(ratingsPodV1.String(), "", apiPort, inbound) && allGood
				allGood = shouldHaveService(productpagePodV1.String(), details, apiPort, outbound) && allGood
				allGood = shouldHaveService(detailsPodV1.String(), "", apiPort, inbound) && allGood
				allGood = shouldHaveService(productpagePodV1.String(), ratings, apiPort, outbound) && allGood

				return allGood
			}, helpers.HelperTimeout, 10*time.Second).Should(BeTrue(), "Istio sidecar proxies are not configured")

			By("Testing service local access")

			Eventually(func() bool {
				allGood := true

				allGood = shouldWgetConnect(reviewsPodV1.String(), "reviews", formatLocalAPI(apiPort, health)) && allGood
				allGood = shouldCurlConnect(ratingsPodV1.String(), "ratings", formatLocalAPI(apiPort, health)) && allGood
				allGood = shouldCurlConnect(ratingsPodV1.String(), "ratings", formatLocalAPI(apiPort, ratingsPath)) && allGood
				allGood = shouldCurlConnect(ratingsPodV1.String(), "istio-proxy", formatLocalAPI(apiPort, health)) && allGood

				allGood = shouldCurlConnect(detailsPodV1.String(), "istio-proxy", formatLocalAPI(apiPort, health)) && allGood
				allGood = shouldWgetConnect(productpagePodV1.String(), "productpage", formatLocalAPI(apiPort, health)) && allGood

				return allGood
			}, helpers.HelperTimeout, 1*time.Second).Should(BeTrue(), "Istio services are not reachable")

			// This is kept here for potential future debuging
			//
			// if !shouldWgetConnect(reviewsPodV1.String(), "reviews", formatAPI(ratings, apiPort, health)) {
			// 	helpers.HoldEnvironment("Pausing test for debugging...")
			// }

			By("Testing L7 filtering")
			// Connectivity checks often need to be repeated because Pilot
			// is eventually consistent, i.e. it may take some time for a
			// sidecar proxy to get updated with the configuration for another
			// new endpoint and it rejects egress traffic with 503s in the
			// meantime.
			Eventually(func() bool {
				allGood := true

				allGood = shouldWgetConnect(reviewsPodV1.String(), "reviews", formatAPI(ratings, apiPort, health)) && allGood
				allGood = shouldNotConnect(reviewsPodV1.String(), "reviews", formatAPI(ratings, apiPort, ratingsPath)) && allGood

				allGood = shouldWgetConnect(productpagePodV1.String(), "productpage", formatAPI(details, apiPort, health)) && allGood

				allGood = shouldNotConnect(productpagePodV1.String(), "productpage", formatAPI(ratings, apiPort, health)) && allGood
				allGood = shouldNotConnect(productpagePodV1.String(), "productpage", formatAPI(ratings, apiPort, ratingsPath)) && allGood

				return allGood
			}, helpers.HelperTimeout, 1*time.Second).Should(BeTrue(), "Istio sidecar proxies are not reachable")
		})
	})
})
