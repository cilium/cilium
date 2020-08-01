// Copyright 2019 Authors of Cilium
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

	. "github.com/onsi/gomega"
	"golang.org/x/sync/errgroup"
)

var _ = Describe("K8sFQDNTest", func() {
	var (
		kubectl          *helpers.Kubectl
		backgroundCancel context.CancelFunc = func() { return }
		backgroundError  error

		demoManifest   = ""
		ciliumFilename string

		apps    = []string{helpers.App2, helpers.App3}
		appPods map[string]string

		// The IPs are updated in BeforeAll
		worldTarget          = "http://vagrant-cache.ci.cilium.io"
		worldTargetIP        = "147.75.38.95"
		worldInvalidTarget   = "http://jenkins.cilium.io"
		worldInvalidTargetIP = "104.198.14.52"
	)

	BeforeAll(func() {
		// In case the IPs changed, update them here
		addrs, err := net.LookupHost("vagrant-cache.ci.cilium.io")
		Expect(err).Should(BeNil(), "Error getting IPs for test")
		worldTargetIP = addrs[0]

		addrs, err = net.LookupHost("jenkins.cilium.io")
		Expect(err).Should(BeNil(), "Error getting IPs for test")
		worldInvalidTargetIP = addrs[0]

		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		demoManifest = helpers.ManifestGet(kubectl.BasePath(), "demo.yaml")
		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
		DeployCiliumAndDNS(kubectl, ciliumFilename)

		By("Applying demo manifest")
		res := kubectl.ApplyDefault(demoManifest)
		res.ExpectSuccess("Demo config cannot be deployed")

		err = kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", helpers.HelperTimeout)
		Expect(err).Should(BeNil(), "Testapp is not ready after timeout")

		appPods = helpers.GetAppPods(apps, helpers.DefaultNamespace, kubectl, "id")
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.CiliumNamespace,
			"cilium service list",
			"cilium endpoint list")
	})

	AfterAll(func() {
		_ = kubectl.Delete(demoManifest)
		kubectl.DeleteCiliumDS()
		ExpectAllPodsTerminated(kubectl)
		kubectl.CloseSSHClient()
	})

	JustBeforeEach(func() {
		backgroundCancel, backgroundError = kubectl.BackgroundReport("uptime")
		Expect(backgroundError).To(BeNil(), "Cannot start background report process")
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
		backgroundCancel()
	})

	AfterEach(func() {
		_ = kubectl.Exec(fmt.Sprintf("%s delete --all cnp", helpers.KubectlCmd))
	})

	It("Restart Cilium validate that FQDN is still working", func() {
		// Test overview:
		//
		// When Cilium is running:
		// Connectivity from App2 can connect to DNS because dns-proxy handles
		// the DNS request. If the connection is made correctly, the IP is
		// allowed by the FQDN rule until the DNS TTL expires.
		//
		// When Cilium is not running:
		// The dns-proxy is not running either, so the IP connectivity to an
		// existing IP that was queried before will work, meanwhile connections
		// using a new DNS request will fail.
		//
		// On restart:
		// Cilium will restore the IPs that were allowed in the FQDN and
		// connectivity resumes.

		fqndProxyPolicy := helpers.ManifestGet(kubectl.BasePath(), "fqdn-proxy-policy.yaml")
		_, err := kubectl.CiliumPolicyAction(
			helpers.DefaultNamespace, fqndProxyPolicy,
			helpers.KubectlApply, helpers.HelperTimeout)
		Expect(err).To(BeNil(), "Cannot install fqdn proxy policy")

		By("Performing baseline test to validate connectivity")
		Expect(
			connectivityTestAll(kubectl, appPods,
				worldTarget, worldInvalidTarget, worldTargetIP, worldInvalidTargetIP),
		).ToNot(HaveOccurred())

		By("Deleting Cilium pods")
		kubectl.Exec(
			fmt.Sprintf("%s -n %s delete pods -l k8s-app=cilium",
				helpers.KubectlCmd,
				helpers.CiliumNamespace),
		).ExpectSuccess()

		// Wait for Cilium pods and fire into a channel when either (1) Cilium
		// pods are ready or (2) a timeout occurred. Once WaitforPods exits, we
		// cancel the context to signal to the WithContext loop below to stop
		// the connectivity test.
		ctx, cancel := context.WithCancel(context.Background())
		ch := make(chan error, 1)
		go func() {
			defer GinkgoRecover()
			ch <- kubectl.WaitforPods(helpers.CiliumNamespace,
				"-l k8s-app=cilium",
				helpers.HelperTimeout)
			cancel()
			close(ch)
		}()

		// We are testing connectivity in a loop until the context is
		// cancelled. Note that we return false purposefully because
		// WithTimeout will stop if the function passed in returns true. Once
		// the context is cancelled, then we return true to stop the loop. This
		// is because we want to simulate similar behavior to ginkgo's
		// Consistently. However, we do return the error regardless because we
		// want to terminate immediately if we encounter an error, i.e. the
		// connectivity wasn't consistently successful.
		By("Testing consistent connectivity during Cilium restart")
		var errs []error
		helpers.WithContext(
			ctx,
			func(c context.Context) (bool, error) {
				err := connectivityTestAll(kubectl, appPods,
					worldTarget, worldInvalidTarget, worldTargetIP, worldInvalidTargetIP)
				errs = append(errs, err)
				return false, err
			},
			10*time.Millisecond,
		)
		for _, e := range errs {
			Expect(e).ToNot(HaveOccurred(), "Expected connectivity to work consistently")
		}
		Expect(<-ch).ToNot(HaveOccurred(), "Timeout waiting for Cilium pods")
	})

	It("Validate that multiple specs are working correctly", func() {
		// To make sure that UUID in multiple specs are plumbed correctly to
		// Cilium Policy
		fqdnPolicy := helpers.ManifestGet(kubectl.BasePath(), "fqdn-proxy-multiple-specs.yaml")
		world1Target := worldTarget
		world2Target := worldInvalidTarget

		_, err := kubectl.CiliumPolicyAction(
			helpers.DefaultNamespace, fqdnPolicy,
			helpers.KubectlApply, helpers.HelperTimeout)
		Expect(err).To(BeNil(), "Cannot install fqdn proxy policy")

		By("Validating APP2 policy connectivity")
		res := kubectl.ExecPodCmd(
			helpers.DefaultNamespace, appPods[helpers.App2],
			helpers.CurlFail(world1Target))
		res.ExpectSuccess("Can't connect to to a valid target when it should work")

		res = kubectl.ExecPodCmd(
			helpers.DefaultNamespace, appPods[helpers.App2],
			helpers.CurlFail(world2Target))
		res.ExpectFail("Can connect to a valid target when it should NOT work")

		By("Validating APP3 policy connectivity")

		res = kubectl.ExecPodCmd(
			helpers.DefaultNamespace, appPods[helpers.App3],
			helpers.CurlFail(world2Target))
		res.ExpectSuccess("Can't connect to to a valid target when it should work")

		res = kubectl.ExecPodCmd(
			helpers.DefaultNamespace, appPods[helpers.App3],
			helpers.CurlFail(world1Target))
		res.ExpectFail("Can connect to to a valid target when it should NOT work")
	})
})

func connectivityTestAll(kubectl *helpers.Kubectl, appPods map[string]string,
	dnsTarget, dnsInvalidTarget, ipTarget, ipInvalidTarget string) error {
	var eg errgroup.Group

	eg.Go(func() error {
		defer GinkgoRecover()
		return connectivityTest(kubectl, appPods, dnsTarget, dnsInvalidTarget)
	})
	eg.Go(func() error {
		defer GinkgoRecover()
		return connectivityTest(kubectl, appPods, ipTarget, ipInvalidTarget)
	})

	return eg.Wait()
}

func connectivityTest(kubectl *helpers.Kubectl, appPods map[string]string,
	target, invalidTarget string) error {
	By("Testing connection from %q to %q should work", appPods[helpers.App2], target)
	if err := run(kubectl, appPods[helpers.App2], helpers.CurlFail(target)); err != nil {
		return fmt.Errorf("connectivity failed when it should work: %v", err)
	}

	By("Testing connection from %q to %q should work => done",
		appPods[helpers.App2], target)

	By("Testing connection from %q to %q shouldn't work",
		appPods[helpers.App2], invalidTarget)
	if err := run(kubectl, appPods[helpers.App2], helpers.CurlFail(invalidTarget)); err == nil {
		return fmt.Errorf("connectivity succeeded when it should have failed: %v", err)
	}

	By("Testing connection from %q to %q shouldn't work => done",
		appPods[helpers.App2], invalidTarget)

	return nil
}

func run(k *helpers.Kubectl, pod, target string) error {
	curl := helpers.CurlFail(target)

	r := k.ExecPodCmd(helpers.DefaultNamespace, pod, curl)
	if !r.WasSuccessful() {
		return fmt.Errorf("cannot curl from %q to %q: %v", pod, target, r.GetError())
	}

	return nil
}
