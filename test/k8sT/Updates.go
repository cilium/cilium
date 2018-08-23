package k8sTest

import (
	"fmt"
	"strings"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

var _ = Describe("K8sUpdates", func() {
	var (
		kubectl            *helpers.Kubectl
		demoPath           string
		l3Policy, l7Policy string
		apps               []string

		microscopeErr    error
		microscopeCancel = func() error { return nil }
		cleanupCallback  = func() { return }
	)

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		_ = kubectl.Delete(helpers.DNSDeployment())

		// Delete kube-dns because if not will be a restore the old endpoints
		// from master instead of create the new ones.
		_ = kubectl.DeleteResource(
			"deploy", fmt.Sprintf("-n %s kube-dns", helpers.KubeSystemNamespace))

		apps = []string{helpers.App1, helpers.App2, helpers.App3}

		demoPath = helpers.ManifestGet("demo.yaml")
		l3Policy = helpers.ManifestGet("l3-l4-policy.yaml")
		l7Policy = helpers.ManifestGet("l7-policy.yaml")

		// Sometimes PolicyGen has a lot of pods running around without delete
		// it. Using this we are sure that we delete before this test start
		kubectl.Exec(fmt.Sprintf(
			"%s delete --all pods,svc,cnp -n %s", helpers.KubectlCmd, helpers.DefaultNamespace))

		ExpectAllPodsTerminated(kubectl)
	})

	JustBeforeEach(func() {
		microscopeErr, microscopeCancel = kubectl.MicroscopeStart()
		Expect(microscopeErr).To(BeNil(), "Microscope cannot be started")
	})

	AfterAll(func() {
		_ = kubectl.Apply(helpers.DNSDeployment())
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.KubeSystemNamespace, "cilium endpoint list")
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsOnLogs(CurrentGinkgoTestDescription().Duration)
		Expect(microscopeCancel()).To(BeNil(), "cannot stop microscope")
	})

	AfterEach(func() {
		cleanupCallback()
		ExpectAllPodsTerminated(kubectl)
	})

	BeforeEach(func() {
		kubectl.Exec("sudo docker rmi cilium/cilium")
		// Making sure that we deleted the  cilium ds. No assert message
		// because maybe is not present
		kubectl.DeleteResource("ds", fmt.Sprintf("-n %s cilium", helpers.KubeSystemNamespace))
		ExpectAllPodsTerminated(kubectl)

		helpers.InstallExampleCilium(kubectl, helpers.StableImage)

		err := kubectl.CiliumEndpointWaitReady()
		Expect(err).To(BeNil(), "Endpoints are not ready after timeout")

	})

	It("Updating Cilium stable to master", func() {
		var assertUpgradeSuccessful func()
		assertUpgradeSuccessful, cleanupCallback = ValidateCiliumUpgrades(kubectl)
		assertUpgradeSuccessful()
	})
})

// ValidateCiliumUpgrades it test that the given cilium master is installed
// correctly and the policies are correctly. It returns two callbacks, the
// first one is the assertfunction that need to run, and the second one are the
// cleanup actions
func ValidateCiliumUpgrades(kubectl *helpers.Kubectl) (func(), func()) {
	demoPath := helpers.ManifestGet("demo.yaml")
	l7Policy := helpers.ManifestGet("l7-policy.yaml")
	apps := []string{helpers.App1, helpers.App2, helpers.App3}
	app1Service := "app1-service"

	cleanupCallback := func() {
		kubectl.Delete(l7Policy)
		kubectl.Delete(demoPath)

		// make sure that Kubedns is deleted correctly
		_ = kubectl.Delete(helpers.DNSDeployment())

		_ = kubectl.DeleteResource(
			"ds", fmt.Sprintf("-n %s cilium", helpers.KubeSystemNamespace))
	}

	testfunc := func() {
		validatedImage := func(image string) {
			By("Checking that installed image is %q", image)

			filter := `{.items[*].status.containerStatuses[0].image}`
			data, err := kubectl.GetPods(
				helpers.KubeSystemNamespace, "-l k8s-app=cilium").Filter(filter)
			ExpectWithOffset(1, err).To(BeNil(), "Cannot get cilium pods")

			for _, val := range strings.Split(data.String(), " ") {
				ExpectWithOffset(1, val).To(Equal(image), "Cilium image didn't update correctly")
			}
		}

		By("Installing kube-dns")
		kubectl.Apply(helpers.DNSDeployment()).ExpectSuccess("Kube-dns cannot be installed")

		By("Creating some endpoints and L7 policy")
		kubectl.Apply(demoPath).ExpectSuccess()

		err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", timeout)
		Expect(err).Should(BeNil(), "Test pods are not ready after timeout")

		ExpectKubeDNSReady(kubectl)

		_, err = kubectl.CiliumPolicyAction(
			helpers.KubeSystemNamespace, l7Policy, helpers.KubectlApply, timeout)
		Expect(err).Should(BeNil(), "cannot import l7 policy: %v", l7Policy)

		err = kubectl.CiliumEndpointWaitReady()
		Expect(err).To(BeNil(), "Endpoints are not ready after timeout")

		appPods := helpers.GetAppPods(apps, helpers.DefaultNamespace, kubectl, "id")

		err = kubectl.WaitForKubeDNSEntry(app1Service, helpers.DefaultNamespace)
		Expect(err).To(BeNil(), "DNS entry is not ready after timeout")

		res := kubectl.ExecPodCmd(
			helpers.DefaultNamespace, appPods[helpers.App2],
			helpers.CurlFail("http://%s/public", app1Service))
		res.ExpectSuccess("Cannot curl app1-service")

		res = kubectl.ExecPodCmd(
			helpers.DefaultNamespace, appPods[helpers.App2],
			helpers.CurlFail("http://%s/private", app1Service))
		res.ExpectFail("Expect a 403 from app1-service")

		By("Updating cilium to master image")

		localImage := "k8s1:5000/cilium/cilium-dev:latest"
		resource := "daemonset/cilium"

		kubectl.Exec(fmt.Sprintf("%s -n %s set image %s cilium-agent=%s",
			helpers.KubectlCmd, helpers.KubeSystemNamespace,
			resource, localImage)).ExpectSuccess(
			"Cannot update image")

		waitForUpdateImage := func() bool {
			pods, err := kubectl.GetCiliumPods(helpers.KubeSystemNamespace)
			if err != nil {
				return false
			}

			filter := `{.items[*].status.containerStatuses[0].image}`
			data, err := kubectl.GetPods(
				helpers.KubeSystemNamespace, "-l k8s-app=cilium").Filter(filter)
			if err != nil {
				return false
			}
			number := strings.Count(data.String(), localImage)
			if number == len(pods) {
				return true
			}
			log.Infof("Only '%v' of '%v' cilium pods updated to the new image",
				number, len(pods))
			return false
		}

		err = helpers.WithTimeout(
			waitForUpdateImage,
			"Cilium Pods are not updating correctly",
			&helpers.TimeoutConfig{Timeout: timeout})
		Expect(err).To(BeNil(), "Pods are not updating")

		err = kubectl.WaitforPods(
			helpers.KubeSystemNamespace, "-l k8s-app=cilium", timeout)
		Expect(err).Should(BeNil(), "Cilium is not ready after timeout")

		validatedImage(localImage)

		err = kubectl.CiliumEndpointWaitReady()
		Expect(err).To(BeNil(), "Endpoints are not ready after timeout")

		ExpectKubeDNSReady(kubectl)

		err = kubectl.WaitForKubeDNSEntry(app1Service, helpers.DefaultNamespace)
		Expect(err).To(BeNil(), "DNS entry is not ready after timeout")

		res = kubectl.ExecPodCmd(
			helpers.DefaultNamespace, appPods[helpers.App2],
			helpers.CurlFail("http://%s/public", app1Service))
		res.ExpectSuccess("Cannot curl app1-service")

		res = kubectl.ExecPodCmd(
			helpers.DefaultNamespace, appPods[helpers.App2],
			helpers.CurlFail("http://%s/private", app1Service))
		res.ExpectFail("Expect a 403 from app1-service")

	}
	return testfunc, cleanupCallback
}
