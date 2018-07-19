package k8sTest

import (
	"fmt"
	"strings"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
	"github.com/sirupsen/logrus"
)

var _ = Describe("K8sValidatedUpdates", func() {
	var (
		kubectl            *helpers.Kubectl
		logger             *logrus.Entry
		demoPath           string
		l3Policy, l7Policy string
		apps               []string

		app1Service = "app1-service.default.svc.cluster.local"

		microscopeErr    error
		microscopeCancel = func() error { return nil }
	)

	BeforeAll(func() {
		logger = log.WithFields(logrus.Fields{"testName": "K8sValidatedUpdates"})
		logger.Info("Starting")

		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		_ = kubectl.Delete(helpers.DNSDeployment())

		// Delete kube-dns because if not will be a restore the old endpoints
		// from master instead of create the new ones.
		_ = kubectl.DeleteResource(
			"deploy", fmt.Sprintf("-n %s kube-dns", helpers.KubeSystemNamespace))

		apps = []string{helpers.App1, helpers.App2, helpers.App3}

		demoPath = helpers.ManifestGet("demo.yaml")
		l3Policy = helpers.ManifestGet("l3_l4_policy.yaml")
		l7Policy = helpers.ManifestGet("l7_policy.yaml")

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
		//This policies maybe are not loaded, (Test failed before) so no assert here.
		kubectl.Delete(l7Policy)
		kubectl.Delete(l3Policy)
		kubectl.Delete(demoPath)

		_ = kubectl.DeleteResource(
			"ds", fmt.Sprintf("-n %s cilium", helpers.KubeSystemNamespace))

		ExpectAllPodsTerminated(kubectl)
	})

	BeforeEach(func() {
		kubectl.Exec("sudo docker rmi cilium/cilium")
		// Making sure that we deleted the  cilium ds. No assert message
		// because maybe is not present
		kubectl.DeleteResource("ds", fmt.Sprintf("-n %s cilium", helpers.KubeSystemNamespace))
		ExpectAllPodsTerminated(kubectl)

		helpers.InstallExampleCilium(kubectl)

		err := kubectl.CiliumEndpointWaitReady()
		Expect(err).To(BeNil(), "Endpoints are not ready after timeout")

	})

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

	It("Updating Cilium stable to master", func() {
		By("Installing kube-dns")
		kubectl.Apply(helpers.DNSDeployment()).ExpectSuccess("Kube-dns cannot be installed")

		By("Creating some endpoints and L7 policy")
		kubectl.Apply(demoPath).ExpectSuccess()

		err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", timeout)
		Expect(err).Should(BeNil())

		ExpectKubeDNSReady(kubectl)

		_, err = kubectl.CiliumPolicyAction(
			helpers.KubeSystemNamespace, l7Policy, helpers.KubectlApply, timeout)
		Expect(err).Should(BeNil(), "cannot import l7 policy: %v", l7Policy)

		err = kubectl.CiliumEndpointWaitReady()
		Expect(err).To(BeNil(), "Endpoints are not ready after timeout")

		appPods := helpers.GetAppPods(apps, helpers.DefaultNamespace, kubectl, "id")

		err = kubectl.WaitForKubeDNSEntry(app1Service)
		Expect(err).To(BeNil(), "DNS entry is not ready after timeout")

		res := kubectl.ExecPodCmd(
			helpers.DefaultNamespace, appPods[helpers.App2],
			helpers.CurlFail("http://%s/public", app1Service))
		res.ExpectSuccess("Cannot curl app1-service")

		res = kubectl.ExecPodCmd(
			helpers.DefaultNamespace, appPods[helpers.App2],
			helpers.CurlWithHTTPCode("http://%s/private", app1Service))
		res.ExpectContains("403", "Expect 403 in the result")

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
			logger.Infof("Only '%v' of '%v' cilium pods updated to the new image",
				number, len(pods))
			return false
		}

		err = helpers.WithTimeout(
			waitForUpdateImage,
			"Cilium Pods are not updating correctly",
			&helpers.TimeoutConfig{Timeout: timeout})
		Expect(err).To(BeNil(), "Pods are not updating")

		Expect(microscopeCancel()).To(BeNil(), "cannot stop microscope")
		Expect(kubectl.WaitCleanAllTerminatingPods()).To(BeNil(), "Pods didn't terminate correctly")

		microscopeErr, microscopeCancel = kubectl.MicroscopeStart()
		Expect(microscopeErr).To(BeNil(), "Microscope cannot be started")

		err = kubectl.WaitforPods(
			helpers.KubeSystemNamespace, "-l k8s-app=cilium", timeout)
		Expect(err).Should(BeNil(), "Cilium is not ready after timeout")

		validatedImage(localImage)

		err = kubectl.CiliumEndpointWaitReady()
		Expect(err).To(BeNil(), "Endpoints are not ready after timeout")

		ExpectKubeDNSReady(kubectl)

		err = kubectl.WaitForKubeDNSEntry(app1Service)
		Expect(err).To(BeNil(), "DNS entry is not ready after timeout")

		res = kubectl.ExecPodCmd(
			helpers.DefaultNamespace, appPods[helpers.App2],
			helpers.CurlFail("http://%s/public", app1Service))
		res.ExpectSuccess("Cannot curl app1-service")

		res = kubectl.ExecPodCmd(
			helpers.DefaultNamespace, appPods[helpers.App2],
			helpers.CurlWithHTTPCode("http://%s/private", app1Service))
		res.ExpectContains("403", "Expect 403 in the result")
	})
})
