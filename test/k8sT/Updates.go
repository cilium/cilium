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

	var kubectl *helpers.Kubectl
	var logger *logrus.Entry
	var ciliumPath string
	var demoPath string
	var l3Policy, l7Policy string
	var apps []string
	var app1Service string = "app1-service.default.svc.cluster.local"

	BeforeAll(func() {
		logger = log.WithFields(logrus.Fields{"testName": "K8sValidatedUpdates"})
		logger.Info("Starting")

		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		ciliumPath = kubectl.ManifestGet("cilium_ds.yaml")
		kubectl.Delete(ciliumPath)

		apps = []string{helpers.App1, helpers.App2, helpers.App3}

		demoPath = kubectl.ManifestGet("demo.yaml")
		l3Policy = kubectl.ManifestGet("l3_l4_policy.yaml")
		l7Policy = kubectl.ManifestGet("l7_policy.yaml")

		// Sometimes PolicyGen has a lot of pods running around without delete
		// it. Using this we are sure that we delete before this test start
		kubectl.Exec(fmt.Sprintf(
			"%s delete --all pods,svc,cnp -n %s", helpers.KubectlCmd, helpers.DefaultNamespace))

		err := kubectl.WaitCleanAllTerminatingPods()
		Expect(err).To(BeNil(), "Terminating containers are not deleted after timeout")

	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.KubeSystemNamespace, []string{
			"cilium endpoint list"})
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsOnLogs(CurrentGinkgoTestDescription().Duration)
	})

	AfterEach(func() {
		//This policies maybe are not loaded, (Test failed before) so no assert here.
		kubectl.Delete(l7Policy)
		kubectl.Delete(l3Policy)
		kubectl.Delete(demoPath)

		res := kubectl.DeleteResource(
			"ds", fmt.Sprintf("-n %s cilium", helpers.KubeSystemNamespace))
		res.ExpectSuccess("Cilium DS cannot be deleted")

		err := kubectl.WaitCleanAllTerminatingPods()
		Expect(err).To(BeNil(), "Terminating containers are not deleted after timeout")
	})

	BeforeEach(func() {
		kubectl.Exec("sudo docker rmi cilium/cilium")
		// Making sure that we deleted the  cilium ds. No assert message
		// because maybe is not present
		kubectl.DeleteResource("ds", fmt.Sprintf("-n %s cilium", helpers.KubeSystemNamespace))
		helpers.InstallExampleCilium(kubectl)
	})

	validatedImage := func(image string) {
		By(fmt.Sprintf("Checking that installed image is %q", image))

		filter := `{.items[*].status.containerStatuses[0].image}`
		data, err := kubectl.GetPods(
			helpers.KubeSystemNamespace, "-l k8s-app=cilium").Filter(filter)
		ExpectWithOffset(1, err).To(BeNil(), "Cannot get cilium pods")

		for _, val := range strings.Split(data.String(), " ") {
			ExpectWithOffset(1, val).To(Equal(image), "Cilium image didn't update correctly")
		}
	}

	waitEndpointReady := func() {
		ciliumPods, err := kubectl.GetCiliumPods(helpers.KubeSystemNamespace)
		Expect(err).To(BeNil(), "cannot retrieve cilium pods")
		for _, pod := range ciliumPods {
			ExpectWithOffset(1, kubectl.CiliumEndpointWait(pod)).To(BeTrue(),
				"Pod %v is not ready", pod)
		}
	}

	It("Updating Cilium stable to master", func() {

		By("Creating some endpoints and L7 policy")
		kubectl.Apply(demoPath).ExpectSuccess()

		_, err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", timeout)
		Expect(err).Should(BeNil())

		_, err = kubectl.CiliumPolicyAction(
			helpers.KubeSystemNamespace, l7Policy, helpers.KubectlApply, timeout)
		Expect(err).Should(BeNil(), "cannot import l7 policy: %v", l7Policy)

		waitEndpointReady()

		appPods := helpers.GetAppPods(apps, helpers.DefaultNamespace, kubectl, "id")

		err = kubectl.WaitForKubeDNSEntry(app1Service)
		Expect(err).To(BeNil(), "DNS entry is not ready after timeout")

		res := kubectl.ExecPodCmd(
			helpers.DefaultNamespace, appPods[helpers.App2],
			helpers.CurlFail("http://%s/public", app1Service))
		res.ExpectSuccess("Cannot curl app1-service")

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

		status, err := kubectl.WaitforPods(
			helpers.KubeSystemNamespace, "-l k8s-app=cilium", timeout)
		Expect(status).Should(BeTrue(), "Cilium is not ready after timeout")
		Expect(err).Should(BeNil(), "Cilium is not ready after timeout")

		validatedImage(localImage)

		err = kubectl.WaitForKubeDNSEntry(app1Service)
		Expect(err).To(BeNil(), "DNS entry is not ready after timeout")

		res = kubectl.ExecPodCmd(
			helpers.DefaultNamespace, appPods[helpers.App2],
			helpers.CurlFail("http://%s/public", app1Service))
		res.ExpectSuccess("Cannot curl app1-service")
	})
})
