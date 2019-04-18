package k8sTest

import (
	"fmt"
	"strconv"
	"strings"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
	. "github.com/onsi/gomega"
)

var _ = Describe("K8sUpdates", func() {

	// This test runs 8 steps as following:
	// 1 - delete all pods. Clean cilium, this can be, and should be achieved by
	// `clean-cilium-state: "true"` option that we have in configmap
	// 2 - install cilium `cilium:v1.4`
	// 3 - make endpoints talk with each other with policy
	// 4 - upgrade cilium to `k8s1:5000/cilium/cilium-dev:latest`
	// 5 - make endpoints talk with each other with policy
	// 6 - downgrade cilium to `cilium:v1.4`
	// 7 - make endpoints talk with each other with policy
	// 8 - delete all pods. Clean cilium, this can be, and should be achieved by
	// `clean-cilium-state: "true"` option that we have in configmap.
	// This makes sure the upgrade tests won't affect any other test
	// 9 - re install cilium:latest image for remaining tests.

	var (
		kubectl *helpers.Kubectl

		cleanupCallback = func() { return }
	)

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		_ = kubectl.Delete(helpers.DNSDeployment())

		// Delete kube-dns because if not will be a restore the old endpoints
		// from master instead of create the new ones.
		_ = kubectl.DeleteResource(
			"deploy", fmt.Sprintf("-n %s kube-dns", helpers.KubeSystemNamespace))

		_ = kubectl.DeleteResource(
			"deploy", fmt.Sprintf("-n %s cilium-operator", helpers.KubeSystemNamespace))
		// Sometimes PolicyGen has a lot of pods running around without delete
		// it. Using this we are sure that we delete before this test start
		kubectl.Exec(fmt.Sprintf(
			"%s delete --all pods,svc,cnp -n %s", helpers.KubectlCmd, helpers.DefaultNamespace))

		kubectl.DeleteETCDOperator()

		ExpectAllPodsTerminated(kubectl)
	})

	AfterAll(func() {
		_ = kubectl.Apply(helpers.DNSDeployment())
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.KubeSystemNamespace, "cilium endpoint list")
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
	})

	AfterEach(func() {
		cleanupCallback()
		ExpectAllPodsTerminated(kubectl)
	})

	It("Tests upgrade and downgrade from a Cilium stable image to master", func() {
		var assertUpgradeSuccessful func()
		assertUpgradeSuccessful, cleanupCallback =
			InstallAndValidateCiliumUpgrades(kubectl, helpers.CiliumStableVersion, helpers.CiliumDeveloperImage)
		assertUpgradeSuccessful()
	})
})

// InstallAndValidateCiliumUpgrades installs and tests if the oldVersion can be
// upgrade to the newVersion and if the newVersion can be downgraded to the
// oldVersion.  It returns two callbacks, the first one is the assertfunction
// that need to run, and the second one are the cleanup actions
func InstallAndValidateCiliumUpgrades(kubectl *helpers.Kubectl, oldVersion, newVersion string) (func(), func()) {
	canRun, err := helpers.CanRunK8sVersion(oldVersion, helpers.GetCurrentK8SEnv())
	ExpectWithOffset(1, err).To(BeNil(), "Unable to get k8s constraints for %s", oldVersion)
	if !canRun {
		Skip(fmt.Sprintf(
			"Cilium %q is not supported in K8s %q. Skipping upgrade/downgrade tests.",
			oldVersion, helpers.GetCurrentK8SEnv()))
		return func() {}, func() {}
	}

	SkipIfFlannel()

	demoPath := helpers.ManifestGet("demo.yaml")
	l7Policy := helpers.ManifestGet("l7-policy.yaml")
	migrateSVCClient := helpers.ManifestGet("migrate-svc-client.yaml")
	migrateSVCServer := helpers.ManifestGet("migrate-svc-server.yaml")
	apps := []string{helpers.App1, helpers.App2, helpers.App3}
	app1Service := "app1-service"

	cleanupCallback := func() {
		kubectl.Delete(migrateSVCClient)
		kubectl.Delete(migrateSVCServer)
		kubectl.Delete(l7Policy)
		kubectl.Delete(demoPath)

		// make sure that Kubedns is deleted correctly
		_ = kubectl.Delete(helpers.DNSDeployment())

		kubectl.DeleteETCDOperator()

		ExpectAllPodsTerminated(kubectl)

		// make sure we clean everything up before doing any other test
		err := kubectl.CiliumInstall(
			helpers.CiliumDefaultDSPatch,
			"cilium-cm-patch-clean-cilium-state.yaml",
		)
		ExpectWithOffset(1, err).To(BeNil(), "Cilium %q was not able to be deployed", newVersion)
		err = kubectl.WaitForCiliumInitContainerToFinish()
		ExpectWithOffset(1, err).To(BeNil(), "Cilium %q was not able to be clean up environment", newVersion)

		_ = kubectl.DeleteResource(
			"ds", fmt.Sprintf("-n %s cilium", helpers.KubeSystemNamespace))
	}

	testfunc := func() {
		// Making sure that we deleted the  cilium ds. No assert message
		// because maybe is not present
		_ = kubectl.DeleteResource("ds", fmt.Sprintf("-n %s cilium", helpers.KubeSystemNamespace))

		// Delete kube-dns because if not will be a restore the old endpoints
		// from master instead of create the new ones.
		_ = kubectl.Delete(helpers.DNSDeployment())

		// Delete all etcd pods otherwise they will be kept running but the bpf
		// endpoints will be cleaned up when we restart cilium with a clean state
		// a couple lines bellow
		_ = kubectl.DeleteResource("pods", fmt.Sprintf("-n %s -l io.cilium/app=etcd-operator", helpers.KubeSystemNamespace))

		ExpectAllPodsTerminated(kubectl)

		By("Installing a cleaning state of Cilium")
		err = kubectl.CiliumInstallVersion(
			helpers.CiliumDefaultDSPatch,
			"cilium-cm-patch-clean-cilium-state.yaml",
			oldVersion,
		)
		Expect(err).To(BeNil(), "Cilium %q was not able to be deployed", oldVersion)

		By("Installing kube-dns")
		_ = kubectl.Apply(helpers.DNSDeployment())

		// Deploy the etcd operator
		By("Deploying etcd-operator")
		err = kubectl.DeployETCDOperator()
		Expect(err).To(BeNil(), "Unable to deploy etcd operator")

		// Cilium is only ready if kvstore is ready, the kvstore is ready if
		// kube-dns is running.
		By("Cilium %q is installed and running", oldVersion)
		ExpectCiliumReady(kubectl)

		By("Installing Cilium-Operator")
		operatorIsInstalled, err := kubectl.CiliumOperatorInstall(oldVersion)
		Expect(err).To(BeNil(), "Cannot install Cilium Operator")

		ExpectETCDOperatorReady(kubectl)
		if operatorIsInstalled {
			ExpectCiliumOperatorReady(kubectl)
		}

		By("Installing Microscope")
		microscopeErr, microscopeCancel := kubectl.MicroscopeStart()
		ExpectWithOffset(1, microscopeErr).To(BeNil(), "Microscope cannot be started")
		defer microscopeCancel()

		validatedImage := func(image string) {
			By("Checking that installed image is %q", image)

			filter := `{.items[*].status.containerStatuses[0].image}`
			data, err := kubectl.GetPods(
				helpers.KubeSystemNamespace, "-l k8s-app=cilium").Filter(filter)
			ExpectWithOffset(1, err).To(BeNil(), "Cannot get cilium pods")

			for _, val := range strings.Split(data.String(), " ") {
				ExpectWithOffset(1, val).To(ContainSubstring(image), "Cilium image didn't update correctly")
			}
		}

		validateEndpointsConnection := func() {
			By("Validate that endpoints are ready before making any connection")
			err := kubectl.CiliumEndpointWaitReady()
			ExpectWithOffset(1, err).To(BeNil(), "Endpoints are not ready after timeout")

			ExpectKubeDNSReady(kubectl)

			err = kubectl.WaitForKubeDNSEntry(app1Service, helpers.DefaultNamespace)
			ExpectWithOffset(1, err).To(BeNil(), "DNS entry is not ready after timeout")

			appPods := helpers.GetAppPods(apps, helpers.DefaultNamespace, kubectl, "id")

			err = kubectl.WaitForKubeDNSEntry(app1Service, helpers.DefaultNamespace)
			ExpectWithOffset(1, err).To(BeNil(), "DNS entry is not ready after timeout")

			By("Making L7 requests between endpoints")
			res := kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				helpers.CurlFail("http://%s/public", app1Service))
			ExpectWithOffset(1, res).Should(helpers.CMDSuccess(), "Cannot curl app1-service")

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				helpers.CurlFail("http://%s/private", app1Service))
			ExpectWithOffset(1, res).ShouldNot(helpers.CMDSuccess(), "Expect a 403 from app1-service")
		}

		// checkNoInteruptsInMigratedSVCFlows checks whether there are no
		// interruptions in established connections to the migrate-svc service
		// after Cilium has been upgraded / downgraded. This is needed to check
		// that migration legacy <-> v2 services does not cause any interruptions.
		//
		// The check is based on restart count of the Pods. We can do it so, because
		// any interrupt in the flow makes a client to panic which makes the Pod
		// to restart.
		lastCount := -1
		checkNoInteruptsInMigratedSVCFlows := func() {
			By("No interrupts in migrated svc flows")

			filter := `{.items[*].status.containerStatuses[0].restartCount}`
			restartCount, err := kubectl.GetPods(helpers.DefaultNamespace,
				"-l zgroup=migrate-svc").Filter(filter)
			ExpectWithOffset(1, err).To(BeNil(), "Failed to query \"migrate-svc-server\" Pod")

			currentCount := 0
			for _, c := range strings.Split(restartCount.String(), " ") {
				count, err := strconv.Atoi(c)
				ExpectWithOffset(1, err).To(BeNil(), "Failed to convert count value")
				currentCount += count
			}
			// The check is invoked for the first time
			if lastCount == -1 {
				lastCount = currentCount
			}
			Expect(lastCount).Should(BeIdenticalTo(currentCount),
				"migrate-svc restart count values do not match")
		}

		By("Creating some endpoints and L7 policy")

		res := kubectl.Apply(demoPath)
		ExpectWithOffset(1, res).To(helpers.CMDSuccess(), "cannot apply dempo application")

		err = kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", timeout)
		Expect(err).Should(BeNil(), "Test pods are not ready after timeout")

		ExpectKubeDNSReady(kubectl)

		_, err = kubectl.CiliumPolicyAction(
			helpers.KubeSystemNamespace, l7Policy, helpers.KubectlApply, timeout)
		Expect(err).Should(BeNil(), "cannot import l7 policy: %v", l7Policy)

		By("Creating service and clients for migration")

		res = kubectl.Apply(migrateSVCServer)
		ExpectWithOffset(1, res).To(helpers.CMDSuccess(), "cannot apply migrate-svc-server")
		err = kubectl.WaitforPods(helpers.DefaultNamespace, "-l app=migrate-svc-server", timeout)
		Expect(err).Should(BeNil(), "migrate-svc-server pods are not ready after timeout")

		res = kubectl.Apply(migrateSVCClient)
		ExpectWithOffset(1, res).To(helpers.CMDSuccess(), "cannot apply migrate-svc-client")
		err = kubectl.WaitforPods(helpers.DefaultNamespace, "-l app=migrate-svc-client", timeout)
		Expect(err).Should(BeNil(), "migrate-svc-client pods are not ready after timeout")

		validateEndpointsConnection()
		checkNoInteruptsInMigratedSVCFlows()

		waitForUpdateImage := func(image string) func() bool {
			return func() bool {
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
				number := strings.Count(data.String(), image)
				if number == len(pods) {
					return true
				}
				log.Infof("Only '%v' of '%v' cilium pods updated to the new image",
					number, len(pods))
				return false
			}
		}

		By("Install Cilium pre-flight check DaemonSet")
		err = kubectl.CiliumPreFlightInstall(helpers.CiliumDefaultPreFlightPatch)
		ExpectWithOffset(1, err).To(BeNil(), "Cilium pre-flight %q was not able to be deployed", newVersion)
		ExpectCiliumPreFlightInstallReady(kubectl)

		// Once they are installed we can remove it
		By("Removing Cilium pre-flight check DaemonSet")
		kubectl.Delete(helpers.GetK8sDescriptor(helpers.CiliumDefaultPreFlight))

		err = kubectl.CiliumInstall(helpers.CiliumDefaultDSPatch, helpers.CiliumConfigMapPatch)
		ExpectWithOffset(1, err).To(BeNil(), "Cilium %q was not able to be deployed", newVersion)

		By("Installing Cilium-Operator")
		operatorIsInstalled, err = kubectl.CiliumOperatorInstall("head")
		Expect(err).To(BeNil(), "Cannot install Cilium Operator")

		err = helpers.WithTimeout(
			waitForUpdateImage(newVersion),
			"Cilium Pods are not updating correctly",
			&helpers.TimeoutConfig{Timeout: timeout})
		ExpectWithOffset(1, err).To(BeNil(), "Pods are not updating")

		err = kubectl.WaitforPods(
			helpers.KubeSystemNamespace, "-l k8s-app=cilium", timeout)
		ExpectWithOffset(1, err).Should(BeNil(), "Cilium is not ready after timeout")

		validatedImage(newVersion)
		ExpectCiliumReady(kubectl)

		if operatorIsInstalled {
			ExpectCiliumOperatorReady(kubectl)
		}

		validateEndpointsConnection()
		checkNoInteruptsInMigratedSVCFlows()

		By("Downgrading cilium to %s image", oldVersion)

		err = kubectl.CiliumInstallVersion(
			helpers.CiliumDefaultDSPatch,
			helpers.CiliumConfigMapPatch,
			oldVersion,
		)
		ExpectWithOffset(1, err).To(BeNil(), "Cilium %q was not able to be deployed", oldVersion)

		By("Installing Cilium-Operator")
		operatorIsInstalled, err = kubectl.CiliumOperatorInstall(oldVersion)
		Expect(err).To(BeNil(), "Cannot install Cilium Operator")

		err = helpers.WithTimeout(
			waitForUpdateImage(oldVersion),
			"Cilium Pods are not updating correctly",
			&helpers.TimeoutConfig{Timeout: timeout})
		ExpectWithOffset(1, err).To(BeNil(), "Pods are not updating")

		err = kubectl.WaitforPods(
			helpers.KubeSystemNamespace, "-l k8s-app=cilium", timeout)
		ExpectWithOffset(1, err).Should(BeNil(), "Cilium is not ready after timeout")

		validatedImage(oldVersion)
		if operatorIsInstalled {
			ExpectCiliumOperatorReady(kubectl)
		}

		validateEndpointsConnection()
		checkNoInteruptsInMigratedSVCFlows()
	}
	return testfunc, cleanupCallback
}
