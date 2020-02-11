// Copyright 2018-2020 Authors of Cilium
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
	"path/filepath"
	"strconv"
	"strings"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

var (
	// These are set in BeforeAll
	demoPath         string
	l7Policy         string
	migrateSVCClient string
	migrateSVCServer string
)

var _ = Describe("K8sUpdates", func() {

	// This test runs 8 steps as following:
	// 1 - delete all pods. Clean cilium, this can be, and should be achieved by
	// `clean-cilium-state: "true"` option that we have in configmap
	// 2 - install cilium `cilium:v${LATEST_STABLE}`
	// 3 - make endpoints talk with each other with policy
	// 4 - upgrade cilium to `k8s1:5000/cilium/cilium-dev:latest`
	// 5 - make endpoints talk with each other with policy
	// 6 - downgrade cilium to `cilium:v${LATEST_STABLE}`
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

		demoPath = helpers.ManifestGet(kubectl.BasePath(), "demo.yaml")
		l7Policy = helpers.ManifestGet(kubectl.BasePath(), "l7-policy.yaml")
		migrateSVCClient = helpers.ManifestGet(kubectl.BasePath(), "migrate-svc-client.yaml")
		migrateSVCServer = helpers.ManifestGet(kubectl.BasePath(), "migrate-svc-server.yaml")
		_ = kubectl.Delete(helpers.DNSDeployment(kubectl.BasePath()))

		kubectl.Delete(migrateSVCClient)
		kubectl.Delete(migrateSVCServer)
		kubectl.Delete(l7Policy)
		kubectl.Delete(demoPath)

		// Delete kube-dns because if not will be a restore the old endpoints
		// from master instead of create the new ones.
		_ = kubectl.DeleteResource(
			"deploy", fmt.Sprintf("-n %s kube-dns", helpers.KubeSystemNamespace))

		_ = kubectl.DeleteResource(
			"deploy", fmt.Sprintf("-n %s cilium-operator", helpers.CiliumNamespace))
		// Sometimes PolicyGen has a lot of pods running around without delete
		// it. Using this we are sure that we delete before this test start
		kubectl.Exec(fmt.Sprintf(
			"%s delete --all pods,svc,cnp -n %s", helpers.KubectlCmd, helpers.DefaultNamespace))

		kubectl.DeleteETCDOperator()

		ExpectAllPodsTerminated(kubectl)
	})

	AfterAll(func() {
		kubectl.CloseSSHClient()
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.CiliumNamespace, "cilium endpoint list")
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
	})

	AfterEach(func() {
		cleanupCallback()
		ExpectAllPodsTerminated(kubectl)
	})
	// FIXME don't skip once stable becomes v1.6 (v1.5 doesn't implement the kube-proxy
	// replacement)
	SkipItIf(func() bool { return !helpers.RunsWithKubeProxy() },
		"Tests upgrade and downgrade from a Cilium stable image to master", func() {
			var assertUpgradeSuccessful func()
			assertUpgradeSuccessful, cleanupCallback =
				InstallAndValidateCiliumUpgrades(
					kubectl,
					helpers.CiliumStableHelmChartVersion,
					helpers.CiliumStableVersion,
					helpers.CiliumLatestHelmChartVersion,
					helpers.CiliumLatestImageVersion,
				)
			assertUpgradeSuccessful()
		})
})

// InstallAndValidateCiliumUpgrades installs and tests if the oldVersion can be
// upgrade to the newVersion and if the newVersion can be downgraded to the
// oldVersion.  It returns two callbacks, the first one is the assertfunction
// that need to run, and the second one are the cleanup actions
func InstallAndValidateCiliumUpgrades(kubectl *helpers.Kubectl, oldHelmChartVersion, oldImageVersion, newHelmChartVersion, newImageVersion string) (func(), func()) {
	canRun, err := helpers.CanRunK8sVersion(oldImageVersion, helpers.GetCurrentK8SEnv())
	ExpectWithOffset(1, err).To(BeNil(), "Unable to get k8s constraints for %s", oldImageVersion)
	if !canRun {
		Skip(fmt.Sprintf(
			"Cilium %q is not supported in K8s %q. Skipping upgrade/downgrade tests.",
			oldImageVersion, helpers.GetCurrentK8SEnv()))
		return func() {}, func() {}
	}

	SkipIfIntegration(helpers.CIIntegrationFlannel)

	apps := []string{helpers.App1, helpers.App2, helpers.App3}
	app1Service := "app1-service"

	cleanupCiliumState := func(helmPath, chartVersion, imageName, imageTag, registry string) {
		_ = kubectl.ExecMiddle("helm delete cilium --namespace=" + helpers.CiliumNamespace)
		_ = kubectl.ExecMiddle(fmt.Sprintf("kubectl delete configmap --namespace=%s cilium-config", helpers.CiliumNamespace))
		_ = kubectl.ExecMiddle(fmt.Sprintf("kubectl delete serviceaccount --namespace=%s cilium cilium-operator", helpers.CiliumNamespace))
		_ = kubectl.ExecMiddle(fmt.Sprintf("kubectl delete clusterrole --namespace=%s cilium cilium-operator", helpers.CiliumNamespace))
		_ = kubectl.ExecMiddle(fmt.Sprintf("kubectl delete clusterrolebinding --namespace=%s cilium cilium-operator", helpers.CiliumNamespace))
		_ = kubectl.ExecMiddle(fmt.Sprintf("kubectl delete daemonset --namespace=%s cilium", helpers.CiliumNamespace))
		_ = kubectl.ExecMiddle(fmt.Sprintf("kubectl delete deployment --namespace=%s cilium-operator", helpers.CiliumNamespace))
		ExpectAllPodsTerminated(kubectl)
		opts := map[string]string{
			"global.cleanState":    "true",
			"global.tag":           imageTag,
			"agent.sleepAfterInit": "true",
			"operator.enabled":     "false ",
		}
		if registry != "" {
			opts["global.registry"] = registry
		}
		if imageName != "" {
			opts["agent.image"] = imageName
		}
		cmd, err := kubectl.RunHelm(
			"install",
			helmPath,
			"cilium",
			chartVersion,
			helpers.CiliumNamespace,
			opts,
		)
		ExpectWithOffset(1, err).To(BeNil(), "Cilium clean state %q was not able to be deployed", chartVersion)
		ExpectWithOffset(1, cmd).To(helpers.CMDSuccess(), "Cilium clean state %q was not able to be deployed", chartVersion)
		err = kubectl.WaitforPods(helpers.CiliumNamespace, "-l k8s-app=cilium", longTimeout)
		ExpectWithOffset(1, err).To(BeNil(), "Cilium %q was not able to be deployed", chartVersion)
		err = kubectl.WaitForCiliumInitContainerToFinish()
		ExpectWithOffset(1, err).To(BeNil(), "Cilium %q was not able to be clean up environment", chartVersion)
		cmd = kubectl.ExecMiddle("helm delete cilium --namespace=" + helpers.CiliumNamespace)
		ExpectWithOffset(1, cmd).To(helpers.CMDSuccess(), "Cilium %q was not able to be deleted", chartVersion)
		ExpectAllPodsTerminated(kubectl)
	}

	cleanupCallback := func() {
		kubectl.Delete(migrateSVCClient)
		kubectl.Delete(migrateSVCServer)
		kubectl.Delete(l7Policy)
		kubectl.Delete(demoPath)

		kubectl.DeleteETCDOperator()

		if res := kubectl.Delete(helpers.DNSDeployment(kubectl.BasePath())); !res.WasSuccessful() {
			log.Warningf("Unable to delete CoreDNS deployment: %s", res.OutputPrettyPrint())
		}

		// make sure we clean everything up before doing any other test
		cleanupCiliumState(filepath.Join(kubectl.BasePath(), helpers.HelmTemplate), newHelmChartVersion, "", newImageVersion, "")
	}

	testfunc := func() {
		By("Deleting Cilium, CoreDNS, and etcd-operator...")
		// Making sure that we deleted the  cilium ds. No assert
		// message because maybe is not present
		if res := kubectl.DeleteResource("ds", fmt.Sprintf("-n %s cilium", helpers.CiliumNamespace)); !res.WasSuccessful() {
			log.Warningf("Unable to delete Cilium DaemonSet: %s", res.OutputPrettyPrint())
		}

		// Delete kube-dns because if not will be a restore the old
		// endpoints from master instead of create the new ones.
		if res := kubectl.Delete(helpers.DNSDeployment(kubectl.BasePath())); !res.WasSuccessful() {
			log.Warningf("Unable to delete CoreDNS deployment: %s", res.OutputPrettyPrint())
		}

		// Delete all etcd pods otherwise they will be kept running but
		// the bpf endpoints will be cleaned up when we restart cilium
		// with a clean state a couple lines bellow
		kubectl.DeleteETCDOperator()

		By("Waiting for pods to be terminated..")
		ExpectAllPodsTerminated(kubectl)

		cmd := kubectl.HelmAddCiliumRepo()
		ExpectWithOffset(1, cmd).To(helpers.CMDSuccess(), "Unable to install helm repository")

		By("Cleaning Cilium state")
		cleanupCiliumState("cilium/cilium", oldHelmChartVersion, "cilium", oldImageVersion, "docker.io/cilium")

		By("Deploying Cilium %s", oldHelmChartVersion)
		cmd, err = kubectl.RunHelm(
			"install",
			"cilium/cilium",
			"cilium",
			oldHelmChartVersion,
			helpers.CiliumNamespace,
			map[string]string{
				"global.tag":      oldImageVersion,
				"global.registry": "docker.io/cilium",
				"agent.image":     "cilium",
			},
		)
		ExpectWithOffset(1, err).To(BeNil(), "Cilium %q was not able to be deployed", oldHelmChartVersion)
		ExpectWithOffset(1, cmd).To(helpers.CMDSuccess(), "Cilium %q was not able to be deployed", oldHelmChartVersion)

		By("Installing kube-dns")
		cmd = kubectl.ApplyDefault(helpers.DNSDeployment(kubectl.BasePath()))
		ExpectWithOffset(1, cmd).To(helpers.CMDSuccess(), "Unable to deploy Kubedns")

		// Cilium is only ready if kvstore is ready, the kvstore is ready if
		// kube-dns is running.
		By("Cilium %q is installed and running", oldHelmChartVersion)
		ExpectCiliumReady(kubectl)
		ExpectCiliumOperatorReady(kubectl)

		validatedImage := func(image string) {
			By("Checking that installed image is %q", image)

			filter := `{.items[*].status.containerStatuses[0].image}`
			data, err := kubectl.GetPods(
				helpers.CiliumNamespace, "-l k8s-app=cilium").Filter(filter)
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

		// checkNoInteruptsInSVCFlows checks whether there are no
		// interrupts in established connections to the migrate-svc service
		// after Cilium has been upgraded / downgraded.
		//
		// The check is based on restart count of the Pods. We can do it so, because
		// any interrupt in the flow makes a client to panic which makes the Pod
		// to restart.
		lastCount := -1
		checkNoInteruptsInSVCFlows := func() {
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

		res := kubectl.ApplyDefault(demoPath)
		ExpectWithOffset(1, res).To(helpers.CMDSuccess(), "cannot apply dempo application")

		err = kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", timeout)
		Expect(err).Should(BeNil(), "Test pods are not ready after timeout")

		ExpectKubeDNSReady(kubectl)

		_, err = kubectl.CiliumPolicyAction(
			helpers.DefaultNamespace, l7Policy, helpers.KubectlApply, timeout)
		Expect(err).Should(BeNil(), "cannot import l7 policy: %v", l7Policy)

		By("Creating service and clients for migration")

		res = kubectl.ApplyDefault(migrateSVCServer)
		ExpectWithOffset(1, res).To(helpers.CMDSuccess(), "cannot apply migrate-svc-server")
		err = kubectl.WaitforPods(helpers.DefaultNamespace, "-l app=migrate-svc-server", timeout)
		Expect(err).Should(BeNil(), "migrate-svc-server pods are not ready after timeout")

		res = kubectl.ApplyDefault(migrateSVCClient)
		ExpectWithOffset(1, res).To(helpers.CMDSuccess(), "cannot apply migrate-svc-client")
		err = kubectl.WaitforPods(helpers.DefaultNamespace, "-l app=migrate-svc-client", timeout)
		Expect(err).Should(BeNil(), "migrate-svc-client pods are not ready after timeout")

		validateEndpointsConnection()
		checkNoInteruptsInSVCFlows()

		waitForUpdateImage := func(image string) func() bool {
			return func() bool {
				pods, err := kubectl.GetCiliumPods(helpers.CiliumNamespace)
				if err != nil {
					return false
				}

				filter := `{.items[*].status.containerStatuses[0].image}`
				data, err := kubectl.GetPods(
					helpers.CiliumNamespace, "-l k8s-app=cilium").Filter(filter)
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
		cmd, err = kubectl.RunHelm(
			"install",
			filepath.Join(kubectl.BasePath(), helpers.HelmTemplate),
			"cilium-preflight",
			newHelmChartVersion,
			helpers.CiliumNamespace,
			map[string]string{
				"preflight.enabled": "true ",
				"agent.enabled":     "false ",
				"config.enabled":    "false ",
				"operator.enabled":  "false ",
				"global.tag":        newImageVersion,
			},
		)
		ExpectWithOffset(1, err).To(BeNil(), "Unable to deploy preflight manifest")
		ExpectWithOffset(1, cmd).To(helpers.CMDSuccess(), "Unable to deploy preflight manifest")
		ExpectCiliumPreFlightInstallReady(kubectl)

		// Once they are installed we can remove it
		By("Removing Cilium pre-flight check DaemonSet")
		cmd = kubectl.ExecMiddle("helm delete cilium-preflight --namespace=" + helpers.CiliumNamespace)
		ExpectWithOffset(1, cmd).To(helpers.CMDSuccess(), "Unable to delete preflight")

		err = kubectl.WaitforPods(
			helpers.CiliumNamespace, "-l k8s-app=cilium", timeout)
		ExpectWithOffset(1, err).Should(BeNil(), "Cilium is not ready after timeout")
		// Need to run using the kvstore-based allocator because upgrading from
		// kvstore-based allocator to CRD-based allocator is not currently
		// supported at this time.
		By("Upgrading Cilium to %s", newHelmChartVersion)
		cmd, err = kubectl.RunHelm(
			"upgrade",
			filepath.Join(kubectl.BasePath(), helpers.HelmTemplate),
			"cilium",
			newHelmChartVersion,
			helpers.CiliumNamespace,
			map[string]string{
				"global.tag":                 newImageVersion,
				"agent.keepDeprecatedLabels": "true",
			})
		ExpectWithOffset(1, err).To(BeNil(), "Cilium %q was not able to be deployed", newHelmChartVersion)
		ExpectWithOffset(1, cmd).To(helpers.CMDSuccess(), "Cilium %q was not able to be deployed", newHelmChartVersion)

		By("Validating pods have the right image version upgraded")
		err = helpers.WithTimeout(
			waitForUpdateImage(newImageVersion),
			fmt.Sprintf("Cilium Pods are not updating correctly to %s", newImageVersion),
			&helpers.TimeoutConfig{Timeout: timeout})
		ExpectWithOffset(1, err).To(BeNil(), "Pods are not updating")

		err = kubectl.WaitforPods(
			helpers.CiliumNamespace, "-l k8s-app=cilium", timeout)
		ExpectWithOffset(1, err).Should(BeNil(), "Cilium is not ready after timeout")

		validatedImage(newImageVersion)
		ExpectCiliumReady(kubectl)
		ExpectCiliumOperatorReady(kubectl)

		validateEndpointsConnection()
		checkNoInteruptsInSVCFlows()

		By("Downgrading cilium to %s image", oldHelmChartVersion)
		// rollback cilium 1 because it's the version that we have started
		// cilium with in this updates test.
		cmd = kubectl.ExecMiddle("helm rollback cilium 1 --namespace=" + helpers.CiliumNamespace)
		ExpectWithOffset(1, cmd).To(helpers.CMDSuccess(), "Cilium %q was not able to be deployed", oldHelmChartVersion)

		err = helpers.WithTimeout(
			waitForUpdateImage(oldImageVersion),
			"Cilium Pods are not updating correctly",
			&helpers.TimeoutConfig{Timeout: timeout})
		ExpectWithOffset(1, err).To(BeNil(), "Pods are not updating")

		err = kubectl.WaitforPods(
			helpers.CiliumNamespace, "-l k8s-app=cilium", timeout)
		ExpectWithOffset(1, err).Should(BeNil(), "Cilium is not ready after timeout")

		validatedImage(oldImageVersion)
		ExpectCiliumOperatorReady(kubectl)

		validateEndpointsConnection()
		checkNoInteruptsInSVCFlows()
	}
	return testfunc, cleanupCallback
}
