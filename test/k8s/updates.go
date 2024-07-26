// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8sTest

import (
	"context"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	. "github.com/onsi/gomega"

	"github.com/cilium/cilium/pkg/versioncheck"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
)

const (
	// cluster name and ID are set to provide coverage for changes to
	// ClusterMesh, including updates to BPF map updates
	clusterName = "test-upgrade-downgrade"
	// clusterID of 170(10101010) was chosen to utilize all 8 bits of the
	// default ClusterID size.
	// note: It's possible to extend the size of ClusterID by setting
	// MaxConnectedClusters, however this feature is only available to new
	// clusters - thus upgrade and downgrade are not possible. Test coverage
	// for this feature should be added after it is released.
	clusterID = "170"
)

var (
	// These are set in BeforeAll
	demoPath         string
	l7Policy         string
	migrateSVCClient string
	migrateSVCServer string
	stableChartPath  string
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

		cleanupCallback = func() {}
	)
	BeforeAll(func() {
		SkipIfIntegration(helpers.CIIntegrationAKS)
		canRun, err := helpers.CanRunK8sVersion(helpers.CiliumStableVersion, helpers.GetCurrentK8SEnv())
		ExpectWithOffset(1, err).To(BeNil(), "Unable to get k8s constraints for %s", helpers.CiliumStableVersion)
		if !canRun {
			Skip(fmt.Sprintf(
				"Cilium %q is not supported in K8s %q. Skipping upgrade/downgrade tests.",
				helpers.CiliumStableVersion, helpers.GetCurrentK8SEnv()))
			return
		}

		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		demoPath = helpers.ManifestGet(kubectl.BasePath(), "demo.yaml")
		l7Policy = helpers.ManifestGet(kubectl.BasePath(), "l7-policy.yaml")
		migrateSVCClient = helpers.ManifestGet(kubectl.BasePath(), "migrate-svc-client.yaml")
		migrateSVCServer = helpers.ManifestGet(kubectl.BasePath(), "migrate-svc-server.yaml")

		kubectl.Delete(migrateSVCClient)
		kubectl.Delete(migrateSVCServer)
		kubectl.Delete(l7Policy)
		kubectl.Delete(demoPath)

		_ = kubectl.DeleteResource(
			"deploy", fmt.Sprintf("-n %s cilium-operator", helpers.CiliumNamespace))
		// Sometimes PolicyGen has a lot of pods running around without delete
		// it. Using this we are sure that we delete before this test start
		kubectl.Exec(fmt.Sprintf(
			"%s delete --all pods,svc,cnp -n %s", helpers.KubectlCmd, helpers.DefaultNamespace))

		By("Waiting for pods to be terminated")
		ExpectAllPodsTerminated(kubectl)

		// Download the stable helm chart from GitHub
		versionPath := filepath.Join(kubectl.BasePath(), "../old-charts", helpers.CiliumStableVersion)
		stableChartPath = filepath.Join(versionPath, fmt.Sprintf("cilium-%s/install/kubernetes/cilium", helpers.CiliumStableHelmChartVersion))

		cmd := kubectl.Exec(fmt.Sprintf("mkdir -p %s && "+
			"cd %s && "+
			"rm -rf * && "+
			"wget https://github.com/cilium/cilium/archive/refs/heads/%s.tar.gz && "+
			"tar -xf %s.tar.gz",
			versionPath,
			versionPath,
			helpers.CiliumStableVersion,
			helpers.CiliumStableVersion))
		ExpectWithOffset(1, cmd).To(helpers.CMDSuccess(), "Unable to download helm chart %s from GitHub", helpers.CiliumStableVersion)
	})

	AfterAll(func() {
		removeCilium(kubectl)
		kubectl.CloseSSHClient()
	})

	AfterFailed(func() {
		kubectl.CiliumReport("cilium-dbg endpoint list")
	})

	JustAfterEach(func() {
		blacklist := helpers.GetBadLogMessages()
		delete(blacklist, helpers.RemovingMapMsg)
		kubectl.ValidateListOfErrorsInLogs(CurrentGinkgoTestDescription().Duration, blacklist)
	})

	AfterEach(func() {
		cleanupCallback()
		ExpectAllPodsTerminated(kubectl)
	})

	It("Tests upgrade and downgrade from a Cilium stable image to master", func() {
		var assertUpgradeSuccessful func()
		assertUpgradeSuccessful, cleanupCallback =
			InstallAndValidateCiliumUpgrades(
				kubectl,
				helpers.CiliumStableHelmChartVersion,
				helpers.CiliumStableVersion,
				helpers.CiliumLatestHelmChartVersion,
				helpers.GetLatestImageVersion(),
			)
		assertUpgradeSuccessful()
	})
})

func removeCilium(kubectl *helpers.Kubectl) {
	_ = kubectl.ExecMiddle("helm delete cilium-preflight --namespace=" + helpers.CiliumNamespace)
	_ = kubectl.ExecMiddle("helm delete cilium --namespace=" + helpers.CiliumNamespace)

	kubectl.CleanupCiliumComponents()
	ExpectAllPodsTerminated(kubectl)
}

// InstallAndValidateCiliumUpgrades installs and tests if the oldVersion can be
// upgrade to the newVersion and if the newVersion can be downgraded to the
// oldVersion.  It returns two callbacks, the first one is the assertfunction
// that need to run, and the second one are the cleanup actions
func InstallAndValidateCiliumUpgrades(kubectl *helpers.Kubectl, oldHelmChartVersion, oldImageVersion, newHelmChartVersion, newImageVersion string) (func(), func()) {
	var (
		err error

		timeout = 5 * time.Minute
	)

	canRun, err := helpers.CanRunK8sVersion(oldImageVersion, helpers.GetCurrentK8SEnv())
	ExpectWithOffset(1, err).To(BeNil(), "Unable to get k8s constraints for %s", oldImageVersion)
	if !canRun {
		Skip(fmt.Sprintf(
			"Cilium %q is not supported in K8s %q. Skipping upgrade/downgrade tests.",
			oldImageVersion, helpers.GetCurrentK8SEnv()))
		return func() {}, func() {}
	}

	apps := []string{helpers.App1, helpers.App2, helpers.App3}
	app1Service := "app1-service"

	cleanupCiliumState := func(helmPath, chartVersion, imageName, imageTag, registry string) {
		// GH-34026: Cilium v1.16.0 broke pidfile cleanup on shutdown. Remove it before the end of the test so that the testsuite can clean up the environment properly.
		By("Cleaning up pidfiles...")
		kubectl.CiliumExecMustSucceedOnAll(context.TODO(), "rm /var/run/cilium/cilium.pid", "Clean up pidfile before test completion")

		removeCilium(kubectl)

		opts := map[string]string{
			"cleanState":         "true",
			"image.tag":          imageTag,
			"sleepAfterInit":     "true",
			"operator.enabled":   "false ",
			"hubble.tls.enabled": "false",
			"cluster.name":       clusterName,
			"cluster.id":         clusterID,
		}
		if imageName != "" {
			opts["image.repository"] = imageName
			opts["preflight.image.repository"] = imageName // preflight must match the target agent image
		}

		EventuallyWithOffset(1, func() (*helpers.CmdRes, error) {
			return kubectl.RunHelm(
				"install",
				helmPath,
				"cilium",
				chartVersion,
				helpers.CiliumNamespace,
				opts,
			)
		}, time.Second*30, time.Second*1).Should(helpers.CMDSuccess(), fmt.Sprintf("Cilium clean state %q was not able to be deployed", chartVersion))

		kubectl.WaitForCiliumReadiness(1, fmt.Sprintf("Cilium %q did not become ready in time", chartVersion))
		err = kubectl.WaitForCiliumInitContainerToFinish()
		ExpectWithOffset(1, err).To(BeNil(), "Cilium %q was not able to be clean up environment", chartVersion)
		cmd := kubectl.ExecMiddle("helm delete cilium --namespace=" + helpers.CiliumNamespace)
		ExpectWithOffset(1, cmd).To(helpers.CMDSuccess(), "Cilium %q was not able to be deleted", chartVersion)
		ExpectAllPodsTerminated(kubectl)
	}

	cleanupCallback := func() {
		kubectl.Delete(migrateSVCClient)
		kubectl.Delete(migrateSVCServer)
		kubectl.Delete(l7Policy)
		kubectl.Delete(demoPath)

		if res := kubectl.DeleteResource("pod", fmt.Sprintf("-n %s -l k8s-app=kube-dns", helpers.KubeSystemNamespace)); !res.WasSuccessful() {
			log.Warningf("Unable to delete DNS pods: %s", res.OutputPrettyPrint())
		}

		// make sure we clean everything up before doing any other test
		cleanupCiliumState(filepath.Join(kubectl.BasePath(), helpers.HelmTemplate), newHelmChartVersion, "", newImageVersion, "")
	}

	testfunc := func() {
		By("Deleting Cilium and CoreDNS")
		// Making sure that we deleted the  cilium ds. No assert
		// message because maybe is not present
		if res := kubectl.DeleteResource("ds", fmt.Sprintf("-n %s cilium", helpers.CiliumNamespace)); !res.WasSuccessful() {
			log.Warningf("Unable to delete Cilium DaemonSet: %s", res.OutputPrettyPrint())
		}

		By("Waiting for pods to be terminated")
		ExpectAllPodsTerminated(kubectl)

		EventuallyWithOffset(1, func() *helpers.CmdRes {
			return kubectl.HelmAddCiliumRepo()
		}, time.Second*30, time.Second*1).Should(helpers.CMDSuccess(), "Unable to install helm repository")

		// New version must come first given prior CI tests may have run on new Cilium version.
		By("Cleaning Cilium state (%s)", newImageVersion)
		cleanupCiliumState(filepath.Join(kubectl.BasePath(), helpers.HelmTemplate), newHelmChartVersion, "", newImageVersion, "")

		By("Cleaning Cilium state (%s)", oldImageVersion)
		cleanupCiliumState(stableChartPath, oldHelmChartVersion, "quay.io/cilium/cilium-ci", oldImageVersion, "")

		By("Deploying Cilium %s", oldHelmChartVersion)

		opts := map[string]string{
			"image.tag":                              oldImageVersion,
			"operator.image.tag":                     oldImageVersion,
			"hubble.relay.image.tag":                 oldImageVersion,
			"clustermesh.apiserver.image.tag":        oldImageVersion,
			"image.repository":                       "quay.io/cilium/cilium-ci",
			"operator.image.repository":              "quay.io/cilium/operator",
			"hubble.relay.image.repository":          "quay.io/cilium/hubble-relay-ci",
			"clustermesh.apiserver.image.repository": "quay.io/cilium/clustermesh-apiserver-ci",
			"cluster.name":                           clusterName,
			"cluster.id":                             clusterID,
		}

		hasNewHelmValues := versioncheck.MustCompile(">=1.12.90")
		if hasNewHelmValues(versioncheck.MustVersion(newHelmChartVersion)) {
			opts["bandwidthManager.enabled"] = "false "
		} else {
			opts["bandwidthManager"] = "false "
		}

		// Eventually allows multiple return values, and performs the assertion
		// on the first return value, and expects that all other return values
		// are zero values (nil, etc.).
		EventuallyWithOffset(1, func() (*helpers.CmdRes, error) {
			return kubectl.RunHelm(
				"install",
				stableChartPath,
				"cilium",
				oldHelmChartVersion,
				helpers.CiliumNamespace,
				opts)
		}, time.Second*30, time.Second*1).Should(helpers.CMDSuccess(), fmt.Sprintf("Cilium %q was not able to be deployed", oldHelmChartVersion))

		// Cilium is only ready if kvstore is ready, the kvstore is ready if
		// kube-dns is running.
		ExpectCiliumReady(kubectl)
		ExpectCiliumOperatorReady(kubectl)
		By("Cilium %q is installed and running", oldHelmChartVersion)

		By("Restarting DNS Pods")
		if res := kubectl.DeleteResource("pod", fmt.Sprintf("-n %s -l k8s-app=kube-dns", helpers.KubeSystemNamespace)); !res.WasSuccessful() {
			log.Warningf("Unable to delete DNS pods: %s", res.OutputPrettyPrint())
		}
		ExpectKubeDNSReady(kubectl)

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
				pods, err := kubectl.GetCiliumPods()
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

		opts = map[string]string{
			"preflight.enabled":   "true ",
			"config.enabled":      "false ",
			"operator.enabled":    "false ",
			"preflight.image.tag": newImageVersion,
			"nodeinit.enabled":    "false",
			"agent":               "false ",
		}

		EventuallyWithOffset(1, func() (*helpers.CmdRes, error) {
			return kubectl.RunHelm(
				"install",
				filepath.Join(kubectl.BasePath(), helpers.HelmTemplate),
				"cilium-preflight",
				newHelmChartVersion,
				helpers.CiliumNamespace,
				opts)
		}, time.Second*30, time.Second*1).Should(helpers.CMDSuccess(), "Unable to deploy preflight manifest")

		ExpectCiliumPreFlightInstallReady(kubectl)

		// Once they are installed we can remove it
		By("Removing Cilium pre-flight check DaemonSet")
		cmd := kubectl.ExecMiddle("helm delete cilium-preflight --namespace=" + helpers.CiliumNamespace)
		ExpectWithOffset(1, cmd).To(helpers.CMDSuccess(), "Unable to delete preflight")

		kubectl.WaitForCiliumReadiness(1, "Cilium is not ready after timeout")
		// Need to run using the kvstore-based allocator because upgrading from
		// kvstore-based allocator to CRD-based allocator is not currently
		// supported at this time.
		By("Upgrading Cilium to %s", newHelmChartVersion)
		opts = map[string]string{
			"image.tag":              newImageVersion,
			"operator.image.tag":     newImageVersion,
			"hubble.relay.image.tag": newImageVersion,
			"cluster.name":           clusterName,
			"cluster.id":             clusterID,
		}

		upgradeCompatibilityVer := strings.TrimSuffix(oldHelmChartVersion, "-dev")
		// Ensure compatibility in the ConfigMap. This tests the
		// upgrade as instructed in the documentation
		opts["upgradeCompatibility"] = upgradeCompatibilityVer

		EventuallyWithOffset(1, func() (*helpers.CmdRes, error) {
			return kubectl.RunHelm(
				"upgrade",
				filepath.Join(kubectl.BasePath(), helpers.HelmTemplate),
				"cilium",
				newHelmChartVersion,
				helpers.CiliumNamespace,
				opts)
		}, time.Second*30, time.Second*1).Should(helpers.CMDSuccess(), fmt.Sprintf("Cilium %q was not able to be deployed", newHelmChartVersion))

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

		nbMissedTailCalls, err := kubectl.CountMissedTailCalls()
		ExpectWithOffset(1, err).Should(BeNil(), "Failed to retrieve number of missed tail calls")
		ExpectWithOffset(1, nbMissedTailCalls).To(BeNumerically("==", 0), "Unexpected missed tail calls")

		By("Check whether svc flows are not interrupted upon cilium-agent restart")
		ciliumFilter := "k8s-app=cilium"
		res = kubectl.Exec(fmt.Sprintf(
			"%s -n %s delete pods -l %s",
			helpers.KubectlCmd, helpers.CiliumNamespace, ciliumFilter))
		res.ExpectSuccess("Failed to delete cilium pods")
		ExpectAllPodsTerminated(kubectl)
		err = kubectl.WaitforPods(
			helpers.CiliumNamespace, fmt.Sprintf("-l %s", ciliumFilter), helpers.HelperTimeout)
		Expect(err).Should(BeNil(), "Pods are not ready after timeout")
		err = kubectl.CiliumEndpointWaitReady()
		Expect(err).To(BeNil(), "Endpoints are not ready after timeout")
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

		nbMissedTailCalls, err = kubectl.CountMissedTailCalls()
		ExpectWithOffset(1, err).Should(BeNil(), "Failed to retrieve number of missed tail calls")
		ExpectWithOffset(1, nbMissedTailCalls).To(BeNumerically("==", 0), "Unexpected missed tail call")
	}
	return testfunc, cleanupCallback
}
