// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8sTest

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/pkg/defaults"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
)

var _ = SkipDescribeIf(func() bool {
	// Believe it or not, bpftool internally attempts to retrieve
	// map info before updating a map, but BPF_OBJ_GET_INFO_BY_FD
	// is not supported on kernel 4.9 (it was introduced in Linux
	// 4.13). Skip on 4.9 kernels.
	//
	// This leaves us with 4.19 and net-next. Coverage should be
	// identical on the two versions, so just run on net-next.
	//
	// Also skip on GKE because we do not have the source of the
	// custom program available on a node, for the compiler pod to
	// pick up (although technically, skipping 4.19 kernels already
	// skips GKE).
	return helpers.DoesNotRunOnNetNextKernel() ||
		helpers.RunsOnGKE()
}, "K8sDatapathCustomCalls", func() {

	var (
		kubectl *helpers.Kubectl
	)

	type customCallDirection uint32

	const (
		// Constants for tail call hooks
		// See CUSTOM_CALLS_IDX_* defines in bpf/lib/maps.h
		IngressIPv4 customCallDirection = 0
		EgressIPv4  customCallDirection = 1
		IngressIPv6 customCallDirection = 2
		EgressIPv6  customCallDirection = 3
		// eBPF virtual file system
		bpffsDir string = defaults.BPFFSRoot + "/" + defaults.TCGlobalsPath + "/"
	)

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		deploymentManager.SetKubectl(kubectl)
	})

	AfterFailed(func() {
		kubectl.CiliumReport("cilium status", "cilium endpoint list")
	})

	AfterAll(func() {
		kubectl.CloseSSHClient()
	})

	JustAfterEach(func() {
		duration := CurrentGinkgoTestDescription().Duration
		kubectl.ValidateNoErrorsInLogs(duration)
	})

	Context("Basic test with byte-counter", func() {

		var (
			yaml string

			// Object file for custom program
			objFileName   string
			localObjFile  string
			remoteObjFile string

			// Pinned paths in bpffs
			progPinPath string
			mapsPinDir  string
			mapPinPath  string

			// Pods from the manifest
			podList v1.PodList
			podApp1 v1.Pod
			podApp2 v1.Pod
		)

		const (
			compilerPodName string = "bytecounter-compiler"
			pingBytes       uint   = 98 * helpers.PingCount
		)

		AfterEach(func() {
			_ = kubectl.Delete(yaml)
			ExpectAllPodsTerminated(kubectl)
		})

		AfterAll(func() {
			deploymentManager.DeleteAll()
			kubectl.ScaleDownDNS()
			ExpectAllPodsTerminated(kubectl)
			deploymentManager.DeleteCilium()
			kubectl.ScaleUpDNS()
		})

		installPods := func() {
			// Initialize all paths. This cannot be done at
			// variable declaration because kubectl is not set when
			// the Context is initialized.
			objFileName = "bytecount.o"
			localObjFile = filepath.Join(kubectl.BasePath(), "../bpf/custom", objFileName)
			remoteObjFile = filepath.Join("/run/cilium/state", objFileName)

			progPinPath = filepath.Join(bpffsDir, "cilium_bytecounter")
			mapsPinDir = filepath.Join(bpffsDir, "cilium_bytecounter_maps")
			mapPinPath = filepath.Join(mapsPinDir, "bytecount_map")

			yaml = helpers.ManifestGet(kubectl.BasePath(), "demo-customcalls.yaml")
			kubectl.ApplyDefault(yaml).ExpectSuccess("Unable to apply %s", yaml)

			By("Compiling custom byte-counter program")

			err := kubectl.WaitForSinglePod(helpers.DefaultNamespace, compilerPodName, helpers.HelperTimeout)
			Expect(err).ToNot(HaveOccurred(), fmt.Sprintf("%s pod not ready after timeout", compilerPodName))

			const bpfCustomDir string = "bpf/custom"

			cmd := fmt.Sprintf("make -C %s clean V=0", bpfCustomDir)
			res := kubectl.ExecPodCmd(helpers.DefaultNamespace, compilerPodName, cmd)
			res.ExpectSuccess(fmt.Sprintf("Failed to clean up %s directory", bpfCustomDir))

			cmd = fmt.Sprintf("make -C %s V=0", bpfCustomDir)
			res = kubectl.ExecPodCmd(helpers.DefaultNamespace, compilerPodName, cmd)
			res.ExpectSuccess("Failed to build custom byte-counter program")

			cmd = fmt.Sprintf("make -C %s V=0", "cilium")
			res = kubectl.ExecPodCmd(helpers.DefaultNamespace, compilerPodName, cmd)
			res.ExpectSuccess("Failed to build cilium CLI")
		}

		getPodsInfo := func() {
			By("Retrieving pods information")
			// Get pods app1 (HTTP/FTP server) on node 1, and app2
			// (client) on node 2
			err := kubectl.GetPods(helpers.DefaultNamespace, "-l id=app1").Unmarshal(&podList)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(podList.Items)).To(Equal(1))
			podApp1 = podList.Items[0]

			err = kubectl.GetPods(helpers.DefaultNamespace, "-l id=app2").Unmarshal(&podList)
			Expect(err).ToNot(HaveOccurred())
			Expect(len(podList.Items)).To(Equal(1))
			podApp2 = podList.Items[0]
		}

		copyAndLoadObjectFile := func(ciliumPod string) {
			By("Copying custom byte-counter program to Cilium pod")

			cmd := fmt.Sprintf("kubectl -n kube-system cp %s %s:%s", localObjFile, ciliumPod, remoteObjFile)
			res := kubectl.Exec(cmd)
			res.ExpectSuccess(fmt.Sprintf("Failed to copy custom program from %s to %s:%s",
				localObjFile, ciliumPod, remoteObjFile))

			By("Loading custom byte-counter program")

			cmd = fmt.Sprintf("bpftool prog load %s %s type classifier pinmaps %s", remoteObjFile, progPinPath, mapsPinDir)
			res = kubectl.ExecPodCmd(helpers.KubeSystemNamespace, ciliumPod, cmd)
			res.ExpectSuccess("Failed to load custom program")
		}

		getIdentityKey := func(label string, ciliumPod string) string {
			cmd := fmt.Sprintf("cilium endpoint list -o json | jq '.[].status.identity|select(.labels[]|contains(\"%s\")).id'", label)
			res := kubectl.ExecPodCmd(helpers.KubeSystemNamespace, ciliumPod, cmd)
			res.ExpectSuccess("Failed to retrieve pod identity")
			identity, err := strconv.Atoi(strings.TrimSpace(res.Stdout()))
			ExpectWithOffset(2, err).ToNot(HaveOccurred(), fmt.Sprintf("Failed to convert pod identity to an integer (%s)", err))
			return fmt.Sprintf("%d %d %d %d",
				identity&0xff,
				(identity>>8)&0xff,
				(identity>>16)&0xff,
				(identity>>24)&0xff)
		}

		extractCounterValue := func(output string) uint {
			var count uint64 = 0
			byteString := strings.TrimSpace(output)
			bytes := strings.Split(byteString, "\n")
			for i, b := range bytes {
				dec, err := strconv.ParseUint(b, 0, 8)
				ExpectWithOffset(3, err).ToNot(HaveOccurred(),
					fmt.Sprintf("Failed to convert byte-counter value to an integer (%s from %q): %s", b, bytes, err))
				count += dec << (i * 8)
			}
			return uint(count)
		}

		checkOneDirection := func(endpointId int64, ciliumPod string,
			clientName string, serverIP string, serverIdentity string,
			direction customCallDirection, expectedCount uint) {

			By("Updating call map with reference to custom program")

			cmd := fmt.Sprintf("bpftool map update pinned %scilium_calls_custom_%05d key %d 0 0 0 value pinned %s",
				bpffsDir, endpointId, direction, progPinPath)
			res := kubectl.ExecPodCmd(helpers.KubeSystemNamespace, ciliumPod, cmd)
			res.ExpectSuccess("Failed to update call map with reference to custom program")

			By("Sending traffic between the pods")

			cmd = helpers.Ping(serverIP)
			res = kubectl.ExecPodCmd(helpers.DefaultNamespace, clientName, cmd)
			res.ExpectSuccess(fmt.Sprintf("Failed to ping from %s to %s", clientName, serverIP))

			By("Retrieving counter value")

			cmd = fmt.Sprintf("bpftool -j map lookup pinned %s key %s | jq -r '.value[]'", mapPinPath, serverIdentity)
			res = kubectl.ExecPodCmd(helpers.KubeSystemNamespace, ciliumPod, cmd)
			res.ExpectSuccess("Failed to lookup byte-counter value")

			// Output from bpftool is on the form
			// "0x11\n0x22\n0x33\n...0x88\n", convert it.
			// Too bad bpftool returns hex that jq doesn't know how
			// to convert yet.
			count := extractCounterValue(res.Stdout())

			By("Checking counter value")

			ExpectWithOffset(2, count).To(Equal(expectedCount),
				fmt.Sprintf("Byte count (%d) differs from expected value (%d)", count, expectedCount))
		}

		getMissedCustomCallsCount := func(ciliumPod string,
			direction string) int {

			cmd := fmt.Sprintf("cilium bpf metrics list -o jsonpath='{$[?(@.reason==11)].values.%s.packets}'", direction)
			res := kubectl.ExecPodCmd(helpers.KubeSystemNamespace, ciliumPod, cmd)
			res.ExpectSuccess("Failed to lookup metrics for missed tail calls to custom programs")

			// If the metrics is missing from the output, consider
			// it is a zero value
			output := strings.TrimSpace(res.Stdout())
			if output == "" {
				return 0
			}

			count, err := strconv.Atoi(output)
			ExpectWithOffset(2, err).ToNot(HaveOccurred(),
				fmt.Sprintf("Failed to convert metrics value: %s", err))
			return count
		}

		cleanupByteCounter := func(endpointId int64, ciliumPod string,
			serverIdentity string, direction customCallDirection) {

			// Clean up tail call map entry
			cmd := fmt.Sprintf("bpftool map delete pinned %scilium_calls_custom_%05d key %d 0 0 0", bpffsDir, endpointId, direction)
			res := kubectl.ExecPodCmd(helpers.KubeSystemNamespace, ciliumPod, cmd)
			if res.GetExitCode() != 0 {
				log.Warningf("Failed to remove reference to byte-counter program from tail call map ('%s'): %s", cmd, res.Stderr())
			}

			// Reset byte-counter entry
			cmd = fmt.Sprintf("bpftool map delete pinned %s key %s", mapPinPath, serverIdentity)
			res = kubectl.ExecPodCmd(helpers.KubeSystemNamespace, ciliumPod, cmd)
			if res.GetExitCode() != 0 {
				log.Warningf("Failed to delete entry from byte-counter map ('%s'): %s", cmd, res.Stderr())
			}
		}

		cleanupLoadedObjects := func(ciliumPod string) {
			By("Cleaning up pinned artefacts")

			// Clean up custom program
			cmd := "rm -- " + progPinPath
			res := kubectl.ExecPodCmd(helpers.KubeSystemNamespace, ciliumPod, cmd)
			if res.GetExitCode() != 0 {
				log.Warningf("Failed to unpin byte-counter program ('%s'): %s", cmd, res.Stderr())
			}

			// Clean up map for custom program
			cmd = "rm -- " + mapPinPath
			res = kubectl.ExecPodCmd(helpers.KubeSystemNamespace, ciliumPod, cmd)
			if res.GetExitCode() != 0 {
				log.Warningf("Failed to unpin byte-counter map ('%s'): %s", cmd, res.Stderr())
			}
			cmd = "rmdir -- " + mapsPinDir
			res = kubectl.ExecPodCmd(helpers.KubeSystemNamespace, ciliumPod, cmd)
			if res.GetExitCode() != 0 {
				log.Warningf("Failed to remove directory for byte-counter pinned map ('%s'): %s", cmd, res.Stderr())
			}
		}

		checkByteCounter := func(ciliumOptions map[string]string,
			expectedCountIngress, expectedCountEgress uint,
			runEgress bool) {

			var metrics = map[string]int{
				"ingress": 0,
				"egress":  0,
			}

			// Deploy Cilium, enable tail calls to custom programs
			deploymentManager.DeployCilium(ciliumOptions, DeployCiliumOptionsAndDNS)

			ciliumPodK8s1, err := kubectl.GetCiliumPodOnNode(helpers.K8s1)
			ExpectWithOffset(1, err).ShouldNot(HaveOccurred(), "Cannot get cilium pod on k8s1")
			ciliumPodK8s2, err := kubectl.GetCiliumPodOnNode(helpers.K8s2)
			ExpectWithOffset(1, err).ShouldNot(HaveOccurred(), "Cannot get cilium pod on k8s2")

			installPods()

			copyAndLoadObjectFile(ciliumPodK8s2)
			defer cleanupLoadedObjects(ciliumPodK8s2)

			getPodsInfo()

			// Get ID for the endpoint for which we count the bytes
			endpoint, err := kubectl.GetCiliumEndpoint(helpers.DefaultNamespace, podApp2.Name)
			ExpectWithOffset(1, err).Should(BeNil(), fmt.Sprintf("Failed to retrieve endpoint for pod %s: %s", podApp2.Name, err))
			ExpectWithOffset(1, endpoint).ShouldNot(BeNil(), fmt.Sprintf("Retrieved empty endpoint id for pod %s", podApp2.Name))
			endpointId := endpoint.ID

			// Get the identity of the pod with which the monitored
			// pod communicates. This identity is used as a key in
			// the byte-counter hash map.
			identityKey := getIdentityKey("k8s:id=app1", ciliumPodK8s1)

			// Collect initial value for metrics on skipped tail
			// calls to custom programs
			for direction := range metrics {
				metrics[direction] = getMissedCustomCallsCount(ciliumPodK8s2, direction)
			}

			err = kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", helpers.HelperTimeout)
			ExpectWithOffset(1, err).Should(BeNil())

			By("Attaching a program on ingress side (IPv4)")

			checkOneDirection(endpointId, ciliumPodK8s2, podApp2.Name,
				podApp1.Status.PodIP, identityKey, IngressIPv4,
				expectedCountIngress)
			cleanupByteCounter(endpointId, ciliumPodK8s2, identityKey, IngressIPv4)

			if !runEgress {
				return
			}

			By("Attaching a program on egress side (IPv4)")

			checkOneDirection(endpointId, ciliumPodK8s2, podApp2.Name,
				podApp1.Status.PodIP, identityKey, EgressIPv4,
				expectedCountEgress)
			cleanupByteCounter(endpointId, ciliumPodK8s2, identityKey, EgressIPv4)

			By("Making sure metrics for skipped calls to custom programs are incremented")

			// We expect the value to have raised for both
			// directions, even if we have a program attached. This
			// is because the metrics is common to all tail calls
			// to custom programs, for all endpoints (the only
			// distinction is ingress/egress), and other endpoints
			// in our network do not have custom programs attached.
			for direction, current := range metrics {
				metrics[direction] = getMissedCustomCallsCount(ciliumPodK8s2, direction) - current
				ExpectWithOffset(1, metrics[direction]).To(BeNumerically(">", 0),
					fmt.Sprintf("Value not incremented (delta: %d) for %s metrics for skipped calls", metrics[direction], direction))
			}
		}

		It("Loads byte-counter and gets consistent values", func() {
			options := map[string]string{
				"customCalls.enabled": "true",
			}
			checkByteCounter(options, pingBytes, pingBytes, true)
		})

		// Check the ingress hook in tail_ipv4_to_endpoint()
		// Similar to the above, with endpointRoutes enabled
		It("Loads byte-counter and gets consistent values, with per-endpoint routes", func() {
			options := map[string]string{
				"customCalls.enabled":    "true",
				"endpointRoutes.enabled": "true",
			}
			checkByteCounter(options, pingBytes, 0, false)
		})
	})
})
