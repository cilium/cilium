// +build linux

/*
Copyright 2015 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e_node

import (
	"fmt"
	"strings"
	"time"

	clientset "k8s.io/client-go/kubernetes"
	stats "k8s.io/kubernetes/pkg/kubelet/apis/stats/v1alpha1"
	"k8s.io/kubernetes/test/e2e/framework"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = framework.KubeDescribe("Resource-usage [Serial] [Slow]", func() {
	const (
		// Interval to poll /stats/container on a node
		containerStatsPollingPeriod = 10 * time.Second
	)

	var (
		rc *ResourceCollector
		om *framework.RuntimeOperationMonitor
	)

	f := framework.NewDefaultFramework("resource-usage")

	BeforeEach(func() {
		om = framework.NewRuntimeOperationMonitor(f.ClientSet)
		// The test collects resource usage from a standalone Cadvisor pod.
		// The Cadvsior of Kubelet has a housekeeping interval of 10s, which is too long to
		// show the resource usage spikes. But changing its interval increases the overhead
		// of kubelet. Hence we use a Cadvisor pod.
		f.PodClient().CreateSync(getCadvisorPod())
		rc = NewResourceCollector(containerStatsPollingPeriod)
	})

	AfterEach(func() {
		result := om.GetLatestRuntimeOperationErrorRate()
		framework.Logf("runtime operation error metrics:\n%s", framework.FormatRuntimeOperationErrorRate(result))
	})

	// This test measures and verifies the steady resource usage of node is within limit
	// It collects data from a standalone Cadvisor with housekeeping interval 1s.
	// It verifies CPU percentiles and the lastest memory usage.
	Context("regular resource usage tracking", func() {
		rTests := []resourceTest{
			{
				podsNr: 10,
				cpuLimits: framework.ContainersCPUSummary{
					stats.SystemContainerKubelet: {0.50: 0.30, 0.95: 0.35},
					stats.SystemContainerRuntime: {0.50: 0.30, 0.95: 0.40},
				},
				memLimits: framework.ResourceUsagePerContainer{
					stats.SystemContainerKubelet: &framework.ContainerResourceUsage{MemoryRSSInBytes: 200 * 1024 * 1024},
					stats.SystemContainerRuntime: &framework.ContainerResourceUsage{MemoryRSSInBytes: 400 * 1024 * 1024},
				},
			},
		}

		for _, testArg := range rTests {
			itArg := testArg
			desc := fmt.Sprintf("resource tracking for %d pods per node", itArg.podsNr)
			It(desc, func() {
				testInfo := getTestNodeInfo(f, itArg.getTestName(), desc)

				runResourceUsageTest(f, rc, itArg)

				// Log and verify resource usage
				logAndVerifyResource(f, rc, itArg.cpuLimits, itArg.memLimits, testInfo, true)
			})
		}
	})

	Context("regular resource usage tracking", func() {
		rTests := []resourceTest{
			{
				podsNr: 0,
			},
			{
				podsNr: 10,
			},
			{
				podsNr: 35,
			},
			{
				podsNr: 105,
			},
		}

		for _, testArg := range rTests {
			itArg := testArg
			desc := fmt.Sprintf("resource tracking for %d pods per node [Benchmark]", itArg.podsNr)
			It(desc, func() {
				testInfo := getTestNodeInfo(f, itArg.getTestName(), desc)

				runResourceUsageTest(f, rc, itArg)

				// Log and verify resource usage
				logAndVerifyResource(f, rc, itArg.cpuLimits, itArg.memLimits, testInfo, false)
			})
		}
	})
})

type resourceTest struct {
	podsNr    int
	cpuLimits framework.ContainersCPUSummary
	memLimits framework.ResourceUsagePerContainer
}

func (rt *resourceTest) getTestName() string {
	return fmt.Sprintf("resource_%d", rt.podsNr)
}

// runResourceUsageTest runs the resource usage test
func runResourceUsageTest(f *framework.Framework, rc *ResourceCollector, testArg resourceTest) {
	const (
		// The monitoring time for one test
		monitoringTime = 10 * time.Minute
		// The periodic reporting period
		reportingPeriod = 5 * time.Minute
		// sleep for an interval here to measure steady data
		sleepAfterCreatePods = 10 * time.Second
	)
	pods := newTestPods(testArg.podsNr, true, framework.GetPauseImageNameForHostArch(), "test_pod")

	rc.Start()
	// Explicitly delete pods to prevent namespace controller cleanning up timeout
	defer deletePodsSync(f, append(pods, getCadvisorPod()))
	defer rc.Stop()

	By("Creating a batch of Pods")
	f.PodClient().CreateBatch(pods)

	// wait for a while to let the node be steady
	time.Sleep(sleepAfterCreatePods)

	// Log once and flush the stats.
	rc.LogLatest()
	rc.Reset()

	By("Start monitoring resource usage")
	// Periodically dump the cpu summary until the deadline is met.
	// Note that without calling framework.ResourceMonitor.Reset(), the stats
	// would occupy increasingly more memory. This should be fine
	// for the current test duration, but we should reclaim the
	// entries if we plan to monitor longer (e.g., 8 hours).
	deadline := time.Now().Add(monitoringTime)
	for time.Now().Before(deadline) {
		timeLeft := deadline.Sub(time.Now())
		framework.Logf("Still running...%v left", timeLeft)
		if timeLeft < reportingPeriod {
			time.Sleep(timeLeft)
		} else {
			time.Sleep(reportingPeriod)
		}
		logPods(f.ClientSet)
	}

	By("Reporting overall resource usage")
	logPods(f.ClientSet)
}

// logAndVerifyResource prints the resource usage as perf data and verifies whether resource usage satisfies the limit.
func logAndVerifyResource(f *framework.Framework, rc *ResourceCollector, cpuLimits framework.ContainersCPUSummary,
	memLimits framework.ResourceUsagePerContainer, testInfo map[string]string, isVerify bool) {
	nodeName := framework.TestContext.NodeName

	// Obtain memory PerfData
	usagePerContainer, err := rc.GetLatest()
	Expect(err).NotTo(HaveOccurred())
	framework.Logf("%s", formatResourceUsageStats(usagePerContainer))

	usagePerNode := make(framework.ResourceUsagePerNode)
	usagePerNode[nodeName] = usagePerContainer

	// Obtain CPU PerfData
	cpuSummary := rc.GetCPUSummary()
	framework.Logf("%s", formatCPUSummary(cpuSummary))

	cpuSummaryPerNode := make(framework.NodesCPUSummary)
	cpuSummaryPerNode[nodeName] = cpuSummary

	// Print resource usage
	logPerfData(framework.ResourceUsageToPerfDataWithLabels(usagePerNode, testInfo), "memory")
	logPerfData(framework.CPUUsageToPerfDataWithLabels(cpuSummaryPerNode, testInfo), "cpu")

	// Verify resource usage
	if isVerify {
		verifyMemoryLimits(f.ClientSet, memLimits, usagePerNode)
		verifyCPULimits(cpuLimits, cpuSummaryPerNode)
	}
}

func verifyMemoryLimits(c clientset.Interface, expected framework.ResourceUsagePerContainer, actual framework.ResourceUsagePerNode) {
	if expected == nil {
		return
	}
	var errList []string
	for nodeName, nodeSummary := range actual {
		var nodeErrs []string
		for cName, expectedResult := range expected {
			container, ok := nodeSummary[cName]
			if !ok {
				nodeErrs = append(nodeErrs, fmt.Sprintf("container %q: missing", cName))
				continue
			}

			expectedValue := expectedResult.MemoryRSSInBytes
			actualValue := container.MemoryRSSInBytes
			if expectedValue != 0 && actualValue > expectedValue {
				nodeErrs = append(nodeErrs, fmt.Sprintf("container %q: expected RSS memory (MB) < %d; got %d",
					cName, expectedValue, actualValue))
			}
		}
		if len(nodeErrs) > 0 {
			errList = append(errList, fmt.Sprintf("node %v:\n %s", nodeName, strings.Join(nodeErrs, ", ")))
			heapStats, err := framework.GetKubeletHeapStats(c, nodeName)
			if err != nil {
				framework.Logf("Unable to get heap stats from %q", nodeName)
			} else {
				framework.Logf("Heap stats on %q\n:%v", nodeName, heapStats)
			}
		}
	}
	if len(errList) > 0 {
		framework.Failf("Memory usage exceeding limits:\n %s", strings.Join(errList, "\n"))
	}
}

func verifyCPULimits(expected framework.ContainersCPUSummary, actual framework.NodesCPUSummary) {
	if expected == nil {
		return
	}
	var errList []string
	for nodeName, perNodeSummary := range actual {
		var nodeErrs []string
		for cName, expectedResult := range expected {
			perContainerSummary, ok := perNodeSummary[cName]
			if !ok {
				nodeErrs = append(nodeErrs, fmt.Sprintf("container %q: missing", cName))
				continue
			}
			for p, expectedValue := range expectedResult {
				actualValue, ok := perContainerSummary[p]
				if !ok {
					nodeErrs = append(nodeErrs, fmt.Sprintf("container %q: missing percentile %v", cName, p))
					continue
				}
				if actualValue > expectedValue {
					nodeErrs = append(nodeErrs, fmt.Sprintf("container %q: expected %.0fth%% usage < %.3f; got %.3f",
						cName, p*100, expectedValue, actualValue))
				}
			}
		}
		if len(nodeErrs) > 0 {
			errList = append(errList, fmt.Sprintf("node %v:\n %s", nodeName, strings.Join(nodeErrs, ", ")))
		}
	}
	if len(errList) > 0 {
		framework.Failf("CPU usage exceeding limits:\n %s", strings.Join(errList, "\n"))
	}
}

func logPods(c clientset.Interface) {
	nodeName := framework.TestContext.NodeName
	podList, err := framework.GetKubeletRunningPods(c, nodeName)
	if err != nil {
		framework.Logf("Unable to retrieve kubelet pods for node %v", nodeName)
	}
	framework.Logf("%d pods are running on node %v", len(podList.Items), nodeName)
}
