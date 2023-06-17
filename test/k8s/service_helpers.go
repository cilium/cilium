// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8sTest

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
)

func getHTTPLink(host string, port int32) string {
	return fmt.Sprintf("http://%s",
		net.JoinHostPort(host, fmt.Sprintf("%d", port)))
}

func getTFTPLink(host string, port int32) string {
	// TFTP requires a filename. Otherwise the packet will be
	// silently dropped by the server.
	return fmt.Sprintf("tftp://%s/hello",
		net.JoinHostPort(host, fmt.Sprintf("%d", port)))
}

func applyPolicy(kubectl *helpers.Kubectl, path string) {
	By(fmt.Sprintf("Applying policy %s", path))
	_, err := kubectl.CiliumPolicyAction(helpers.DefaultNamespace, path, helpers.KubectlApply, helpers.HelperTimeout)
	ExpectWithOffset(1, err).Should(BeNil(), fmt.Sprintf("Error creating resource %s: %s", path, err))
}

func ciliumAddService(kubectl *helpers.Kubectl, id int64, frontend string, backends []string, svcType, trafficPolicy string) {
	ciliumPods, err := kubectl.GetCiliumPods()
	ExpectWithOffset(1, err).To(BeNil(), "Cannot get cilium pods")
	for _, pod := range ciliumPods {
		err := kubectl.CiliumServiceAdd(pod, id, frontend, backends, svcType, trafficPolicy)
		ExpectWithOffset(1, err).To(BeNil(), "Failed to add cilium service")
	}
}

func ciliumDelService(kubectl *helpers.Kubectl, id int64) {
	ciliumPods, err := kubectl.GetCiliumPods()
	ExpectWithOffset(1, err).To(BeNil(), "Cannot get cilium pods")
	for _, pod := range ciliumPods {
		// ignore result so tear down still continues on failures
		_ = kubectl.CiliumServiceDel(pod, id)
	}
}

var newlineRegexp = regexp.MustCompile(`\n[ \t\n]*`)

func trimNewlines(script string) string {
	return newlineRegexp.ReplaceAllLiteralString(script, " ")
}

// Return a command string for bash test loop.
func testCommand(cmd string, count, fails int) string {
	// Repeat 'cmd' 'count' times, while recording return codes of failed invocations.
	// Successful cmd exit values are also echoed for debugging this script itself.
	// Prints "failed:" followed by colon separated list of command ordinals and exit codes.
	// Returns success (0) if no more than 'fails' rounds fail, otherwise returns 42.
	//
	// Note: All newlines and the following whitespace is removed from the script below.
	//       This requires explicit semicolons also at the ends of lines!
	return trimNewlines(fmt.Sprintf(
		`/usr/bin/env bash -c
			'fails="";
			id=$RANDOM;
			for i in $(seq 1 %d); do
			  if %s -H "User-Agent: cilium-test-$id/$i"; then
			    echo "Test round $id/$i exit code: $?";
			  else
			    fails=$fails:$id/$i=$?;
			  fi;
			done;
			if [ -n "$fails" ]; then
			  echo "failed: $fails";
			fi;
			cnt="${fails//[^:]}";
			if [ ${#cnt} -gt %d ]; then
			  exit 42;
			fi'`,
		count, cmd, fails))
}

func testCurlFromPods(kubectl *helpers.Kubectl, clientPodLabel, url string, count, fails int) {
	pods, err := kubectl.GetPodNames(helpers.DefaultNamespace, clientPodLabel)
	ExpectWithOffset(1, err).Should(BeNil(), "cannot retrieve pod names by filter %q", clientPodLabel)
	cmd := testCommand(helpers.CurlFailNoStats(url), count, fails)
	for _, pod := range pods {
		By("Making %d curl requests from %s pod to service %s", count, pod, url)
		res := kubectl.ExecPodCmd(helpers.DefaultNamespace, pod, cmd)
		ExpectWithOffset(1, res).Should(helpers.CMDSuccess(), "Request from %s pod to service %s failed", pod, url)
	}
}

func testCurlFromPodWithSourceIPCheck(kubectl *helpers.Kubectl, clientPodLabel, url string, count int, sourceIP string) {
	var cmd string

	pods, err := kubectl.GetPodNames(helpers.DefaultNamespace, clientPodLabel)
	ExpectWithOffset(1, err).Should(BeNil(), "cannot retrieve pod names by filter %s", clientPodLabel)

	By("Making %d HTTP requests from pods(%v) to %s", count, pods, url)
	for _, pod := range pods {
		for i := 1; i <= count; i++ {
			cmd = helpers.CurlFail(url)
			if sourceIP != "" {
				cmd += " | grep client_address="
			}

			res := kubectl.ExecPodCmd(helpers.DefaultNamespace, pod, cmd)
			ExpectWithOffset(1, res).Should(helpers.CMDSuccess(),
				"Can not connect to url %q from pod(%s)", url, pod)
			if sourceIP != "" {
				// Parse the IPs to avoid issues with 4-in-6 formats
				ipStr := strings.TrimSpace(strings.Split(res.Stdout(), "=")[1])
				outIP, err := netip.ParseAddr(ipStr)
				ExpectWithOffset(1, err).Should(BeNil(), "Cannot parse IP %q", ipStr)
				srcIP, err := netip.ParseAddr(sourceIP)
				ExpectWithOffset(1, err).Should(BeNil(), "Cannot parse IP %q", sourceIP)
				ExpectWithOffset(1, outIP).To(Equal(srcIP))
			}
		}
	}
}

func testCurlFromPodsFail(kubectl *helpers.Kubectl, clientPodLabel, url string) {
	pods, err := kubectl.GetPodNames(helpers.DefaultNamespace, clientPodLabel)
	ExpectWithOffset(1, err).Should(BeNil(), "cannot retrieve pod names by filter %q", clientPodLabel)
	for _, pod := range pods {
		res := kubectl.ExecPodCmd(
			helpers.DefaultNamespace, pod,
			helpers.CurlFail(url))
		ExpectWithOffset(1, res).ShouldNot(helpers.CMDSuccess(),
			"Pod %q can unexpectedly connect to service %q", pod, url)
	}
}

func curlClusterIPFromExternalHost(kubectl *helpers.Kubectl, ni *helpers.NodesInfo) *helpers.CmdRes {
	clusterIP, _, err := kubectl.GetServiceHostPort(helpers.DefaultNamespace, appServiceName)
	ExpectWithOffset(1, err).Should(BeNil(), "Cannot get service %s", appServiceName)
	_, err = netip.ParseAddr(clusterIP)
	ExpectWithOffset(1, err).Should(BeNil(), "Cannot parse IP %q", clusterIP)
	httpSVCURL := fmt.Sprintf("http://%s/", net.JoinHostPort(clusterIP, "80"))

	By("testing external connectivity via cluster IP %s", clusterIP)

	status := kubectl.ExecInHostNetNS(context.TODO(), ni.K8s1NodeName, helpers.CurlFail(httpSVCURL))
	ExpectWithOffset(1, status).Should(helpers.CMDSuccess(), "cannot curl to service IP from host: %s", status.CombineOutput())

	return kubectl.ExecInHostNetNS(context.TODO(), ni.OutsideNodeName, helpers.CurlFail(httpSVCURL))
}

func waitPodsDs(kubectl *helpers.Kubectl, groups []string) {
	for _, pod := range groups {
		err := kubectl.WaitforPods(helpers.DefaultNamespace, fmt.Sprintf("-l %s", pod), helpers.HelperTimeout)
		ExpectWithOffset(1, err).Should(BeNil())
	}
}

func testCurlFromPodInHostNetNS(kubectl *helpers.Kubectl, url string, count, fails int, fromPod string) {
	By("Making %d curl requests from pod (host netns) %s to %q", count, fromPod, url)
	cmd := testCommand(helpers.CurlFailNoStats(url), count, fails)
	res := kubectl.ExecInHostNetNS(context.TODO(), fromPod, cmd)
	ExpectWithOffset(1, res).Should(helpers.CMDSuccess(),
		"Request from %s to service %s failed", fromPod, url)
}

func testCurlFailFromPodInHostNetNS(kubectl *helpers.Kubectl, url string, count int, fromPod string) {
	By("Making %d curl requests from %s to %q", count, fromPod, url)
	for i := 1; i <= count; i++ {
		res := kubectl.ExecInHostNetNS(context.TODO(), fromPod, helpers.CurlFail(url))
		ExpectWithOffset(1, res).ShouldNot(helpers.CMDSuccess(),
			"%s host unexpectedly connected to service %q, it should fail", fromPod, url)
	}
}

func failBind(kubectl *helpers.Kubectl, addr string, port int32, proto, fromPod string) {
	By("Trying to bind NodePort addr %q:%d on %s", addr, port, fromPod)
	res := kubectl.ExecInHostNetNS(context.TODO(), fromPod,
		helpers.PythonBind(addr, uint16(port), proto))
	ExpectWithOffset(2, res).ShouldNot(helpers.CMDSuccess(),
		"%s host unexpectedly was able to bind on %q:%d, it should fail", fromPod, addr, port)
}

func testCurlFromPodInHostNetNSExpectingHTTPCode(kubectl *helpers.Kubectl, url string, count int, expectedCode string, fromPod string) {
	By("Making %d HTTP requests from %s to %q, expecting HTTP %s", count, fromPod, url, expectedCode)
	for i := 1; i <= count; i++ {
		res := kubectl.ExecInHostNetNS(context.TODO(), fromPod, helpers.CurlWithHTTPCode(url))
		ExpectWithOffset(1, res).Should(helpers.CMDSuccess(),
			"%s host can not connect to service %q", fromPod, url)
		res.ExpectContains(expectedCode, "Request from %s to %q returned HTTP Code %q, expected %q",
			fromPod, url, res.GetStdOut(), expectedCode)
	}
}

func testCurlFromOutsideWithLocalPort(kubectl *helpers.Kubectl, ni *helpers.NodesInfo, url string, count int, checkSourceIP bool, fromPort int) {
	var cmd string

	By("Making %d HTTP requests from outside cluster (using port %d) to %q", count, fromPort, url)
	for i := 1; i <= count; i++ {
		if fromPort == 0 {
			cmd = helpers.CurlFail(url)
		} else {
			cmd = helpers.CurlFail("--local-port %d %s", fromPort, url)
		}
		if checkSourceIP {
			cmd += " | grep client_address="
		}
		res := kubectl.ExecInHostNetNS(context.TODO(), ni.OutsideNodeName, cmd)
		ExpectWithOffset(1, res).Should(helpers.CMDSuccess(),
			"Can not connect to service %q from outside cluster (%d/%d)", url, i, count)
		if checkSourceIP {
			// Parse the IPs to avoid issues with 4-in-6 formats
			ipStr := strings.TrimSpace(strings.Split(res.Stdout(), "=")[1])
			sourceIP, err := netip.ParseAddr(ipStr)
			ExpectWithOffset(1, err).Should(BeNil(), "Cannot parse IP %q", ipStr)
			var outIP netip.Addr
			switch {
			case sourceIP.Is4():
				outIP, err = netip.ParseAddr(ni.OutsideIP)
				ExpectWithOffset(1, err).Should(BeNil(), "Cannot parse IPv4 address %q", ni.OutsideIP)
			case sourceIP.Is4In6():
				outIP, err = netip.ParseAddr(ni.OutsideIP)
				ExpectWithOffset(1, err).Should(BeNil(), "Cannot parse IPv4-mapped IPv6 address %q", ni.OutsideIP)
			default:
				outIP, err = netip.ParseAddr(ni.OutsideIPv6)
				ExpectWithOffset(1, err).Should(BeNil(), "Cannot parse IPv6 address %q", ni.OutsideIP)
			}
			ExpectWithOffset(1, sourceIP).To(Equal(outIP))
		}
	}
}

func testCurlFailFromOutside(kubectl *helpers.Kubectl, ni *helpers.NodesInfo, url string, count int) {
	By("Making %d HTTP requests from outside cluster to %q", count, url)
	for i := 1; i <= count; i++ {
		res := kubectl.ExecInHostNetNS(context.TODO(), ni.OutsideNodeName, helpers.CurlFail(url))
		ExpectWithOffset(1, res).ShouldNot(helpers.CMDSuccess(),
			"%s host unexpectedly connected to service %q, it should fail", ni.OutsideNodeName, url)
	}
}

func testCurlFromOutside(kubectl *helpers.Kubectl, ni *helpers.NodesInfo, url string, count int, checkSourceIP bool) {
	testCurlFromOutsideWithLocalPort(kubectl, ni, url, count, checkSourceIP, 0)
}

// srcPod:     Name of pod sending the datagram
// srcPort:    Source UDP port (should be different for each doFragmentRequest invocation to allow distinct CT table entries)
// dstPodIP:   Receiver pod IP (for checking in CT table)
// dstPodPort: Receiver pod port (for checking in CT table)
// dstIP:      Target endpoint IP for sending the datagram
// dstPort:    Target endpoint port for sending the datagram
// hasDNAT:    True if DNAT is used for target IP and port
func doFragmentedRequest(kubectl *helpers.Kubectl, srcPod string, srcPort, dstPodPort int, dstIP string, dstPort int32, hasDNAT bool) {
	var (
		blockSize  = 5120
		blockCount = 1
	)
	ciliumPodK8s1, err := kubectl.GetCiliumPodOnNode(helpers.K8s1)
	ExpectWithOffset(2, err).Should(BeNil(), "Cannot get cilium pod on k8s1")
	ciliumPodK8s2, err := kubectl.GetCiliumPodOnNode(helpers.K8s2)
	ExpectWithOffset(2, err).Should(BeNil(), "Cannot get cilium pod on k8s2")

	_, dstPodIPK8s1 := kubectl.GetPodOnNodeLabeledWithOffset(helpers.K8s1, testDS, 1)
	_, dstPodIPK8s2 := kubectl.GetPodOnNodeLabeledWithOffset(helpers.K8s2, testDS, 1)

	// Get initial number of packets for the flow we test
	// from conntrack table. The flow is probably not in
	// the table the first time we check, so do not stop if
	// Atoi() throws an error and simply consider we have 0
	// packets.

	// Field #7 is "RxPackets=<n>"
	cmdIn := "cilium bpf ct list global | awk '/%s/ { sub(\".*=\",\"\", $7); print $7 }'"

	endpointK8s1 := net.JoinHostPort(dstPodIPK8s1, fmt.Sprintf("%d", dstPodPort))
	patternInK8s1 := fmt.Sprintf("UDP IN [^:]+:%d -> %s", srcPort, endpointK8s1)
	cmdInK8s1 := fmt.Sprintf(cmdIn, patternInK8s1)
	res := kubectl.CiliumExecMustSucceed(context.TODO(), ciliumPodK8s1, cmdInK8s1)
	countInK8s1, _ := strconv.Atoi(strings.TrimSpace(res.Stdout()))

	endpointK8s2 := net.JoinHostPort(dstPodIPK8s2, fmt.Sprintf("%d", dstPodPort))
	patternInK8s2 := fmt.Sprintf("UDP IN [^:]+:%d -> %s", srcPort, endpointK8s2)
	cmdInK8s2 := fmt.Sprintf(cmdIn, patternInK8s2)
	res = kubectl.CiliumExecMustSucceed(context.TODO(), ciliumPodK8s2, cmdInK8s2)
	countInK8s2, _ := strconv.Atoi(strings.TrimSpace(res.Stdout()))

	// Field #11 is "TxPackets=<n>"
	cmdOut := "cilium bpf ct list global | awk '/%s/ { sub(\".*=\",\"\", $11); print $11 }'"

	if !hasDNAT {
		// If kube-proxy is enabled, we see packets in ctmap with the
		// service's IP address and port, not backend's.
		dstIPv4 := strings.Replace(dstIP, "::ffff:", "", 1)
		endpointK8s1 = net.JoinHostPort(dstIPv4, fmt.Sprintf("%d", dstPort))
		endpointK8s2 = endpointK8s1
	}
	patternOutK8s1 := fmt.Sprintf("UDP OUT [^:]+:%d -> %s", srcPort, endpointK8s1)
	cmdOutK8s1 := fmt.Sprintf(cmdOut, patternOutK8s1)
	res = kubectl.CiliumExecMustSucceed(context.TODO(), ciliumPodK8s1, cmdOutK8s1)
	countOutK8s1, _ := strconv.Atoi(strings.TrimSpace(res.Stdout()))

	// If kube-proxy is enabled, the two commands are the same and
	// there's no point executing it twice.
	countOutK8s2 := 0
	patternOutK8s2 := fmt.Sprintf("UDP OUT [^:]+:%d -> %s", srcPort, endpointK8s2)
	cmdOutK8s2 := fmt.Sprintf(cmdOut, patternOutK8s2)
	if hasDNAT {
		res = kubectl.CiliumExecMustSucceed(context.TODO(), ciliumPodK8s1, cmdOutK8s2)
		countOutK8s2, _ = strconv.Atoi(strings.TrimSpace(res.Stdout()))
	}

	fragmentedPacketsBeforeK8s1, _ := helpers.GetBPFPacketsCount(kubectl, ciliumPodK8s1, "Fragmented packet", "ingress")
	fragmentedPacketsBeforeK8s2, _ := helpers.GetBPFPacketsCount(kubectl, ciliumPodK8s2, "Fragmented packet", "ingress")

	// Send datagram
	By("Sending a fragmented packet from %s to endpoint %s", srcPod, net.JoinHostPort(dstIP, fmt.Sprintf("%d", dstPort)))
	cmd := fmt.Sprintf("bash -c 'dd if=/dev/zero bs=%d count=%d | nc -u -w 1 -p %d %s %d'", blockSize, blockCount, srcPort, dstIP, dstPort)
	res = kubectl.ExecPodCmd(helpers.DefaultNamespace, srcPod, cmd)
	ExpectWithOffset(1, res).Should(helpers.CMDSuccess(),
		"Cannot send fragmented datagram: %s", res.CombineOutput())

	// Let's compute the expected number of packets. First
	// fragment holds 1416 bytes of data under standard
	// conditions for temperature, pressure and MTU.
	// Following ones do not have UDP header: up to 1424
	// bytes of data.
	delta := 1
	if blockSize*blockCount >= 1416 {
		delta += (blockSize*blockCount - 1416) / 1424
		if (blockSize*blockCount-1416)%1424 != 0 {
			delta++
		}
	}

	// Check that the expected packets were processed
	// Because of load balancing we do not know what
	// backend pod received the datagram, so we check for
	// each node.
	res = kubectl.CiliumExecMustSucceed(context.TODO(), ciliumPodK8s1, cmdInK8s1)
	newCountInK8s1, _ := strconv.Atoi(strings.TrimSpace(res.Stdout()))
	res = kubectl.CiliumExecMustSucceed(context.TODO(), ciliumPodK8s2, cmdInK8s2)
	newCountInK8s2, _ := strconv.Atoi(strings.TrimSpace(res.Stdout()))
	ExpectWithOffset(2, []int{newCountInK8s1, newCountInK8s2}).To(SatisfyAny(
		Equal([]int{countInK8s1, countInK8s2 + delta}),
		Equal([]int{countInK8s1 + delta, countInK8s2}),
	), "Failed to account for IPv4 fragments to %s (in)", dstIP)

	res = kubectl.CiliumExecMustSucceed(context.TODO(), ciliumPodK8s1, cmdOutK8s1)
	newCountOutK8s1, _ := strconv.Atoi(strings.TrimSpace(res.Stdout()))
	// If kube-proxy is enabled, the two commands are the same and
	// there's no point executing it twice.
	newCountOutK8s2 := 0
	if hasDNAT {
		res = kubectl.CiliumExecMustSucceed(context.TODO(), ciliumPodK8s1, cmdOutK8s2)
		newCountOutK8s2, _ = strconv.Atoi(strings.TrimSpace(res.Stdout()))
	}
	ExpectWithOffset(2, []int{newCountOutK8s1, newCountOutK8s2}).To(SatisfyAny(
		Equal([]int{countOutK8s1, countOutK8s2 + delta}),
		Equal([]int{countOutK8s1 + delta, countOutK8s2}),
	), "Failed to account for IPv4 fragments to %s (out)", dstIP)

	fragmentedPacketsAfterK8s1, _ := helpers.GetBPFPacketsCount(kubectl, ciliumPodK8s1, "Fragmented packet", "ingress")
	fragmentedPacketsAfterK8s2, _ := helpers.GetBPFPacketsCount(kubectl, ciliumPodK8s2, "Fragmented packet", "ingress")

	ExpectWithOffset(2, []int{fragmentedPacketsAfterK8s1, fragmentedPacketsAfterK8s2}).To(SatisfyAny(
		Equal([]int{fragmentedPacketsBeforeK8s1, fragmentedPacketsBeforeK8s2 + delta}),
		Equal([]int{fragmentedPacketsBeforeK8s1 + delta, fragmentedPacketsBeforeK8s2}),
	), "Failed to account for INGRESS IPv4 fragments to %s in BPF metrics", dstIP)
}

func testNodePort(kubectl *helpers.Kubectl, ni *helpers.NodesInfo, bpfNodePort, testFromOutside bool, fails int) {
	var (
		err          error
		data, v6Data v1.Service
		wg           sync.WaitGroup
	)

	serviceNameIPv4 := "test-nodeport"
	serviceNameIPv6 := "test-nodeport-ipv6"

	err = kubectl.Get(helpers.DefaultNamespace, fmt.Sprintf("service %s", serviceNameIPv4)).Unmarshal(&data)
	ExpectWithOffset(1, err).Should(BeNil(), "Can not retrieve service %q", serviceNameIPv4)

	if helpers.DualStackSupported() {
		err = kubectl.Get(helpers.DefaultNamespace, fmt.Sprintf("service %s", serviceNameIPv6)).Unmarshal(&v6Data)
		ExpectWithOffset(1, err).Should(BeNil(), "Can not retrieve service %q", serviceNameIPv6)
	}

	// These are going to be tested from pods running in their own net namespaces
	testURLsFromPods := []string{
		getHTTPLink(data.Spec.ClusterIP, data.Spec.Ports[0].Port),
		getTFTPLink(data.Spec.ClusterIP, data.Spec.Ports[1].Port),

		getHTTPLink(ni.K8s1IP, data.Spec.Ports[0].NodePort),
		getTFTPLink(ni.K8s1IP, data.Spec.Ports[1].NodePort),

		getHTTPLink("::ffff:"+ni.K8s1IP, data.Spec.Ports[0].NodePort),
		getTFTPLink("::ffff:"+ni.K8s1IP, data.Spec.Ports[1].NodePort),

		getHTTPLink(ni.K8s2IP, data.Spec.Ports[0].NodePort),
		getTFTPLink(ni.K8s2IP, data.Spec.Ports[1].NodePort),

		getHTTPLink("::ffff:"+ni.K8s2IP, data.Spec.Ports[0].NodePort),
		getTFTPLink("::ffff:"+ni.K8s2IP, data.Spec.Ports[1].NodePort),
	}

	if helpers.DualStackSupported() {
		testURLsFromPods = append(testURLsFromPods,
			getHTTPLink(v6Data.Spec.ClusterIP, v6Data.Spec.Ports[0].Port),
			getTFTPLink(v6Data.Spec.ClusterIP, v6Data.Spec.Ports[1].Port),

			getHTTPLink(ni.PrimaryK8s1IPv6, v6Data.Spec.Ports[0].NodePort),
			getTFTPLink(ni.PrimaryK8s1IPv6, v6Data.Spec.Ports[1].NodePort),

			getHTTPLink(ni.PrimaryK8s2IPv6, v6Data.Spec.Ports[0].NodePort),
			getTFTPLink(ni.PrimaryK8s2IPv6, v6Data.Spec.Ports[1].NodePort),
		)
	}

	// There are tested from pods running in the host net namespace
	testURLsFromHosts := []string{
		getHTTPLink(data.Spec.ClusterIP, data.Spec.Ports[0].Port),
		getTFTPLink(data.Spec.ClusterIP, data.Spec.Ports[1].Port),

		getHTTPLink("127.0.0.1", data.Spec.Ports[0].NodePort),
		getTFTPLink("127.0.0.1", data.Spec.Ports[1].NodePort),

		getHTTPLink("::ffff:127.0.0.1", data.Spec.Ports[0].NodePort),
		getTFTPLink("::ffff:127.0.0.1", data.Spec.Ports[1].NodePort),

		getHTTPLink(ni.K8s1IP, data.Spec.Ports[0].NodePort),
		getTFTPLink(ni.K8s1IP, data.Spec.Ports[1].NodePort),

		getHTTPLink("::ffff:"+ni.K8s1IP, data.Spec.Ports[0].NodePort),
		getTFTPLink("::ffff:"+ni.K8s1IP, data.Spec.Ports[1].NodePort),

		getHTTPLink(ni.K8s2IP, data.Spec.Ports[0].NodePort),
		getTFTPLink(ni.K8s2IP, data.Spec.Ports[1].NodePort),

		getHTTPLink("::ffff:"+ni.K8s2IP, data.Spec.Ports[0].NodePort),
		getTFTPLink("::ffff:"+ni.K8s2IP, data.Spec.Ports[1].NodePort),
	}

	if helpers.DualStackSupported() {
		testURLsFromHosts = append(testURLsFromHosts,
			getHTTPLink(v6Data.Spec.ClusterIP, v6Data.Spec.Ports[0].Port),
			getTFTPLink(v6Data.Spec.ClusterIP, v6Data.Spec.Ports[1].Port),

			getHTTPLink(ni.PrimaryK8s1IPv6, v6Data.Spec.Ports[0].NodePort),
			getTFTPLink(ni.PrimaryK8s1IPv6, v6Data.Spec.Ports[1].NodePort),

			getHTTPLink(ni.PrimaryK8s2IPv6, v6Data.Spec.Ports[0].NodePort),
			getTFTPLink(ni.PrimaryK8s2IPv6, v6Data.Spec.Ports[1].NodePort),
		)
	}

	if helpers.RunsOnGKE() {
		k8s1ExternalIP, err := kubectl.GetNodeIPByLabel(helpers.K8s1, true)
		Expect(err).Should(BeNil(), "Cannot retrieve Node External IP for %s", helpers.K8s1)
		k8s2ExternalIP, err := kubectl.GetNodeIPByLabel(helpers.K8s2, true)
		Expect(err).Should(BeNil(), "Cannot retrieve Node External IP for %s", helpers.K8s2)
		testURLsFromPods = append(testURLsFromPods,
			getHTTPLink(k8s1ExternalIP, data.Spec.Ports[0].NodePort),
			getTFTPLink(k8s1ExternalIP, data.Spec.Ports[1].NodePort),
			getHTTPLink(k8s2ExternalIP, data.Spec.Ports[0].NodePort),
			getTFTPLink(k8s2ExternalIP, data.Spec.Ports[1].NodePort),
		)

		// Testing LoadBalancer types subject to bpf_sock.
		lbIP, err := kubectl.GetLoadBalancerIP(helpers.DefaultNamespace, "test-lb", 60*time.Second)
		Expect(err).Should(BeNil(), "Cannot retrieve loadbalancer IP for test-lb")

		testURLsFromHosts = append(testURLsFromHosts, []string{
			getHTTPLink(lbIP, 80),
			getHTTPLink("::ffff:"+lbIP, 80),
		}...)

		testURLsFromPods = append(testURLsFromPods, []string{
			getHTTPLink(lbIP, 80),
			getHTTPLink("::ffff:"+lbIP, 80),
		}...)
	}

	testURLsFromOutside := []string{}
	if testFromOutside {
		// These are tested from external node which does not run
		// cilium-agent (so it's not a subject to bpf_sock)
		testURLsFromOutside = []string{
			getHTTPLink(ni.K8s1IP, data.Spec.Ports[0].NodePort),
			getTFTPLink(ni.K8s1IP, data.Spec.Ports[1].NodePort),

			getHTTPLink(ni.K8s2IP, data.Spec.Ports[0].NodePort),
			getTFTPLink(ni.K8s2IP, data.Spec.Ports[1].NodePort),
		}

		if helpers.DualStackSupported() {
			testURLsFromOutside = append(testURLsFromOutside,
				getHTTPLink(ni.PrimaryK8s1IPv6, v6Data.Spec.Ports[0].NodePort),
				getTFTPLink(ni.PrimaryK8s1IPv6, v6Data.Spec.Ports[1].NodePort),

				getHTTPLink(ni.PrimaryK8s2IPv6, v6Data.Spec.Ports[0].NodePort),
				getTFTPLink(ni.PrimaryK8s2IPv6, v6Data.Spec.Ports[1].NodePort),
			)
		}
	}

	count := 10
	for _, url := range testURLsFromPods {
		wg.Add(1)
		go func(url string) {
			defer GinkgoRecover()
			defer wg.Done()
			testCurlFromPods(kubectl, testDSClient, url, count, fails)
		}(url)
	}
	for _, url := range testURLsFromHosts {
		wg.Add(1)
		go func(url string) {
			defer GinkgoRecover()
			defer wg.Done()
			testCurlFromPodInHostNetNS(kubectl, url, count, fails, ni.K8s1NodeName)
		}(url)
	}
	for _, url := range testURLsFromOutside {
		wg.Add(1)
		go func(url string) {
			defer GinkgoRecover()
			defer wg.Done()
			testCurlFromOutside(kubectl, ni, url, count, false)
		}(url)
	}
	// TODO: IPv6
	if bpfNodePort && helpers.RunsOnNetNextKernel() {
		httpURL := getHTTPLink("127.0.0.1", data.Spec.Ports[0].NodePort)
		tftpURL := getTFTPLink("127.0.0.1", data.Spec.Ports[1].NodePort)
		testCurlFromPodsFail(kubectl, testDSClient, httpURL)
		testCurlFromPodsFail(kubectl, testDSClient, tftpURL)

		if helpers.DualStackSupported() {
			httpURL = getHTTPLink("::1", v6Data.Spec.Ports[0].NodePort)
			tftpURL = getTFTPLink("::1", v6Data.Spec.Ports[1].NodePort)
			testCurlFromPodsFail(kubectl, testDSClient, httpURL)
			testCurlFromPodsFail(kubectl, testDSClient, tftpURL)
		}

		httpURL = getHTTPLink("::ffff:127.0.0.1", data.Spec.Ports[0].NodePort)
		tftpURL = getTFTPLink("::ffff:127.0.0.1", data.Spec.Ports[1].NodePort)
		testCurlFromPodsFail(kubectl, testDSClient, httpURL)
		testCurlFromPodsFail(kubectl, testDSClient, tftpURL)
	}

	wg.Wait()
}

func testExternalIPs(kubectl *helpers.Kubectl, ni *helpers.NodesInfo) {
	var (
		data                v1.Service
		nodePortService     = "test-external-ips"
		nodePortServiceIPv6 = "test-external-ips-ipv6"
	)
	count := 10

	services := map[string]string{
		nodePortService: ni.K8s1IP,
	}
	if helpers.DualStackSupported() {
		services[nodePortServiceIPv6] = ni.PrimaryK8s1IPv6
	}

	for svcName, nodeIP := range services {
		err := kubectl.Get(helpers.DefaultNamespace, fmt.Sprintf("service %s", svcName)).Unmarshal(&data)
		ExpectWithOffset(1, err).Should(BeNil(), "Can not retrieve service %s", svcName)
		svcExternalIP := data.Spec.ExternalIPs[0]

		// Append k8s1 IP addr to the external IPs for testing whether the svc
		// can be reached from within a cluster via k8s1 IP addr
		res := kubectl.Patch(helpers.DefaultNamespace, "service", svcName,
			fmt.Sprintf(`{"spec":{"externalIPs":["%s","%s"]}}`, svcExternalIP, nodeIP))
		ExpectWithOffset(1, res).Should(helpers.CMDSuccess(), "Error patching external IP service with node 1 IP")

		err = kubectl.WaitForServiceFrontend(ni.K8s1NodeName, nodeIP)
		ExpectWithOffset(1, err).Should(BeNil(), "Failed waiting for %s frontend entry on %s", nodeIP, ni.K8s1NodeName)

		httpURL := getHTTPLink(svcExternalIP, data.Spec.Ports[0].Port)
		tftpURL := getTFTPLink(svcExternalIP, data.Spec.Ports[1].Port)

		// Add the route on the outside node to the external IP addr
		res = kubectl.AddIPRoute(ni.OutsideNodeName, svcExternalIP, nodeIP, false)
		ExpectWithOffset(1, res).Should(helpers.CMDSuccess(), "Error removing IP route for %s via %s", svcExternalIP, nodeIP)
		defer func(externalIP, nodeIP string) {
			res := kubectl.DelIPRoute(ni.OutsideNodeName, externalIP, nodeIP)
			ExpectWithOffset(1, res).Should(helpers.CMDSuccess(), "Error removing IP route for %s via %s", externalIP, nodeIP)
		}(svcExternalIP, nodeIP)

		// Should work from outside via the external IP
		testCurlFromOutside(kubectl, ni, httpURL, count, false)
		testCurlFromOutside(kubectl, ni, tftpURL, count, false)
		// Should fail from inside a pod & hostns
		testCurlFromPodsFail(kubectl, testDSClient, httpURL)
		testCurlFromPodsFail(kubectl, testDSClient, tftpURL)
		testCurlFailFromPodInHostNetNS(kubectl, httpURL, 1, ni.K8s1NodeName)
		testCurlFailFromPodInHostNetNS(kubectl, httpURL, 1, ni.K8s1NodeName)
		testCurlFailFromPodInHostNetNS(kubectl, httpURL, 1, ni.K8s2NodeName)
		testCurlFailFromPodInHostNetNS(kubectl, httpURL, 1, ni.K8s2NodeName)
		// However, it should work via the k8s1 IP addr
		httpURL = getHTTPLink(nodeIP, data.Spec.Ports[0].Port)
		tftpURL = getTFTPLink(nodeIP, data.Spec.Ports[1].Port)
		testCurlFromPodInHostNetNS(kubectl, httpURL, count, 0, ni.K8s1NodeName)
		testCurlFromPodInHostNetNS(kubectl, tftpURL, count, 0, ni.K8s1NodeName)
		// TODO(fristonio): fix IPv6 access issue for external IP from non k8s1
		// pod.
		if svcName != nodePortServiceIPv6 {
			testCurlFromPods(kubectl, testDSClient, httpURL, 10, 0)
			testCurlFromPods(kubectl, testDSClient, tftpURL, 10, 0)
		}
	}
}

func testFailBind(kubectl *helpers.Kubectl, ni *helpers.NodesInfo) {
	var data v1.Service

	err := kubectl.Get(helpers.DefaultNamespace, "service test-nodeport").Unmarshal(&data)
	ExpectWithOffset(1, err).Should(BeNil(), "Can not retrieve service")

	// Ensure the NodePort cannot be bound from any redirected address
	failBind(kubectl, "127.0.0.1", data.Spec.Ports[0].NodePort, "tcp", ni.K8s1NodeName)
	failBind(kubectl, "127.0.0.1", data.Spec.Ports[1].NodePort, "udp", ni.K8s1NodeName)
	failBind(kubectl, "", data.Spec.Ports[0].NodePort, "tcp", ni.K8s1NodeName)
	failBind(kubectl, "", data.Spec.Ports[1].NodePort, "udp", ni.K8s1NodeName)

	failBind(kubectl, "::ffff:127.0.0.1", data.Spec.Ports[0].NodePort, "tcp", ni.K8s1NodeName)
	failBind(kubectl, "::ffff:127.0.0.1", data.Spec.Ports[1].NodePort, "udp", ni.K8s1NodeName)
}

func testNodePortExternal(kubectl *helpers.Kubectl, ni *helpers.NodesInfo, testSecondaryNodePortIP, checkTCP, checkUDP bool) {
	type svc struct {
		name   string
		nodeIP string
	}

	var (
		data                v1.Service
		nodePortService     = "test-nodeport"
		nodePortServiceIPv6 = "test-nodeport-ipv6"
	)

	services := []svc{{nodePortService, ni.K8s1IP}}

	if helpers.DualStackSupported() {
		services = append(services, svc{name: nodePortServiceIPv6, nodeIP: ni.PrimaryK8s1IPv6})
	}
	if testSecondaryNodePortIP {
		services = append(services, svc{name: nodePortService, nodeIP: ni.SecondaryK8s1IPv4})
		if helpers.DualStackSupported() {
			services = append(services, svc{name: nodePortServiceIPv6, nodeIP: ni.SecondaryK8s1IPv6})
		}
	}

	for _, svc := range services {
		err := kubectl.Get(helpers.DefaultNamespace, fmt.Sprintf("service %s", svc.name)).Unmarshal(&data)
		ExpectWithOffset(1, err).Should(BeNil(), "Cannot retrieve service")

		httpURL := getHTTPLink(svc.nodeIP, data.Spec.Ports[0].NodePort)
		tftpURL := getTFTPLink(svc.nodeIP, data.Spec.Ports[1].NodePort)

		// Test from external connectivity
		// Note:
		//   In case of SNAT checkSourceIP is false here since the HTTP request
		//   won't have the client IP but the service IP (given the request comes
		//   from the Cilium node to the backend, not from the client directly).
		//   Same in case of Hybrid mode for UDP.
		testCurlFromOutside(kubectl, ni, httpURL, 10, checkTCP)
		testCurlFromOutside(kubectl, ni, tftpURL, 10, checkUDP)

		// Clear CT tables on all Cilium nodes
		kubectl.CiliumExecMustSucceedOnAll(context.TODO(),
			"cilium bpf ct flush global", "Unable to flush CT maps")
	}
}

// fromOutside=true tests session affinity implementation from lb.h, while
// fromOutside=false tests from  bpf_sock.c.
func testSessionAffinity(kubectl *helpers.Kubectl, ni *helpers.NodesInfo, fromOutside, vxlan bool) {
	var (
		data   v1.Service
		dstPod string
		count  = 10
		from   string
		err    error
		res    *helpers.CmdRes

		serviceAffinityServiceIPv4 = "test-affinity"
		serviceAffinityServiceIPv6 = "test-affinity-ipv6"
	)

	services := map[string]string{
		serviceAffinityServiceIPv4: ni.K8s1IP,
	}
	if helpers.DualStackSupported() {
		services[serviceAffinityServiceIPv6] = ni.PrimaryK8s1IPv6
	}

	for svcName, nodeIP := range services {
		err = kubectl.Get(helpers.DefaultNamespace, fmt.Sprintf("service %s", svcName)).Unmarshal(&data)
		ExpectWithOffset(1, err).Should(BeNil(), "Cannot retrieve service %s", svcName)

		httpURL := getHTTPLink(nodeIP, data.Spec.Ports[0].NodePort)
		cmd := helpers.CurlFail(httpURL) + " | grep 'Hostname:' " // pod name is in the hostname

		if fromOutside {
			from = ni.OutsideNodeName
		} else {
			pods, err := kubectl.GetPodNames(helpers.DefaultNamespace, testDSClient)
			ExpectWithOffset(1, err).Should(BeNil(), "cannot retrieve pod names by filter %q", testDSClient)
			from = pods[0]
		}

		// Send 10 requests to the test-affinity and check that the same backend is chosen
		By("Making %d HTTP requests from %s to %q (sessionAffinity)", count, from, httpURL)

		for i := 1; i <= count; i++ {
			if fromOutside {
				res = kubectl.ExecInHostNetNS(context.TODO(), from, cmd)
			} else {
				res = kubectl.ExecPodCmd(helpers.DefaultNamespace, from, cmd)
			}
			ExpectWithOffset(1, res).Should(helpers.CMDSuccess(),
				"Cannot connect to service %q from %s (%d/%d)", httpURL, from, i, count)
			pod := strings.TrimSpace(strings.Split(res.Stdout(), ": ")[1])
			if i == 1 {
				// Retrieve the destination pod from the first request
				dstPod = pod
			} else {
				// Check that destination pod is always the same
				ExpectWithOffset(1, dstPod).To(Equal(pod))
			}
		}

		By("Removing %s pod so that another pod is chosen", dstPod)

		// Delete the pod, and check that a new backend is chosen
		res := kubectl.DeleteResource("pod", dstPod)
		ExpectWithOffset(1, res).Should(helpers.CMDSuccess(), "Unable to delete %s pod", dstPod)

		// Wait until the replacement pod has been provisioned and appeared
		// in the ipcache of the second node.
		//
		// The first wait should give enough time for cilium-agents to remove
		// the deleted pod from the BPF LB maps, so that the next request won't
		// choose the deleted pod.
		waitPodsDs(kubectl, []string{testDS, testDSClient, testDSK8s2})
		// The second wait is needed to make sure that an IPCache entry of the
		// new pod appears on the k8s1 node. Otherwise, if the new pod runs
		// on k8s2 and a request below selects it, the request will be dropped
		// in the vxlan mode (the tailcall IPV4_NODEPORT_NAT body won't pass
		// the request to the encap routines, and instead it will be dropped
		// due to failing fib_lookup).
		if fromOutside && vxlan {
			podIPs, err := kubectl.GetPodsIPs(helpers.DefaultNamespace, testDS)
			ExpectWithOffset(1, err).Should(BeNil(), "Cannot get pod IP addrs for -l %s pods", testDS)
			for _, ipAddr := range podIPs {
				err = kubectl.WaitForIPCacheEntry(helpers.K8s1, ipAddr)
				ExpectWithOffset(1, err).Should(BeNil(), "Failed waiting for %s ipcache entry on k8s1", ipAddr)
			}
		}

		for i := 1; i <= count; i++ {
			if fromOutside {
				res = kubectl.ExecInHostNetNS(context.TODO(), from, cmd)
			} else {
				res = kubectl.ExecPodCmd(helpers.DefaultNamespace, from, cmd)
			}
			ExpectWithOffset(1, res).Should(helpers.CMDSuccess(),
				"Cannot connect to service %q from %s (%d/%d) after restart", httpURL, from, i, count)
			pod := strings.TrimSpace(strings.Split(res.Stdout(), ": ")[1])
			if i == 1 {
				// Retrieve the destination pod from the first request
				ExpectWithOffset(1, dstPod).ShouldNot(Equal(pod))
				dstPod = pod
			} else {
				// Check that destination pod is always the same
				ExpectWithOffset(1, dstPod).To(Equal(pod))
			}
		}
	}
}

func testExternalTrafficPolicyLocal(kubectl *helpers.Kubectl, ni *helpers.NodesInfo) {
	var (
		data    v1.Service
		httpURL string
		tftpURL string

		localNodePortSvcIPv4 = "test-nodeport-local"
		localNodePortSvcIPv6 = "test-nodeport-local-ipv6"

		localNodePortK8s2SvcIpv4 = "test-nodeport-local-k8s2"
		localNodePortK8s2SvcIpv6 = "test-nodeport-local-k8s2-ipv6"
	)

	type nodeInfo struct {
		node1IP, node2IP       string
		localSvc, k8s2LocalSvc string
	}

	services := []nodeInfo{
		{
			ni.K8s1IP,
			ni.K8s2IP,
			localNodePortSvcIPv4,
			localNodePortK8s2SvcIpv4,
		},
	}
	if helpers.DualStackSupported() {
		services = append(services, nodeInfo{
			ni.PrimaryK8s1IPv6,
			ni.PrimaryK8s2IPv6,
			localNodePortSvcIPv6,
			localNodePortK8s2SvcIpv6,
		})
	}

	for _, node := range services {
		// Checks requests are not SNATed when externalTrafficPolicy=Local
		err := kubectl.Get(helpers.DefaultNamespace, fmt.Sprintf("service %s", node.localSvc)).Unmarshal(&data)
		ExpectWithOffset(1, err).Should(BeNil(), "Cannot retrieve service %s", node.localSvc)

		count := 10

		ciliumPodK8s2, err := kubectl.GetCiliumPodOnNode(helpers.K8s2)
		ExpectWithOffset(1, err).Should(BeNil(), "Cannot get cilium pod on k8s2")

		if helpers.ExistNodeWithoutCilium() {
			httpURL = getHTTPLink(node.node1IP, data.Spec.Ports[0].NodePort)
			tftpURL = getTFTPLink(node.node1IP, data.Spec.Ports[1].NodePort)
			testCurlFromOutside(kubectl, ni, httpURL, count, true)
			testCurlFromOutside(kubectl, ni, tftpURL, count, true)
		} else {
			GinkgoPrint("Skipping externalTrafficPolicy=Local test from external node")
		}

		err = kubectl.Get(helpers.DefaultNamespace, fmt.Sprintf("service %s", node.k8s2LocalSvc)).Unmarshal(&data)
		ExpectWithOffset(1, err).Should(BeNil(), "Can not retrieve service %s", node.k8s2LocalSvc)

		// Checks that requests to k8s2 succeed where Pod is also running
		httpURL = getHTTPLink(node.node2IP, data.Spec.Ports[0].NodePort)
		tftpURL = getTFTPLink(node.node2IP, data.Spec.Ports[1].NodePort)
		testCurlFromPodInHostNetNS(kubectl, httpURL, count, 0, ni.K8s1NodeName)
		testCurlFromPodInHostNetNS(kubectl, tftpURL, count, 0, ni.K8s1NodeName)
		testCurlFromPodInHostNetNS(kubectl, httpURL, count, 0, ni.K8s2NodeName)
		testCurlFromPodInHostNetNS(kubectl, tftpURL, count, 0, ni.K8s2NodeName)
		if helpers.ExistNodeWithoutCilium() {
			testCurlFromOutside(kubectl, ni, httpURL, count, true)
			testCurlFromOutside(kubectl, ni, tftpURL, count, true)
		}

		// Local requests should be load-balanced on kube-proxy 1.15+.
		// See kubernetes/kubernetes#77523 for the PR which introduced this
		// behavior on the iptables-backend for kube-proxy.
		httpURL = getHTTPLink(node.node1IP, data.Spec.Ports[0].NodePort)
		tftpURL = getTFTPLink(node.node1IP, data.Spec.Ports[1].NodePort)
		testCurlFromPodInHostNetNS(kubectl, httpURL, count, 0, ni.K8s1NodeName)
		testCurlFromPodInHostNetNS(kubectl, tftpURL, count, 0, ni.K8s1NodeName)
		// In-cluster connectivity from k8s2 to k8s1 IP will still work with
		// SocketLB (regardless of if we are running with or
		// without kube-proxy) since we'll hit the wildcard rule in bpf_sock
		// and k8s1 IP is in ipcache as REMOTE_NODE_ID. But that is fine since
		// it's all in-cluster connectivity w/ client IP preserved.
		// This is a known incompatibility with kube-proxy:
		// kube-proxy 1.15+ will only load-balance requests from k8s1 to k8s1,
		// but not from k8s2 to k8s1. In the k8s2 to k8s1 case, kube-proxy
		// would send traffic to k8s1, where it would be subsequently
		// dropped, because k8s1 has no service backend.
		// If SocketLB is enabled, Cilium does the service
		// translation for ClusterIP services on the client node, bypassing
		// kube-proxy completely. Here, we are probing NodePort service, so we
		// need BPF NodePort to be enabled as well for the requests to succeed.
		socketLB := kubectl.HasSocketLB(ciliumPodK8s2)
		bpfNodePort := kubectl.HasBPFNodePort(ciliumPodK8s2)
		if socketLB && bpfNodePort {
			testCurlFromPodInHostNetNS(kubectl, httpURL, count, 0, ni.K8s2NodeName)
			testCurlFromPodInHostNetNS(kubectl, tftpURL, count, 0, ni.K8s2NodeName)
		} else {
			testCurlFailFromPodInHostNetNS(kubectl, httpURL, 1, ni.K8s2NodeName)
			testCurlFailFromPodInHostNetNS(kubectl, tftpURL, 1, ni.K8s2NodeName)
		}

		// Requests from a non-Cilium node to k8s1 IP will fail though.
		if helpers.ExistNodeWithoutCilium() {
			testCurlFailFromOutside(kubectl, ni, tftpURL, 1)
		}
	}
}

func testHealthCheckNodePort(kubectl *helpers.Kubectl, ni *helpers.NodesInfo) {
	var data v1.Service

	// Service with HealthCheckNodePort that only has backends on k8s2
	err := kubectl.Get(helpers.DefaultNamespace, "service test-lb-local-k8s2").Unmarshal(&data)
	ExpectWithOffset(1, err).Should(BeNil(), "Can not retrieve service")

	count := 10

	// Checks that requests to k8s2 return 200
	url := getHTTPLink(ni.K8s2IP, data.Spec.HealthCheckNodePort)
	testCurlFromPodInHostNetNSExpectingHTTPCode(kubectl, url, count, "200", ni.K8s1NodeName)
	testCurlFromPodInHostNetNSExpectingHTTPCode(kubectl, url, count, "200", ni.K8s2NodeName)

	// Checks that requests to k8s1 return 503 Service Unavailable
	url = getHTTPLink(ni.K8s1IP, data.Spec.HealthCheckNodePort)
	testCurlFromPodInHostNetNSExpectingHTTPCode(kubectl, url, count, "503", ni.K8s1NodeName)
	testCurlFromPodInHostNetNSExpectingHTTPCode(kubectl, url, count, "503", ni.K8s2NodeName)
}

func testIPv4FragmentSupport(kubectl *helpers.Kubectl, ni *helpers.NodesInfo) {
	var (
		data    v1.Service
		srcPort = 12345
		hasDNAT = true
	)
	// Destination address and port for fragmented datagram
	// are not DNAT-ed with kube-proxy but without bpf_sock.
	if helpers.DoesNotRunWithKubeProxyReplacement() {
		ciliumPodK8s1, err := kubectl.GetCiliumPodOnNode(helpers.K8s1)
		ExpectWithOffset(1, err).Should(BeNil(), "Cannot get cilium pod on k8s1")
		hasDNAT = kubectl.HasSocketLB(ciliumPodK8s1)
	}

	// Get testDSClient and testDS pods running on k8s1.
	// This is because we search for new packets in the
	// conntrack table for node k8s1.
	clientPod, _ := kubectl.GetPodOnNodeLabeledWithOffset(helpers.K8s1, testDSClient, 1)

	err := kubectl.Get(helpers.DefaultNamespace, "service test-nodeport").Unmarshal(&data)
	ExpectWithOffset(1, err).Should(BeNil(), "Cannot retrieve service")
	nodePort := data.Spec.Ports[1].NodePort
	serverPort := data.Spec.Ports[1].TargetPort.IntValue()

	// With ClusterIP
	doFragmentedRequest(kubectl, clientPod, srcPort, serverPort, data.Spec.ClusterIP, data.Spec.Ports[1].Port, true)

	// From pod via node IPs
	doFragmentedRequest(kubectl, clientPod, srcPort+1, serverPort, ni.K8s1IP, nodePort, hasDNAT)
	doFragmentedRequest(kubectl, clientPod, srcPort+2, serverPort, "::ffff:"+ni.K8s1IP, nodePort, hasDNAT)
	doFragmentedRequest(kubectl, clientPod, srcPort+3, serverPort, ni.K8s2IP, nodePort, hasDNAT)
	doFragmentedRequest(kubectl, clientPod, srcPort+4, serverPort, "::ffff:"+ni.K8s2IP, nodePort, hasDNAT)
}

func testMaglev(kubectl *helpers.Kubectl, ni *helpers.NodesInfo) {
	var (
		data  v1.Service
		count = 10
	)

	err := kubectl.Get(helpers.DefaultNamespace, "service echo").Unmarshal(&data)
	ExpectWithOffset(1, err).Should(BeNil(), "Cannot retrieve service")

	// Flush CT tables so that any entry with src port 6{0,1,2}000
	// from previous tests with --node-port-algorithm=random
	// won't interfere the backend selection.
	for _, label := range []string{helpers.K8s1, helpers.K8s2} {
		pod, err := kubectl.GetCiliumPodOnNode(helpers.K8s1)
		ExpectWithOffset(1, err).Should(BeNil(), "cannot get cilium pod name %s", label)
		kubectl.CiliumExecMustSucceed(context.TODO(), pod, "cilium bpf ct flush global", "Unable to flush CT maps")
	}

	for _, port := range []int{60000, 61000, 62000} {
		dstPod := ""

		// Send requests from the same IP and port to different nodes, and check
		// that the same backend is selected

		for _, host := range []string{ni.K8s1IP, ni.K8s2IP} {
			url := getTFTPLink(host, data.Spec.Ports[1].NodePort)
			cmd := helpers.CurlFail("--local-port %d %s", port, url) + " | grep 'Hostname:' " // pod name is in the hostname

			By("Making %d HTTP requests from %s:%d to %q", count, ni.OutsideNodeName, port, url)

			for i := 1; i <= count; i++ {
				res := kubectl.ExecInHostNetNS(context.TODO(), ni.OutsideNodeName, cmd)
				ExpectWithOffset(1, res).Should(helpers.CMDSuccess(),
					"Cannot connect to service %q (%d/%d)", url, i, count)
				pod := strings.TrimSpace(strings.Split(res.Stdout(), ": ")[1])
				if dstPod == "" {
					dstPod = pod
				} else {
					ExpectWithOffset(1, dstPod).To(Equal(pod))
				}
			}
		}
	}
}

func testDSR(kubectl *helpers.Kubectl, ni *helpers.NodesInfo, k8s1IP string, k8s2SvcName string, sourcePortForCTGCtest int) {
	var data v1.Service
	err := kubectl.Get(helpers.DefaultNamespace, "service test-nodeport").Unmarshal(&data)
	ExpectWithOffset(1, err).Should(BeNil(), "Cannot retrieve service")
	url := getHTTPLink(ni.K8s1IP, data.Spec.Ports[0].NodePort)
	testCurlFromOutside(kubectl, ni, url, 10, true)

	// Test whether DSR NAT entries are evicted by GC

	pod, err := kubectl.GetCiliumPodOnNode(helpers.K8s2)
	ExpectWithOffset(1, err).Should(BeNil(), "Cannot determine cilium pod name")
	// "test-nodeport-k8s2" because we want to trigger SNAT with a single request:
	// client -> k8s1 -> endpoint @ k8s2.
	err = kubectl.Get(helpers.DefaultNamespace, k8s2SvcName).Unmarshal(&data)
	ExpectWithOffset(1, err).Should(BeNil(), "Cannot retrieve service")
	url = getHTTPLink(k8s1IP, data.Spec.Ports[0].NodePort)

	testCurlFromOutsideWithLocalPort(kubectl, ni, url, 1, true, sourcePortForCTGCtest)
	res := kubectl.CiliumExecContext(context.TODO(), pod, fmt.Sprintf("cilium bpf nat list | grep %d", sourcePortForCTGCtest))
	ExpectWithOffset(1, res.Stdout()).ShouldNot(BeEmpty(), "NAT entry was not found")
	// Flush CT maps to trigger eviction of the NAT entries (simulates CT GC)
	_ = kubectl.CiliumExecMustSucceed(context.TODO(), pod, "cilium bpf ct flush global", "Unable to flush CT maps")
	res = kubectl.CiliumExecContext(context.TODO(), pod, fmt.Sprintf("cilium bpf nat list | grep %d", sourcePortForCTGCtest))
	res.ExpectFail("NAT entry was not evicted")
}
