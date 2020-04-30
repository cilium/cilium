// Copyright 2017-2020 Authors of Cilium
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
	"strconv"
	"strings"
	"time"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	"github.com/asaskevich/govalidator"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
)

var _ = Describe("K8sServicesTest", func() {
	var (
		kubectl *helpers.Kubectl

		ciliumFilename         string
		serviceName                               = "app1-service"
		backgroundCancel       context.CancelFunc = func() { return }
		backgroundError        error
		enableBackgroundReport = true
		ciliumPodK8s1          string
		testDSClient           = "zgroup=testDSClient"
		testDS                 = "zgroup=testDS"
		testDSK8s2             = "zgroup=test-k8s2"
		echoServiceName        = "echo"
		echoPodLabel           = "name=echo"
	)

	applyPolicy := func(path string) {
		By(fmt.Sprintf("Applying policy %s", path))
		_, err := kubectl.CiliumPolicyAction(helpers.DefaultNamespace, path, helpers.KubectlApply, helpers.HelperTimeout)
		ExpectWithOffset(1, err).Should(BeNil(), fmt.Sprintf("Error creating resource %s: %s", path, err))
	}

	BeforeAll(func() {
		var err error

		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
		DeployCiliumAndDNS(kubectl, ciliumFilename)

		ciliumPodK8s1, err = kubectl.GetCiliumPodOnNodeWithLabel(helpers.CiliumNamespace, helpers.K8s1)
		Expect(err).Should(BeNil(), "Cannot get cilium pod on k8s1")
	})

	AfterFailed(func() {
		kubectl.CiliumReport(helpers.CiliumNamespace,
			"cilium service list",
			"cilium endpoint list")
	})

	JustBeforeEach(func() {
		if enableBackgroundReport {
			backgroundCancel, backgroundError = kubectl.BackgroundReport("uptime")
			Expect(backgroundError).To(BeNil(), "Cannot start background report process")
		}
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
		backgroundCancel()
	})

	AfterEach(func() {
		ExpectAllPodsTerminated(kubectl)
	})

	AfterAll(func() {
		kubectl.DeleteCiliumDS()
		ExpectAllPodsTerminated(kubectl)
		kubectl.CloseSSHClient()
	})

	ciliumIPv6Backends := func(label string, port string) (backends []string) {
		ciliumPods, err := kubectl.GetCiliumPods(helpers.CiliumNamespace)
		Expect(err).To(BeNil(), "Cannot get cilium pods")
		for _, pod := range ciliumPods {
			endpointIPs := kubectl.CiliumEndpointIPv6(pod, label)
			for _, ip := range endpointIPs {
				backends = append(backends, net.JoinHostPort(ip, port))
			}
		}
		Expect(backends).To(Not(BeEmpty()), "Cannot find any IPv6 backends")
		return backends
	}

	ciliumAddService := func(id int64, frontend string, backends []string, svcType, trafficPolicy string) {
		ciliumPods, err := kubectl.GetCiliumPods(helpers.CiliumNamespace)
		Expect(err).To(BeNil(), "Cannot get cilium pods")
		for _, pod := range ciliumPods {
			err := kubectl.CiliumServiceAdd(pod, id, frontend, backends, svcType, trafficPolicy)
			Expect(err).To(BeNil(), "Failed to add cilium service")
		}
	}

	ciliumDelService := func(id int64) {
		ciliumPods, err := kubectl.GetCiliumPods(helpers.CiliumNamespace)
		Expect(err).To(BeNil(), "Cannot get cilium pods")
		for _, pod := range ciliumPods {
			// ignore result so tear down still continues on failures
			_ = kubectl.CiliumServiceDel(pod, id)
		}
	}

	testCurlRequest := func(clientPodLabel, url string) {
		pods, err := kubectl.GetPodNames(helpers.DefaultNamespace, clientPodLabel)
		ExpectWithOffset(1, err).Should(BeNil(), "cannot retrieve pod names by filter %q", testDSClient)
		// A DS with client is running in each node. So we try from each node
		// that can connect to the service.  To make sure that the cross-node
		// service connectivity is correct we tried 10 times, so balance in the
		// two nodes
		for _, pod := range pods {
			tries := 10
			By("Making %d curl requests from %q to %q", tries, pod, url)
			for i := 1; i <= tries; i++ {
				res := kubectl.ExecPodCmd(
					helpers.DefaultNamespace, pod,
					helpers.CurlFail(url))
				ExpectWithOffset(1, res).Should(helpers.CMDSuccess(),
					"Pod %q can not connect to service %q (failed in request %d/%d)",
					pod, url, i, tries)
			}
		}
	}

	testCurlRequestFail := func(clientPodLabel, url string) {
		pods, err := kubectl.GetPodNames(helpers.DefaultNamespace, clientPodLabel)
		ExpectWithOffset(1, err).Should(BeNil(), "cannot retrieve pod names by filter %q", testDSClient)
		for _, pod := range pods {
			res := kubectl.ExecPodCmd(
				helpers.DefaultNamespace, pod,
				helpers.CurlFail(url))
			ExpectWithOffset(1, res).ShouldNot(helpers.CMDSuccess(),
				"Pod %q can unexpectedly connect to service %q", pod, url)
		}
	}

	waitPodsDs := func() {
		groups := []string{testDS, testDSClient, testDSK8s2}
		for _, pod := range groups {
			err := kubectl.WaitforPods(helpers.DefaultNamespace, fmt.Sprintf("-l %s", pod), helpers.HelperTimeout)
			ExpectWithOffset(1, err).Should(BeNil())
		}
	}

	Context("Checks ClusterIP Connectivity", func() {

		var (
			demoYAML    string
			echoSVCYAML string
		)

		BeforeAll(func() {

			demoYAML = helpers.ManifestGet(kubectl.BasePath(), "demo.yaml")
			echoSVCYAML = helpers.ManifestGet(kubectl.BasePath(), "echo-svc.yaml")
		})

		BeforeEach(func() {
			res := kubectl.ApplyDefault(demoYAML)
			res.ExpectSuccess("unable to apply %s", demoYAML)
			res = kubectl.ApplyDefault(echoSVCYAML)
			res.ExpectSuccess("unable to apply %s", echoSVCYAML)
		})

		AfterEach(func() {
			// Explicitly ignore result of deletion of resources to avoid incomplete
			// teardown if any step fails.
			_ = kubectl.Delete(demoYAML)
			_ = kubectl.Delete(echoSVCYAML)
		})

		It("Checks service on same node", func() {
			err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", helpers.HelperTimeout)
			Expect(err).Should(BeNil())
			clusterIP, _, err := kubectl.GetServiceHostPort(helpers.DefaultNamespace, serviceName)
			Expect(err).Should(BeNil(), "Cannot get service %s", serviceName)
			Expect(govalidator.IsIP(clusterIP)).Should(BeTrue(), "ClusterIP is not an IP")

			By("testing connectivity via cluster IP %s", clusterIP)
			monitorRes, monitorCancel := kubectl.MonitorStart(helpers.CiliumNamespace, ciliumPodK8s1)
			defer func() {
				monitorCancel()
				helpers.WriteToReportFile(monitorRes.CombineOutput().Bytes(), "cluster-ip-same-node.log")
			}()

			httpSVCURL := fmt.Sprintf("http://%s/", clusterIP)
			tftpSVCURL := fmt.Sprintf("tftp://%s/hello", clusterIP)

			k8s1Name, _ := kubectl.GetNodeInfo(helpers.K8s1)
			status, err := kubectl.ExecInHostNetNS(context.TODO(), k8s1Name,
				helpers.CurlFail(httpSVCURL))
			Expect(err).To(BeNil(), "Cannot run curl in host netns")
			status.ExpectSuccess("cannot curl to service IP from host")

			status, err = kubectl.ExecInHostNetNS(context.TODO(), k8s1Name,
				helpers.CurlFail(tftpSVCURL))
			Expect(err).To(BeNil(), "Cannot run curl in host netns")
			status.ExpectSuccess("cannot curl to service IP from host")
			ciliumPods, err := kubectl.GetCiliumPods(helpers.CiliumNamespace)
			Expect(err).To(BeNil(), "Cannot get cilium pods")
			for _, pod := range ciliumPods {
				service := kubectl.CiliumExecMustSucceed(context.TODO(), pod, "cilium service list", "Cannot retrieve services on cilium Pod")
				service.ExpectContains(clusterIP, "ClusterIP is not present in the cilium service list")
			}
			for i := 0; i < 10; i++ {
				// Send requests from "app2" pod which runs on the same node as
				// "app1" pods
				testCurlRequest("id=app2", httpSVCURL)
				testCurlRequest("id=app2", tftpSVCURL)
			}
		}, 300)

		It("Checks service accessing itself (hairpin flow)", func() {
			err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l name=echo", helpers.HelperTimeout)
			Expect(err).Should(BeNil())
			clusterIP, _, err := kubectl.GetServiceHostPort(helpers.DefaultNamespace, echoServiceName)
			Expect(err).Should(BeNil(), "Cannot get service %q ClusterIP", echoServiceName)
			Expect(govalidator.IsIP(clusterIP)).Should(BeTrue(), "ClusterIP is not an IP")

			url := fmt.Sprintf("http://%s/", clusterIP)
			testCurlRequest(echoPodLabel, url)
			url = fmt.Sprintf("tftp://%s/hello", clusterIP)
			testCurlRequest(echoPodLabel, url)
		}, 300)

		SkipContextIf(helpers.RunsWithKubeProxy, "IPv6 Connectivity", func() {
			// Because the deployed K8s does not have dual-stack mode enabled,
			// we install the Cilium service rules manually via Cilium CLI.

			demoClusterIPv6 := "fd03::100"
			echoClusterIPv6 := "fd03::200"

			BeforeEach(func() {
				// Installs the IPv6 equivalent of app1-service (demo.yaml)
				err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l id=app1", helpers.HelperTimeout)
				Expect(err).Should(BeNil())
				httpBackends := ciliumIPv6Backends("-l k8s:id=app1,k8s:io.kubernetes.pod.namespace=default", "80")
				ciliumAddService(10080, net.JoinHostPort(demoClusterIPv6, "80"), httpBackends, "ClusterIP", "Cluster")
				tftpBackends := ciliumIPv6Backends("-l k8s:id=app1,k8s:io.kubernetes.pod.namespace=default", "69")
				ciliumAddService(10069, net.JoinHostPort(demoClusterIPv6, "69"), tftpBackends, "ClusterIP", "Cluster")
				// Installs the IPv6 equivalent of echo (echo-svc.yaml)
				err = kubectl.WaitforPods(helpers.DefaultNamespace, "-l name=echo", helpers.HelperTimeout)
				Expect(err).Should(BeNil())
				httpBackends = ciliumIPv6Backends("-l k8s:name=echo,k8s:io.kubernetes.pod.namespace=default", "80")
				ciliumAddService(20080, net.JoinHostPort(echoClusterIPv6, "80"), httpBackends, "ClusterIP", "Cluster")
				tftpBackends = ciliumIPv6Backends("-l k8s:name=echo,k8s:io.kubernetes.pod.namespace=default", "69")
				ciliumAddService(20069, net.JoinHostPort(echoClusterIPv6, "69"), tftpBackends, "ClusterIP", "Cluster")
			})

			AfterEach(func() {
				ciliumDelService(10080)
				ciliumDelService(10069)
				ciliumDelService(20080)
				ciliumDelService(20069)
			})

			It("Checks service on same node", func() {
				k8s1Name, _ := kubectl.GetNodeInfo(helpers.K8s1)
				status, err := kubectl.ExecInHostNetNS(context.TODO(), k8s1Name,
					helpers.CurlFail(`"http://[%s]/"`, demoClusterIPv6))
				Expect(err).To(BeNil(), "Cannot run curl in host netns")
				status.ExpectSuccess("cannot curl to service IP from host")

				status, err = kubectl.ExecInHostNetNS(context.TODO(), k8s1Name,
					helpers.CurlFail(`"tftp://[%s]/hello"`, demoClusterIPv6))
				Expect(err).To(BeNil(), "Cannot run curl in host netns")
				status.ExpectSuccess("cannot curl to service IP from host")
			})

			It("Checks service accessing itself (hairpin flow)", func() {
				url := fmt.Sprintf(`"http://[%s]/"`, echoClusterIPv6)
				testCurlRequest(echoPodLabel, url)
				url = fmt.Sprintf(`"tftp://[%s]/hello"`, echoClusterIPv6)
				testCurlRequest(echoPodLabel, url)
			})
		})
	})

	Context("Checks service across nodes", func() {

		var (
			demoYAML string
		)

		BeforeAll(func() {
			demoYAML = helpers.ManifestGet(kubectl.BasePath(), "demo_ds.yaml")
			res := kubectl.ApplyDefault(demoYAML)
			res.ExpectSuccess("Unable to apply %s", demoYAML)
		})

		AfterAll(func() {
			// Explicitly ignore result of deletion of resources to avoid incomplete
			// teardown if any step fails.
			_ = kubectl.Delete(demoYAML)
			ExpectAllPodsTerminated(kubectl)
		})

		It("Checks ClusterIP Connectivity", func() {
			waitPodsDs()
			service := "testds-service"

			clusterIP, _, err := kubectl.GetServiceHostPort(helpers.DefaultNamespace, service)
			Expect(err).Should(BeNil(), "Cannot get service %s", service)
			Expect(govalidator.IsIP(clusterIP)).Should(BeTrue(), "ClusterIP is not an IP")

			url := fmt.Sprintf("http://%s/", clusterIP)
			testCurlRequest(testDSClient, url)

			url = fmt.Sprintf("tftp://%s/hello", clusterIP)
			testCurlRequest(testDSClient, url)
		})

		SkipContextIf(helpers.RunsWithKubeProxy, "IPv6 Connectivity", func() {
			testDSIPv6 := "fd03::310"

			BeforeAll(func() {
				// Install rules for testds-service (demo_ds.yaml)
				waitPodsDs()
				httpBackends := ciliumIPv6Backends("-l k8s:zgroup=testDS,k8s:io.kubernetes.pod.namespace=default", "80")
				ciliumAddService(31080, net.JoinHostPort(testDSIPv6, "80"), httpBackends, "ClusterIP", "Cluster")
				tftpBackends := ciliumIPv6Backends("-l k8s:zgroup=testDS,k8s:io.kubernetes.pod.namespace=default", "69")
				ciliumAddService(31069, net.JoinHostPort(testDSIPv6, "69"), tftpBackends, "ClusterIP", "Cluster")
			})

			AfterAll(func() {
				ciliumDelService(31080)
				ciliumDelService(31069)
			})

			It("Checks ClusterIP Connectivity", func() {
				url := fmt.Sprintf(`"http://[%s]/"`, testDSIPv6)
				testCurlRequest(testDSClient, url)

				url = fmt.Sprintf(`"tftp://[%s]/hello"`, testDSIPv6)
				testCurlRequest(testDSClient, url)
			})
		})

		getHTTPLink := func(host string, port int32) string {
			return fmt.Sprintf("http://%s",
				net.JoinHostPort(host, fmt.Sprintf("%d", port)))
		}

		getTFTPLink := func(host string, port int32) string {
			// TFTP requires a filename. Otherwise the packet will be
			// silently dropped by the server.
			return fmt.Sprintf("tftp://%s/hello",
				net.JoinHostPort(host, fmt.Sprintf("%d", port)))
		}

		doRequests := func(url string, count int, fromPod string) {
			By("Making %d curl requests from %s to %q", count, fromPod, url)
			for i := 1; i <= count; i++ {
				res, err := kubectl.ExecInHostNetNS(context.TODO(), fromPod, helpers.CurlFail(url))
				ExpectWithOffset(1, err).To(BeNil(), "Cannot run curl in host netns")
				ExpectWithOffset(1, res).Should(helpers.CMDSuccess(),
					"%s host can not connect to service %q (failed in request %d/%d)",
					fromPod, url, i, count)
			}
		}

		failRequests := func(url string, count int, fromPod string) {
			By("Making %d curl requests from %s to %q", count, fromPod, url)
			for i := 1; i <= count; i++ {
				res, err := kubectl.ExecInHostNetNS(context.TODO(), fromPod, helpers.CurlFail(url, "--max-time 3"))
				ExpectWithOffset(1, err).To(BeNil(), "Cannot run curl in host netns")
				ExpectWithOffset(1, res).ShouldNot(helpers.CMDSuccess(),
					"%s host unexpectedly connected to service %q, it should fail", fromPod, url)
			}
		}

		//failBind := func(addr string, port int32, proto, fromPod string) {
		//	By("Trying to bind NodePort addr %q:%d on %s", addr, port, fromPod)
		//	res, err := kubectl.ExecInHostNetNS(context.TODO(), fromPod,
		//		helpers.PythonBind(addr, uint16(port), proto))
		//	ExpectWithOffset(1, err).To(BeNil(), "Cannot run python in host netns")
		//	ExpectWithOffset(1, res).ShouldNot(helpers.CMDSuccess(),
		//		"%s host unexpectedly was able to bind on %q:%d, it should fail", fromPod, addr, port)
		//}

		doRequestsExpectingHTTPCode := func(url string, count int, expectedCode string, fromPod string) {
			By("Making %d HTTP requests from %s to %q, expecting HTTP %s", count, fromPod, url, expectedCode)
			for i := 1; i <= count; i++ {
				res, err := kubectl.ExecInHostNetNS(context.TODO(), fromPod, helpers.CurlWithHTTPCode(url))
				ExpectWithOffset(1, err).To(BeNil(), "Cannot run curl in host netns")
				ExpectWithOffset(1, res).Should(helpers.CMDSuccess(),
					"%s host can not connect to service %q", fromPod, url)
				res.ExpectContains(expectedCode, "Request from %s to %q returned HTTP Code %q, expected %q",
					fromPod, url, res.Output(), expectedCode)
			}
		}

		doRequestsFromThirdHostWithLocalPort :=
			func(url string, count int, checkSourceIP bool, fromPort int) {
				var cmd string

				By("Making %d HTTP requests from outside cluster to %q", count, url)
				for i := 1; i <= count; i++ {
					if fromPort == 0 {
						cmd = helpers.CurlFail(url)
					} else {
						cmd = helpers.CurlFail("--local-port %d %s", fromPort, url)
					}
					if checkSourceIP {
						cmd += " | grep client_address="
					}
					clientNodeName, clientIP := kubectl.GetNodeInfo(helpers.GetNodeWithoutCilium())
					res, err := kubectl.ExecInHostNetNS(context.TODO(), clientNodeName, cmd)
					Expect(err).Should(BeNil(), "Cannot exec in k8s3 host netns")
					ExpectWithOffset(1, res).Should(helpers.CMDSuccess(),
						"Can not connect to service %q from outside cluster", url)
					if checkSourceIP {
						// Parse the IPs to avoid issues with 4-in-6 formats
						sourceIP := net.ParseIP(strings.TrimSpace(strings.Split(res.GetStdOut(), "=")[1]))
						clientIP := net.ParseIP(clientIP)
						Expect(sourceIP).To(Equal(clientIP))
					}
				}
			}

		doRequestsFromThirdHost := func(url string, count int, checkSourceIP bool) {
			doRequestsFromThirdHostWithLocalPort(url, count, checkSourceIP, 0)
		}

		// srcPod:      Name of pod sending the datagram
		// srcPort:     Source UDP port
		// dstPodIP:    Receiver pod IP (for checking in CT table)
		// dstPodPort:  Receiver pod port (for checking in CT table)
		// dstIP:       Target endpoint IP for sending the datagram
		// dstPort:     Target endpoint port for sending the datagram
		// kubeProxy:   True if kube-proxy is enabled
		doFragmentedRequest := func(srcPod string, srcPort, dstPodPort int, dstIP string, dstPort int32, kubeProxy bool) {
			var (
				blockSize  = 5120
				blockCount = 1
			)
			ciliumPodK8s1, err := kubectl.GetCiliumPodOnNode(helpers.CiliumNamespace, helpers.K8s1)
			Expect(err).Should(BeNil(), fmt.Sprintf("Cannot get cilium pod on k8s1"))
			ciliumPodK8s2, err := kubectl.GetCiliumPodOnNode(helpers.CiliumNamespace, helpers.K8s2)
			Expect(err).Should(BeNil(), fmt.Sprintf("Cannot get cilium pod on k8s2"))

			_, dstPodIPK8s1 := kubectl.GetPodOnNodeWithOffset(helpers.K8s1, testDS, 1)
			_, dstPodIPK8s2 := kubectl.GetPodOnNodeWithOffset(helpers.K8s2, testDS, 1)

			// Get initial number of packets for the flow we test
			// from conntrack table. The flow is probably not in
			// the table the first time we check, so do not stop if
			// Atoi() throws an error and simply consider we have 0
			// packets.

			// Field #7 is "RxPackets=<n>"
			cmdIn := "cilium bpf ct list global | awk '/%s/ { sub(\".*=\",\"\", $7); print $7 }'"

			endpointK8s1 := fmt.Sprintf("%s:%d", dstPodIPK8s1, dstPodPort)
			patternInK8s1 := fmt.Sprintf("UDP IN [^:]+:%d -> %s", srcPort, endpointK8s1)
			cmdInK8s1 := fmt.Sprintf(cmdIn, patternInK8s1)
			res := kubectl.CiliumExecMustSucceed(context.TODO(), ciliumPodK8s1, cmdInK8s1)
			countInK8s1, _ := strconv.Atoi(strings.TrimSpace(res.GetStdOut()))

			endpointK8s2 := fmt.Sprintf("%s:%d", dstPodIPK8s2, dstPodPort)
			patternInK8s2 := fmt.Sprintf("UDP IN [^:]+:%d -> %s", srcPort, endpointK8s2)
			cmdInK8s2 := fmt.Sprintf(cmdIn, patternInK8s2)
			res = kubectl.CiliumExecMustSucceed(context.TODO(), ciliumPodK8s2, cmdInK8s2)
			countInK8s2, _ := strconv.Atoi(strings.TrimSpace(res.GetStdOut()))

			// Field #11 is "TxPackets=<n>"
			cmdOut := "cilium bpf ct list global | awk '/%s/ { sub(\".*=\",\"\", $11); print $11 }'"

			if kubeProxy {
				// If kube-proxy is enabled, we see packets in ctmap with the
				// service's IP address and port, not backend's.
				dstIPv4 := strings.Replace(dstIP, "::ffff:", "", 1)
				endpointK8s1 = fmt.Sprintf("%s:%d", dstIPv4, dstPort)
				endpointK8s2 = endpointK8s1
			}
			patternOutK8s1 := fmt.Sprintf("UDP OUT [^:]+:%d -> %s", srcPort, endpointK8s1)
			cmdOutK8s1 := fmt.Sprintf(cmdOut, patternOutK8s1)
			res = kubectl.CiliumExecMustSucceed(context.TODO(), ciliumPodK8s1, cmdOutK8s1)
			countOutK8s1, _ := strconv.Atoi(strings.TrimSpace(res.GetStdOut()))

			// If kube-proxy is enabled, the two commands are the same and
			// there's no point executing it twice.
			countOutK8s2 := 0
			patternOutK8s2 := fmt.Sprintf("UDP OUT [^:]+:%d -> %s", srcPort, endpointK8s2)
			cmdOutK8s2 := fmt.Sprintf(cmdOut, patternOutK8s2)
			if !kubeProxy {
				res = kubectl.CiliumExecMustSucceed(context.TODO(), ciliumPodK8s1, cmdOutK8s2)
				countOutK8s2, _ = strconv.Atoi(strings.TrimSpace(res.GetStdOut()))
			}

			// Send datagram
			By("Sending a fragmented packet from %s to endpoint %s:%d", srcPod, dstIP, dstPort)
			cmd := fmt.Sprintf("bash -c 'dd if=/dev/zero bs=%d count=%d | nc -u -w 1 -p %d %s %d'", blockSize, blockCount, srcPort, dstIP, dstPort)
			res = kubectl.ExecPodCmd(helpers.DefaultNamespace, srcPod, cmd)
			res.ExpectSuccess("Cannot send fragmented datagram: %s", res.CombineOutput())

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
			newCountInK8s1, _ := strconv.Atoi(strings.TrimSpace(res.GetStdOut()))
			res = kubectl.CiliumExecMustSucceed(context.TODO(), ciliumPodK8s2, cmdInK8s2)
			newCountInK8s2, _ := strconv.Atoi(strings.TrimSpace(res.GetStdOut()))
			Expect([]int{newCountInK8s1, newCountInK8s2}).To(SatisfyAny(
				Equal([]int{countInK8s1, countInK8s2 + delta}),
				Equal([]int{countInK8s1 + delta, countInK8s2}),
			), "Failed to account for IPv4 fragments to %s (in)", dstIP)

			res = kubectl.CiliumExecMustSucceed(context.TODO(), ciliumPodK8s1, cmdOutK8s1)
			newCountOutK8s1, _ := strconv.Atoi(strings.TrimSpace(res.GetStdOut()))
			// If kube-proxy is enabled, the two commands are the same and
			// there's no point executing it twice.
			newCountOutK8s2 := 0
			if !kubeProxy {
				res = kubectl.CiliumExecMustSucceed(context.TODO(), ciliumPodK8s1, cmdOutK8s2)
				newCountOutK8s2, _ = strconv.Atoi(strings.TrimSpace(res.GetStdOut()))
			}
			Expect([]int{newCountOutK8s1, newCountOutK8s2}).To(SatisfyAny(
				Equal([]int{countOutK8s1, countOutK8s2 + delta}),
				Equal([]int{countOutK8s1 + delta, countOutK8s2}),
			), "Failed to account for IPv4 fragments to %s (out)", dstIP)
		}

		startMonitor := func() {
			ciliumPodK8s1, err := kubectl.GetCiliumPodOnNodeWithLabel(helpers.CiliumNamespace, helpers.K8s1)
			Expect(err).Should(BeNil(), "Cannot get cilium pod on k8s1")
			ciliumPodK8s2, err := kubectl.GetCiliumPodOnNodeWithLabel(helpers.CiliumNamespace, helpers.K8s2)
			Expect(err).Should(BeNil(), "Cannot get cilium pod on k8s2")
			monitorRes1, monitorCancel1 := kubectl.MonitorStart(helpers.CiliumNamespace, ciliumPodK8s1)
			monitorRes2, monitorCancel2 := kubectl.MonitorStart(helpers.CiliumNamespace, ciliumPodK8s2)

			helpers.FoobarCallback = func() {
				time.Sleep(1 * time.Second)
				monitorCancel1()
				helpers.WriteToReportFile(monitorRes1.CombineOutput().Bytes(), "foobar-k8s1.log")
				monitorCancel2()
				helpers.WriteToReportFile(monitorRes2.CombineOutput().Bytes(), "foobar-k8s2.log")
			}
		}

		testNodePort := func(bpfNodePort bool) {
			if bpfNodePort {
				startMonitor()
			}

			var data v1.Service
			k8s1Name, k8s1IP := kubectl.GetNodeInfo(helpers.K8s1)
			k8s2Name, k8s2IP := kubectl.GetNodeInfo(helpers.K8s2)

			waitPodsDs()

			err := kubectl.Get(helpers.DefaultNamespace, "service test-nodeport").Unmarshal(&data)
			Expect(err).Should(BeNil(), "Can not retrieve service")
			httpURL := getHTTPLink(data.Spec.ClusterIP, data.Spec.Ports[0].Port)
			tftpURL := getTFTPLink(data.Spec.ClusterIP, data.Spec.Ports[1].Port)
			testCurlRequest(testDSClient, httpURL)
			testCurlRequest(testDSClient, tftpURL)

			// From host via localhost IP
			// TODO: IPv6
			count := 20
			httpURL = getHTTPLink("127.0.0.1", data.Spec.Ports[0].NodePort)
			tftpURL = getTFTPLink("127.0.0.1", data.Spec.Ports[1].NodePort)
			doRequests(httpURL, count, k8s1Name)
			doRequests(tftpURL, count, k8s1Name)

			httpURL = getHTTPLink("::ffff:127.0.0.1", data.Spec.Ports[0].NodePort)
			tftpURL = getTFTPLink("::ffff:127.0.0.1", data.Spec.Ports[1].NodePort)
			doRequests(httpURL, count, k8s1Name)
			doRequests(tftpURL, count, k8s1Name)

			httpURL = getHTTPLink(k8s1IP, data.Spec.Ports[0].NodePort)
			tftpURL = getTFTPLink(k8s1IP, data.Spec.Ports[1].NodePort)
			doRequests(httpURL, count, k8s1Name)
			doRequests(tftpURL, count, k8s1Name)

			httpURL = getHTTPLink("::ffff:"+k8s1IP, data.Spec.Ports[0].NodePort)
			tftpURL = getTFTPLink("::ffff:"+k8s1IP, data.Spec.Ports[1].NodePort)
			doRequests(httpURL, count, k8s1Name)
			doRequests(tftpURL, count, k8s1Name)

			httpURL = getHTTPLink(k8s2IP, data.Spec.Ports[0].NodePort)
			tftpURL = getTFTPLink(k8s2IP, data.Spec.Ports[1].NodePort)
			doRequests(httpURL, count, k8s1Name)
			doRequests(tftpURL, count, k8s1Name)

			httpURL = getHTTPLink("::ffff:"+k8s2IP, data.Spec.Ports[0].NodePort)
			tftpURL = getTFTPLink("::ffff:"+k8s2IP, data.Spec.Ports[1].NodePort)
			doRequests(httpURL, count, k8s1Name)
			doRequests(tftpURL, count, k8s1Name)

			// From pod via node IPs
			httpURL = getHTTPLink(k8s1IP, data.Spec.Ports[0].NodePort)
			tftpURL = getTFTPLink(k8s1IP, data.Spec.Ports[1].NodePort)
			testCurlRequest(testDSClient, tftpURL)
			testCurlRequest(testDSClient, httpURL)

			httpURL = getHTTPLink("::ffff:"+k8s1IP, data.Spec.Ports[0].NodePort)
			tftpURL = getTFTPLink("::ffff:"+k8s1IP, data.Spec.Ports[1].NodePort)
			testCurlRequest(testDSClient, tftpURL)
			testCurlRequest(testDSClient, httpURL)

			httpURL = getHTTPLink(k8s2IP, data.Spec.Ports[0].NodePort)
			tftpURL = getTFTPLink(k8s2IP, data.Spec.Ports[1].NodePort)
			testCurlRequest(testDSClient, httpURL)
			testCurlRequest(testDSClient, tftpURL)

			httpURL = getHTTPLink("::ffff:"+k8s2IP, data.Spec.Ports[0].NodePort)
			tftpURL = getTFTPLink("::ffff:"+k8s2IP, data.Spec.Ports[1].NodePort)
			testCurlRequest(testDSClient, httpURL)
			testCurlRequest(testDSClient, tftpURL)

			if bpfNodePort {
				// From host via local cilium_host
				localCiliumHostIPv4, err := kubectl.GetCiliumHostIPv4(context.TODO(), k8s1Name)
				Expect(err).Should(BeNil(), "Cannot retrieve local cilium_host ipv4")
				httpURL = getHTTPLink(localCiliumHostIPv4, data.Spec.Ports[0].NodePort)
				tftpURL = getTFTPLink(localCiliumHostIPv4, data.Spec.Ports[1].NodePort)
				doRequests(httpURL, count, k8s1Name)
				doRequests(tftpURL, count, k8s1Name)

				httpURL = getHTTPLink("::ffff:"+localCiliumHostIPv4, data.Spec.Ports[0].NodePort)
				tftpURL = getTFTPLink("::ffff:"+localCiliumHostIPv4, data.Spec.Ports[1].NodePort)
				doRequests(httpURL, count, k8s1Name)
				doRequests(tftpURL, count, k8s1Name)

				// From host via remote cilium_host
				remoteCiliumHostIPv4, err := kubectl.GetCiliumHostIPv4(context.TODO(), k8s2Name)
				Expect(err).Should(BeNil(), "Cannot retrieve remote cilium_host ipv4")

				httpURL = getHTTPLink(remoteCiliumHostIPv4, data.Spec.Ports[0].NodePort)
				tftpURL = getTFTPLink(remoteCiliumHostIPv4, data.Spec.Ports[1].NodePort)
				doRequests(httpURL, count, k8s1Name)
				doRequests(tftpURL, count, k8s1Name)

				httpURL = getHTTPLink("::ffff:"+remoteCiliumHostIPv4, data.Spec.Ports[0].NodePort)
				tftpURL = getTFTPLink("::ffff:"+remoteCiliumHostIPv4, data.Spec.Ports[1].NodePort)
				doRequests(httpURL, count, k8s1Name)
				doRequests(tftpURL, count, k8s1Name)

				// From pod via loopback (host reachable services)
				httpURL = getHTTPLink("127.0.0.1", data.Spec.Ports[0].NodePort)
				tftpURL = getTFTPLink("127.0.0.1", data.Spec.Ports[1].NodePort)
				testCurlRequestFail(testDSClient, httpURL)
				testCurlRequestFail(testDSClient, tftpURL)

				httpURL = getHTTPLink("::ffff:127.0.0.1", data.Spec.Ports[0].NodePort)
				tftpURL = getTFTPLink("::ffff:127.0.0.1", data.Spec.Ports[1].NodePort)
				testCurlRequestFail(testDSClient, httpURL)
				testCurlRequestFail(testDSClient, tftpURL)

				// From pod via local cilium_host
				httpURL = getHTTPLink(localCiliumHostIPv4, data.Spec.Ports[0].NodePort)
				//tftpURL = getTFTPLink(localCiliumHostIPv4, data.Spec.Ports[1].NodePort)
				testCurlRequest(testDSClient, httpURL)
				//testCurlRequest(testDSClient, tftpURL)

				httpURL = getHTTPLink("::ffff:"+localCiliumHostIPv4, data.Spec.Ports[0].NodePort)
				//tftpURL = getTFTPLink("::ffff:"+localCiliumHostIPv4, data.Spec.Ports[1].NodePort)
				testCurlRequest(testDSClient, httpURL)
				//testCurlRequest(testDSClient, tftpURL)

				//// From pod via remote cilium_host
				//httpURL = getHTTPLink(remoteCiliumHostIPv4, data.Spec.Ports[0].NodePort)
				//tftpURL = getTFTPLink(remoteCiliumHostIPv4, data.Spec.Ports[1].NodePort)
				//testCurlRequest(testDSClient, httpURL)
				//testCurlRequest(testDSClient, tftpURL)

				//httpURL = getHTTPLink("::ffff:"+remoteCiliumHostIPv4, data.Spec.Ports[0].NodePort)
				//tftpURL = getTFTPLink("::ffff:"+remoteCiliumHostIPv4, data.Spec.Ports[1].NodePort)
				//testCurlRequest(testDSClient, httpURL)
				//testCurlRequest(testDSClient, tftpURL)

				//// Ensure the NodePort cannot be bound from any redirected address
				//failBind(localCiliumHostIPv4, data.Spec.Ports[0].NodePort, "tcp", k8s1Name)
				//failBind(localCiliumHostIPv4, data.Spec.Ports[1].NodePort, "udp", k8s1Name)
				//failBind("127.0.0.1", data.Spec.Ports[0].NodePort, "tcp", k8s1Name)
				//failBind("127.0.0.1", data.Spec.Ports[1].NodePort, "udp", k8s1Name)
				//failBind("", data.Spec.Ports[0].NodePort, "tcp", k8s1Name)
				//failBind("", data.Spec.Ports[1].NodePort, "udp", k8s1Name)

				//failBind("::ffff:127.0.0.1", data.Spec.Ports[0].NodePort, "tcp", k8s1Name)
				//failBind("::ffff:127.0.0.1", data.Spec.Ports[1].NodePort, "udp", k8s1Name)
				//failBind("::ffff:"+localCiliumHostIPv4, data.Spec.Ports[0].NodePort, "tcp", k8s1Name)
				//failBind("::ffff:"+localCiliumHostIPv4, data.Spec.Ports[1].NodePort, "udp", k8s1Name)
			}
		}

		testNodePortExternal := func(checkTCP, checkUDP bool) {
			var data v1.Service

			err := kubectl.Get(helpers.DefaultNamespace, "service test-nodeport").Unmarshal(&data)
			Expect(err).Should(BeNil(), "Cannot retrieve service")
			_, k8s1IP := kubectl.GetNodeInfo(helpers.K8s1)

			httpURL := getHTTPLink(k8s1IP, data.Spec.Ports[0].NodePort)
			tftpURL := getTFTPLink(k8s1IP, data.Spec.Ports[1].NodePort)

			// Test from external connectivity
			// Note:
			//   In case of SNAT checkSourceIP is false here since the HTTP request
			//   won't have the client IP but the service IP (given the request comes
			//   from the Cilium node to the backend, not from the client directly).
			//   Same in case of Hybrid mode for UDP.
			doRequestsFromThirdHost(httpURL, 20, checkTCP)
			doRequestsFromThirdHost(tftpURL, 20, checkUDP)

			// Make sure all the rest works as expected as well
			testNodePort(true)

			// Clear CT tables on both Cilium nodes
			pod, err := kubectl.GetCiliumPodOnNode(helpers.CiliumNamespace, helpers.K8s1)
			Expect(err).Should(BeNil(), "Cannot determine cilium pod name")
			kubectl.CiliumExecMustSucceed(context.TODO(), pod, "cilium bpf ct flush global", "Unable to flush CT maps")

			pod, err = kubectl.GetCiliumPodOnNode(helpers.CiliumNamespace, helpers.K8s2)
			Expect(err).Should(BeNil(), "Cannot determine cilium pod name")
			kubectl.CiliumExecMustSucceed(context.TODO(), pod, "cilium bpf ct flush global", "Unable to flush CT maps")
		}

		// fromOutside=true tests session affinity implementation from lb.h, while
		// fromOutside=false tests from  bpf_sock.c.
		testSessionAffinity := func(fromOutside bool) {
			var (
				data   v1.Service
				dstPod string
				count  = 10
				from   string
				err    error
				res    *helpers.CmdRes
			)

			err = kubectl.Get(helpers.DefaultNamespace, "service test-affinity").Unmarshal(&data)
			Expect(err).Should(BeNil(), "Cannot retrieve service")
			_, k8s1IP := kubectl.GetNodeInfo(helpers.K8s1)

			httpURL := getHTTPLink(k8s1IP, data.Spec.Ports[0].NodePort)
			cmd := helpers.CurlFail(httpURL) + " | grep 'Hostname:' " // pod name is in the hostname

			if fromOutside {
				from, _ = kubectl.GetNodeInfo(helpers.GetNodeWithoutCilium())
			} else {
				pods, err := kubectl.GetPodNames(helpers.DefaultNamespace, testDSClient)
				ExpectWithOffset(1, err).Should(BeNil(), "cannot retrieve pod names by filter %q", testDSClient)
				from = pods[0]
			}

			// Send 10 requests to the test-affinity and check that the same backend is chosen

			By("Making %d HTTP requests from %s to %q (sessionAffinity)", count, from, httpURL)

			for i := 1; i <= count; i++ {
				if fromOutside {
					res, err = kubectl.ExecInHostNetNS(context.TODO(), from, cmd)
					Expect(err).Should(BeNil(), "Cannot exec in %s host netns", from)
				} else {
					res = kubectl.ExecPodCmd(helpers.DefaultNamespace, from, cmd)
				}
				ExpectWithOffset(1, res).Should(helpers.CMDSuccess(),
					"Cannot connect to service %q from %s (%d/%d)", httpURL, from, i, count)
				pod := strings.TrimSpace(strings.Split(res.GetStdOut(), ": ")[1])
				if i == 1 {
					// Retrieve the destination pod from the first request
					dstPod = pod
				} else {
					// Check that destination pod is always the same
					Expect(dstPod).To(Equal(pod))
				}
			}

			// Delete the pod, and check that a new backend is chosen
			nodes, err := kubectl.GetPodsNodes(helpers.DefaultNamespace, dstPod)
			Expect(err).Should(BeNil(), "Cannot get node name of %s pod", dstPod)
			kubectl.DeleteResource("pod", dstPod).ExpectSuccess("Unable to delete %s pod", dstPod)
			// Wait until the pod has been removed from the cilium endpoints list.
			// Otherwise, the requests below might fail as the non-existing endpoint
			// will be chosen.
			kubectl.WaitForCiliumEndpointDeleted(nodes[dstPod], helpers.DefaultNamespace, dstPod)

			for i := 1; i <= count; i++ {
				if fromOutside {
					res, err = kubectl.ExecInHostNetNS(context.TODO(), from, cmd)
					Expect(err).Should(BeNil(), "Cannot exec in %s host netns", from)
				} else {
					res = kubectl.ExecPodCmd(helpers.DefaultNamespace, from, cmd)
				}
				ExpectWithOffset(1, res).Should(helpers.CMDSuccess(),
					"Cannot connect to service %q from %s (%d/%d) after restart", httpURL, from, i, count)
				pod := strings.TrimSpace(strings.Split(res.GetStdOut(), ": ")[1])
				if i == 1 {
					// Retrieve the destination pod from the first request
					Expect(dstPod).ShouldNot(Equal(pod))
					dstPod = pod
				} else {
					// Check that destination pod is always the same
					Expect(dstPod).To(Equal(pod))
				}
			}
		}

		testExternalTrafficPolicyLocal := func() {
			var (
				data    v1.Service
				httpURL string
				tftpURL string
			)

			k8s1Name, k8s1IP := kubectl.GetNodeInfo(helpers.K8s1)
			k8s2Name, k8s2IP := kubectl.GetNodeInfo(helpers.K8s2)

			// Checks requests are not SNATed when externalTrafficPolicy=Local
			err := kubectl.Get(helpers.DefaultNamespace, "service test-nodeport-local").Unmarshal(&data)
			Expect(err).Should(BeNil(), "Can not retrieve service")

			count := 10

			if helpers.ExistNodeWithoutCilium() {
				httpURL = getHTTPLink(k8s1IP, data.Spec.Ports[0].NodePort)
				tftpURL = getTFTPLink(k8s1IP, data.Spec.Ports[1].NodePort)
				doRequestsFromThirdHost(httpURL, count, true)
				doRequestsFromThirdHost(tftpURL, count, true)
			} else {
				GinkgoPrint("Skipping externalTrafficPolicy=Local test from external node")
			}

			// Checks that requests to k8s2 succeed, while requests to k8s1 are dropped
			err = kubectl.Get(helpers.DefaultNamespace, "service test-nodeport-local-k8s2").Unmarshal(&data)
			Expect(err).Should(BeNil(), "Can not retrieve service")

			httpURL = getHTTPLink(k8s2IP, data.Spec.Ports[0].NodePort)
			tftpURL = getTFTPLink(k8s2IP, data.Spec.Ports[1].NodePort)
			doRequests(httpURL, count, k8s1Name)
			doRequests(httpURL, count, k8s2Name)
			doRequests(tftpURL, count, k8s1Name)
			doRequests(tftpURL, count, k8s2Name)

			httpURL = getHTTPLink(k8s1IP, data.Spec.Ports[0].NodePort)
			tftpURL = getTFTPLink(k8s1IP, data.Spec.Ports[1].NodePort)
			failRequests(httpURL, count, k8s1Name)
			failRequests(httpURL, count, k8s2Name)
			failRequests(tftpURL, count, k8s1Name)
			failRequests(tftpURL, count, k8s2Name)
		}

		testHostPort := func() {
			var (
				httpURL string
				tftpURL string
			)

			k8s1Name, _ := kubectl.GetNodeInfo(helpers.K8s1)
			k8s2Name, k8s2IP := kubectl.GetNodeInfo(helpers.K8s2)

			httpHostPort := int32(8080)
			tftpHostPort := int32(6969)

			httpHostPortStr := strconv.Itoa(int(httpHostPort))
			tftpHostPortStr := strconv.Itoa(int(tftpHostPort))

			count := 10

			pod, err := kubectl.GetCiliumPodOnNode(helpers.CiliumNamespace, helpers.K8s2)
			Expect(err).Should(BeNil(), "Cannot determine cilium pod name")

			res := kubectl.CiliumExecContext(context.TODO(), pod, "cilium service list | grep "+k8s2IP+":"+httpHostPortStr+" | grep HostPort")
			Expect(res.GetStdOut()).ShouldNot(BeEmpty(), "No HostPort entry for "+k8s2IP+":"+httpHostPortStr)

			res = kubectl.CiliumExecContext(context.TODO(), pod, "cilium service list | grep "+k8s2IP+":"+tftpHostPortStr+" | grep HostPort")
			Expect(res.GetStdOut()).ShouldNot(BeEmpty(), "No HostPort entry for "+k8s2IP+":"+tftpHostPortStr)

			// Cluster-internal connectivity to HostPort
			httpURL = getHTTPLink(k8s2IP, httpHostPort)
			tftpURL = getTFTPLink(k8s2IP, tftpHostPort)

			// ... from same node
			doRequests(httpURL, count, k8s2Name)
			doRequests(tftpURL, count, k8s2Name)

			// ... from different node
			doRequests(httpURL, count, k8s1Name)
			doRequests(tftpURL, count, k8s1Name)
		}

		testHealthCheckNodePort := func() {
			var data v1.Service
			k8s1Name, k8s1IP := kubectl.GetNodeInfo(helpers.K8s1)
			k8s2Name, k8s2IP := kubectl.GetNodeInfo(helpers.K8s2)

			// Service with HealthCheckNodePort that only has backends on k8s2
			err := kubectl.Get(helpers.DefaultNamespace, "service test-lb-local-k8s2").Unmarshal(&data)
			Expect(err).Should(BeNil(), "Can not retrieve service")

			count := 10

			// Checks that requests to k8s2 return 200
			url := getHTTPLink(k8s2IP, data.Spec.HealthCheckNodePort)
			doRequestsExpectingHTTPCode(url, count, "200", k8s1Name)
			doRequestsExpectingHTTPCode(url, count, "200", k8s2Name)

			// Checks that requests to k8s1 return 503 Service Unavailable
			url = getHTTPLink(k8s1IP, data.Spec.HealthCheckNodePort)
			doRequestsExpectingHTTPCode(url, count, "503", k8s1Name)
			doRequestsExpectingHTTPCode(url, count, "503", k8s2Name)
		}

		testIPv4FragmentSupport := func() {
			var (
				data    v1.Service
				srcPort = 12345
			)
			k8s1Name, k8s1IP := kubectl.GetNodeInfo(helpers.K8s1)
			k8s2Name, k8s2IP := kubectl.GetNodeInfo(helpers.K8s2)
			kubeProxy := !helpers.RunsWithoutKubeProxy()

			waitPodsDs()

			// Get testDSClient and testDS pods running on k8s1.
			// This is because we search for new packets in the
			// conntrack table for node k8s1.
			clientPod, _ := kubectl.GetPodOnNodeWithOffset(helpers.K8s1, testDSClient, 1)

			err := kubectl.Get(helpers.DefaultNamespace, "service test-nodeport").Unmarshal(&data)
			Expect(err).Should(BeNil(), "Cannot retrieve service")
			nodePort := data.Spec.Ports[1].NodePort
			serverPort := data.Spec.Ports[1].TargetPort.IntValue()

			// With ClusterIP
			doFragmentedRequest(clientPod, srcPort, serverPort, data.Spec.ClusterIP, data.Spec.Ports[1].Port, false)

			// From pod via node IPs
			doFragmentedRequest(clientPod, srcPort+1, serverPort, k8s1IP, nodePort, kubeProxy)
			doFragmentedRequest(clientPod, srcPort+2, serverPort, "::ffff:"+k8s1IP, nodePort, kubeProxy)
			doFragmentedRequest(clientPod, srcPort+3, serverPort, k8s2IP, nodePort, kubeProxy)
			doFragmentedRequest(clientPod, srcPort+4, serverPort, "::ffff:"+k8s2IP, nodePort, kubeProxy)

			if !kubeProxy {
				localCiliumHostIPv4, err := kubectl.GetCiliumHostIPv4(context.TODO(), k8s1Name)
				Expect(err).Should(BeNil(), "Cannot retrieve local cilium_host ipv4")
				remoteCiliumHostIPv4, err := kubectl.GetCiliumHostIPv4(context.TODO(), k8s2Name)
				Expect(err).Should(BeNil(), "Cannot retrieve remote cilium_host ipv4")

				// From pod via local cilium_host
				doFragmentedRequest(clientPod, srcPort+5, serverPort, localCiliumHostIPv4, nodePort, kubeProxy)
				doFragmentedRequest(clientPod, srcPort+6, serverPort, "::ffff:"+localCiliumHostIPv4, nodePort, kubeProxy)

				// From pod via remote cilium_host
				doFragmentedRequest(clientPod, srcPort+7, serverPort, remoteCiliumHostIPv4, nodePort, kubeProxy)
				doFragmentedRequest(clientPod, srcPort+8, serverPort, "::ffff:"+remoteCiliumHostIPv4, nodePort, kubeProxy)
			}
		}

		SkipItIf(helpers.RunsWithoutKubeProxy, "Tests NodePort (kube-proxy)", func() {
			testNodePort(false)
		})

		SkipItIf(helpers.RunsWithoutKubeProxy, "Tests NodePort (kube-proxy) with externalTrafficPolicy=Local", func() {
			testExternalTrafficPolicyLocal()
		})

		SkipContextIf(
			func() bool {
				return helpers.IsIntegration(helpers.CIIntegrationEKS) ||
					helpers.IsIntegration(helpers.CIIntegrationGKE) || // Re-enable when GH-11235 is fixed
					helpers.RunsWithoutKubeProxy()
			},
			"with L7 policy", func() {
				var (
					demoPolicy string
				)

				BeforeAll(func() {
					demoPolicy = helpers.ManifestGet(kubectl.BasePath(), "l7-policy-demo.yaml")
				})

				AfterAll(func() {
					// Explicitly ignore result of deletion of resources to avoid incomplete
					// teardown if any step fails.
					_ = kubectl.Delete(demoPolicy)
				})

				It("Tests NodePort with L7 Policy", func() {
					applyPolicy(demoPolicy)
					testNodePort(false)
				})
			})

		SkipContextIf(
			func() bool {
				return helpers.DoesNotRunOnNetNextOr419Kernel() ||
					helpers.RunsWithKubeProxy()
			},
			"Tests NodePort BPF", func() {
				// TODO(brb) Add with L7 policy test cases after GH#8971 has been fixed

				BeforeAll(func() {
					enableBackgroundReport = false
				})

				AfterAll(func() {
					enableBackgroundReport = true
					kubectl.DeleteCiliumDS()
					ExpectAllPodsTerminated(kubectl)
					// Deploy Cilium as the next test expects it to be up and running
					DeployCiliumAndDNS(kubectl, ciliumFilename)
				})

				Context("Tests with vxlan", func() {
					BeforeAll(func() {
						DeployCiliumAndDNS(kubectl, ciliumFilename)
					})

					It("Tests NodePort", func() {
						testNodePort(true)
					})

					It("Tests NodePort with externalTrafficPolicy=Local", func() {
						testExternalTrafficPolicyLocal()
					})

					It("Tests NodePort with sessionAffinity", func() {
						testSessionAffinity(false)
					})

					SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests NodePort with sessionAffinity from outside", func() {
						testSessionAffinity(true)
					})

					It("Tests HealthCheckNodePort", func() {
						testHealthCheckNodePort()
					})

					It("Tests HostPort", func() {
						testHostPort()
					})
				})

				Context("Tests with direct routing", func() {
					BeforeAll(func() {
						DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
							"global.tunnel":               "disabled",
							"global.autoDirectNodeRoutes": "true",
						})
					})

					It("Tests NodePort", func() {
						testNodePort(true)
					})

					It("Tests NodePort with externalTrafficPolicy=Local", func() {
						testExternalTrafficPolicyLocal()
					})

					It("Tests NodePort with sessionAffinity", func() {
						testSessionAffinity(false)
					})

					SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests NodePort with sessionAffinity from outside", func() {
						testSessionAffinity(true)
					})

					It("Tests HealthCheckNodePort", func() {
						testHealthCheckNodePort()
					})

					It("Tests HostPort", func() {
						testHostPort()
					})

					SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests GH#10983", func() {
						var data v1.Service
						_, k8s2IP := kubectl.GetNodeInfo(helpers.K8s2)

						// We need two NodePort services with the same single endpoint,
						// so thus we choose the "test-nodeport{-local,}-k8s2" svc.
						// Both svcs will be accessed via the k8s2 node, because
						// "test-nodeport-local-k8s2" has the local external traffic
						// policy.
						err := kubectl.Get(helpers.DefaultNamespace, "svc test-nodeport-local-k8s2").Unmarshal(&data)
						Expect(err).Should(BeNil(), "Can not retrieve service")
						svc1URL := getHTTPLink(k8s2IP, data.Spec.Ports[0].NodePort)
						err = kubectl.Get(helpers.DefaultNamespace, "svc test-nodeport-k8s2").Unmarshal(&data)
						Expect(err).Should(BeNil(), "Can not retrieve service")
						svc2URL := getHTTPLink(k8s2IP, data.Spec.Ports[0].NodePort)

						// Send two requests from the same src IP and port to the endpoint
						// via two different NodePort svc to trigger the stale conntrack
						// entry issue. Once it's fixed, the second request should not
						// fail.
						doRequestsFromThirdHostWithLocalPort(svc1URL, 1, false, 64002)
						time.Sleep(120 * time.Second) // to reuse the source port
						doRequestsFromThirdHostWithLocalPort(svc2URL, 1, false, 64002)
					})

					SkipContextIf(helpers.DoesNotExistNodeWithoutCilium, "Tests with MetalLB", func() {
						var (
							metalLB string
						)

						BeforeAll(func() {
							// Will allocate LoadBalancer IPs from 192.168.36.{240-250} range
							metalLB = helpers.ManifestGet(kubectl.BasePath(), "metallb.yaml")
							res := kubectl.ApplyDefault(metalLB)
							res.ExpectSuccess("Unable to apply %s", metalLB)
						})

						AfterAll(func() {
							_ = kubectl.Delete(metalLB)
						})

						It("Connectivity to endpoint via LB", func() {
							lbIP, err := kubectl.GetLoadBalancerIP(
								helpers.DefaultNamespace, "test-lb", 30*time.Second)
							Expect(err).Should(BeNil(), "Cannot retrieve loadbalancer IP for test-lb")

							doRequestsFromThirdHost("http://"+lbIP, 10, false)
						})
					})
				})

				SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests with direct routing and DSR", func() {
					DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
						"global.nodePort.mode":        "dsr",
						"global.tunnel":               "disabled",
						"global.autoDirectNodeRoutes": "true",
					})

					var data v1.Service
					err := kubectl.Get(helpers.DefaultNamespace, "service test-nodeport").Unmarshal(&data)
					Expect(err).Should(BeNil(), "Cannot retrieve service")
					_, k8s1IP := kubectl.GetNodeInfo(helpers.K8s1)
					url := getHTTPLink(k8s1IP, data.Spec.Ports[0].NodePort)
					doRequestsFromThirdHost(url, 10, true)

					// Test whether DSR NAT entries are evicted by GC

					pod, err := kubectl.GetCiliumPodOnNode(helpers.CiliumNamespace, helpers.K8s2)
					Expect(err).Should(BeNil(), "Cannot determine cilium pod name")
					// "test-nodeport-k8s2" because we want to trigger SNAT with a single request:
					// client -> k8s1 -> endpoint @ k8s2.
					err = kubectl.Get(helpers.DefaultNamespace, "service test-nodeport-k8s2").Unmarshal(&data)
					Expect(err).Should(BeNil(), "Cannot retrieve service")
					url = getHTTPLink(k8s1IP, data.Spec.Ports[0].NodePort)

					doRequestsFromThirdHostWithLocalPort(url, 1, true, 64000)
					res := kubectl.CiliumExecContext(context.TODO(), pod, "cilium bpf nat list | grep 64000")
					Expect(res.GetStdOut()).ShouldNot(BeEmpty(), "NAT entry was not evicted")
					// Flush CT maps to trigger eviction of the NAT entries (simulates CT GC)
					kubectl.CiliumExecMustSucceed(context.TODO(), pod, "cilium bpf ct flush global", "Unable to flush CT maps")
					res = kubectl.CiliumExecContext(context.TODO(), pod, "cilium bpf nat list | grep 64000")
					res.ExpectFail("NAT entry was not evicted")
				})

				Context("XDP", func() {

					SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests with XDP, direct routing and SNAT", func() {
						DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
							"global.nodePort.acceleration": "testing-only",
							"global.nodePort.mode":         "snat",
							"global.tunnel":                "disabled",
							"global.autoDirectNodeRoutes":  "true",
						})
						testNodePortExternal(false, false)
					})

					SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests with XDP, direct routing and Hybrid", func() {
						DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
							"global.nodePort.acceleration": "testing-only",
							"global.nodePort.mode":         "hybrid",
							"global.tunnel":                "disabled",
							"global.autoDirectNodeRoutes":  "true",
						})
						testNodePortExternal(true, false)
					})

					SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests with XDP, direct routing and DSR", func() {
						DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
							"global.nodePort.acceleration": "testing-only",
							"global.nodePort.mode":         "dsr",
							"global.tunnel":                "disabled",
							"global.autoDirectNodeRoutes":  "true",
						})
						testNodePortExternal(true, true)
					})
				})

				SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests with TC, direct routing and SNAT", func() {
					DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
						"global.nodePort.acceleration": "none",
						"global.nodePort.mode":         "snat",
						"global.tunnel":                "disabled",
						"global.autoDirectNodeRoutes":  "true",
					})
					testNodePortExternal(false, false)
				})

				SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests with TC, direct routing and Hybrid", func() {
					DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
						"global.nodePort.acceleration": "none",
						"global.nodePort.mode":         "hybrid",
						"global.tunnel":                "disabled",
						"global.autoDirectNodeRoutes":  "true",
					})
					testNodePortExternal(true, false)
				})

				SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests with TC, direct routing and DSR", func() {
					DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
						"global.nodePort.acceleration": "none",
						"global.nodePort.mode":         "dsr",
						"global.tunnel":                "disabled",
						"global.autoDirectNodeRoutes":  "true",
					})
					testNodePortExternal(true, true)
				})

			})

		// Net-next and not old versions, because of LRU requirement.
		SkipItIf(helpers.DoesNotRunOnNetNextOr419Kernel, "Supports IPv4 fragments", func() {
			testIPv4FragmentSupport()
		})
	})

	//TODO: Check service with IPV6

	Context("External services", func() {

		var (
			expectedCIDR = "198.49.23.144/32"

			endpointPath      string
			podPath           string
			policyPath        string
			policyLabeledPath string
			servicePath       string
		)

		BeforeAll(func() {
			endpointPath = helpers.ManifestGet(kubectl.BasePath(), "external_endpoint.yaml")
			podPath = helpers.ManifestGet(kubectl.BasePath(), "external_pod.yaml")
			policyPath = helpers.ManifestGet(kubectl.BasePath(), "external-policy.yaml")
			policyLabeledPath = helpers.ManifestGet(kubectl.BasePath(), "external-policy-labeled.yaml")
			servicePath = helpers.ManifestGet(kubectl.BasePath(), "external_service.yaml")

			kubectl.ApplyDefault(servicePath).ExpectSuccess("cannot install external service")
			kubectl.ApplyDefault(podPath).ExpectSuccess("cannot install pod path")

			err := kubectl.WaitforPods(helpers.DefaultNamespace, "", helpers.HelperTimeout)
			Expect(err).To(BeNil(), "Pods are not ready after timeout")

			err = kubectl.CiliumEndpointWaitReady()
			Expect(err).To(BeNil(), "Endpoints are not ready after timeout")
		})

		AfterAll(func() {
			_ = kubectl.Delete(servicePath)
			_ = kubectl.Delete(podPath)

			ExpectAllPodsTerminated(kubectl)
		})

		AfterEach(func() {
			_ = kubectl.Delete(policyLabeledPath)
			_ = kubectl.Delete(policyPath)
			_ = kubectl.Delete(endpointPath)
		})

		validateEgress := func() {
			By("Checking that toServices CIDR is plumbed into the policy")
			Eventually(func() string {
				output, err := kubectl.LoadedPolicyInFirstAgent()
				ExpectWithOffset(1, err).To(BeNil(), "unable to retrieve policy")
				return output
			}, 2*time.Minute, 2*time.Second).Should(ContainSubstring(expectedCIDR))
		}

		validateEgressAfterDeletion := func() {
			By("Checking that toServices CIDR is no longer plumbed into the policy")
			Eventually(func() string {
				output, err := kubectl.LoadedPolicyInFirstAgent()
				ExpectWithOffset(1, err).To(BeNil(), "unable to retrieve policy")
				return output
			}, 2*time.Minute, 2*time.Second).ShouldNot(ContainSubstring(expectedCIDR))
		}

		It("To Services first endpoint creation", func() {
			res := kubectl.ApplyDefault(endpointPath)
			res.ExpectSuccess()

			applyPolicy(policyPath)
			validateEgress()

			kubectl.Delete(policyPath)
			kubectl.Delete(endpointPath)
			validateEgressAfterDeletion()
		})

		It("To Services first policy", func() {
			applyPolicy(policyPath)
			res := kubectl.ApplyDefault(endpointPath)
			res.ExpectSuccess()

			validateEgress()

			kubectl.Delete(policyPath)
			kubectl.Delete(endpointPath)
			validateEgressAfterDeletion()
		})

		It("To Services first endpoint creation match service by labels", func() {
			By("Creating Kubernetes Endpoint")
			res := kubectl.ApplyDefault(endpointPath)
			res.ExpectSuccess()

			applyPolicy(policyLabeledPath)

			validateEgress()

			kubectl.Delete(policyLabeledPath)
			kubectl.Delete(endpointPath)
			validateEgressAfterDeletion()
		})

		It("To Services first policy, match service by labels", func() {
			applyPolicy(policyLabeledPath)

			By("Creating Kubernetes Endpoint")
			res := kubectl.ApplyDefault(endpointPath)
			res.ExpectSuccess()

			validateEgress()

			kubectl.Delete(policyLabeledPath)
			kubectl.Delete(endpointPath)
			validateEgressAfterDeletion()
		})
	})

	// FIXME: to test external IPs one needs to setup a routing to the VMs
	//        a manual test can be achieved by running
	//        checking `test/k8sT/manifests/externalIPs/README.md`
	//
	//        NOTES: When setting a external-ips-service with a port already allocated, for example 31388
	//               kube-proxy will not allow it and even print a warning in its logs.
	//
	// Context("External IPs services", func() {
	//
	// 	var (
	// 		externalIP                              = "192.0.2.233"
	// 		expectedCIDR                            = externalIP + "/32"
	// 		podName                                 = "toservices"
	// 		podPath, policyLabeledPath, servicePath string
	//
	// 		// shouldConnect asserts that srcPod can connect to dst.
	// 		shouldConnect = func(srcPod, dst string) {
	// 			By("Checking that %q can connect to %q", srcPod, dst)
	// 			res := kubectl.ExecPodCmd(helpers.DefaultNamespace, srcPod, fmt.Sprintf("sh -c 'rm -f index.html && wget %s'", dst))
	// 			res.ExpectSuccess("Unable to connect from %q to %q", srcPod, dst)
	// 		}
	// 	)
	//
	// 	BeforeAll(func() {
	// 		podPath = helpers.ManifestGet(kubectl.BasePath(), "demo.yaml")
	// 		policyLabeledPath = helpers.ManifestGet(kubectl.BasePath(), "external-policy-labeled.yaml")
	// 		servicePath = helpers.ManifestGet(kubectl.BasePath(), "external-ips-service.yaml")
	//
	// 		localExec := helpers.CreateLocalExecutor(os.Environ())
	// 		localExec.Exec(fmt.Sprintf("sudo ip route add %s via %s", externalIP, helpers.K8s1Ip))
	// 		kubectl.Apply(servicePath).ExpectSuccess("cannot install external service")
	// 		kubectl.Apply(podPath).ExpectSuccess("cannot install pod path")
	//
	// 		err := kubectl.WaitforPods(helpers.DefaultNamespace, "", helpers.HelperTimeout)
	// 		Expect(err).To(BeNil(), "Pods are not ready after timeout")
	//
	// 		err = kubectl.CiliumEndpointWaitReady()
	// 		Expect(err).To(BeNil(), "Endpoints are not ready after timeout")
	// 	})
	//
	// 	AfterAll(func() {
	// 		_ = kubectl.Delete(servicePath)
	// 		_ = kubectl.Delete(podPath)
	//
	// 		ExpectAllPodsTerminated(kubectl)
	// 		localExec := helpers.CreateLocalExecutor(os.Environ())
	// 		localExec.Exec(fmt.Sprintf("sudo ip route delete %s via %s", externalIP, helpers.K8s1Ip))
	// 	})
	//
	// 	AfterEach(func() {
	// 		_ = kubectl.Delete(policyLabeledPath)
	// 	})
	//
	// 	validateEgress := func() {
	// 		By("Checking that toServices CIDR is plumbed into CEP")
	// 		Eventually(func() string {
	// 			res := kubectl.Exec(fmt.Sprintf(
	// 				"%s -n %s get cep %s -o json",
	// 				helpers.KubectlCmd,
	// 				helpers.DefaultNamespace,
	// 				podName))
	// 			ExpectWithOffset(1, res).Should(helpers.CMDSuccess(), "cannot get Cilium endpoint")
	// 			data, err := res.Filter(`{.status.policy.egress}`)
	// 			ExpectWithOffset(1, err).To(BeNil(), "unable to get endpoint %s metadata", podName)
	// 			return data.String()
	// 		}, 2*time.Minute, 2*time.Second).Should(ContainSubstring(expectedCIDR))
	// 	}
	//
	// 	validateEgressAfterDeletion := func() {
	// 		By("Checking that toServices CIDR is no longer plumbed into CEP")
	// 		Eventually(func() string {
	// 			res := kubectl.Exec(fmt.Sprintf(
	// 				"%s -n %s get cep %s -o json",
	// 				helpers.KubectlCmd,
	// 				helpers.DefaultNamespace,
	// 				podName))
	// 			ExpectWithOffset(1, res).Should(helpers.CMDSuccess(), "cannot get Cilium endpoint")
	// 			data, err := res.Filter(`{.status.policy.egress}`)
	// 			ExpectWithOffset(1, err).To(BeNil(), "unable to get endpoint %s metadata", podName)
	// 			return data.String()
	// 		}, 2*time.Minute, 2*time.Second).ShouldNot(ContainSubstring(expectedCIDR))
	// 	}
	//
	// 	It("Connects to external IPs", func() {
	// 		shouldConnect(podName, externalIP)
	// 	})
	//
	// 	It("Connects to service IP backed by external IPs", func() {
	// 		err := kubectl.WaitForKubeDNSEntry("external-ips-service", helpers.DefaultNamespace)
	// 		Expect(err).To(BeNil(), "DNS entry is not ready after timeout")
	// 		shouldConnect(podName, serviceName)
	// 	})
	//
	// 	It("To Services first endpoint creation match service by labels", func() {
	// 		By("Creating Kubernetes Endpoint")
	// 		applyPolicy(policyLabeledPath)
	//
	// 		validateEgress()
	//
	// 		kubectl.Delete(policyLabeledPath)
	// 		validateEgressAfterDeletion()
	// 	})
	//
	// })

	SkipContextIf(func() bool { return helpers.IsIntegration(helpers.CIIntegrationEKS) }, "Bookinfo Demo", func() {

		var (
			bookinfoV1YAML, bookinfoV2YAML string
			resourceYAMLs                  []string
			policyPath                     string
		)

		BeforeEach(func() {

			bookinfoV1YAML = helpers.ManifestGet(kubectl.BasePath(), "bookinfo-v1.yaml")
			bookinfoV2YAML = helpers.ManifestGet(kubectl.BasePath(), "bookinfo-v2.yaml")
			policyPath = helpers.ManifestGet(kubectl.BasePath(), "cnp-specs.yaml")

			resourceYAMLs = []string{bookinfoV1YAML, bookinfoV2YAML}

			for _, resourcePath := range resourceYAMLs {
				By("Creating objects in file %q", resourcePath)
				res := kubectl.Create(resourcePath)
				res.ExpectSuccess("unable to create resource %q", resourcePath)
			}
		})

		AfterEach(func() {

			// Explicitly do not check result to avoid having assertions in AfterEach.
			_ = kubectl.Delete(policyPath)

			for _, resourcePath := range resourceYAMLs {
				By("Deleting resource %s", resourcePath)
				// Explicitly do not check result to avoid having assertions in AfterEach.
				_ = kubectl.Delete(resourcePath)
			}
		})

		It("Tests bookinfo demo", func() {

			// We use wget in this test because the Istio apps do not provide curl.
			wgetCommand := fmt.Sprintf("wget --tries=2 --connect-timeout %d", helpers.CurlConnectTimeout)

			version := "version"
			v1 := "v1"

			productPage := "productpage"
			reviews := "reviews"
			ratings := "ratings"
			details := "details"
			dnsChecks := []string{productPage, reviews, ratings, details}
			app := "app"
			health := "health"
			ratingsPath := "ratings/0"

			apiPort := "9080"

			podNameFilter := "{.items[*].metadata.name}"

			// shouldConnect asserts that srcPod can connect to dst.
			shouldConnect := func(srcPod, dst string) {
				By("Checking that %q can connect to %q", srcPod, dst)
				res := kubectl.ExecPodCmd(
					helpers.DefaultNamespace, srcPod, fmt.Sprintf("%s %s", wgetCommand, dst))
				res.ExpectSuccess("Unable to connect from %q to %q", srcPod, dst)
			}

			// shouldNotConnect asserts that srcPod cannot connect to dst.
			shouldNotConnect := func(srcPod, dst string) {
				By("Checking that %q cannot connect to %q", srcPod, dst)
				res := kubectl.ExecPodCmd(
					helpers.DefaultNamespace, srcPod, fmt.Sprintf("%s %s", wgetCommand, dst))
				res.ExpectFail("Was able to connect from %q to %q, but expected no connection: %s", srcPod, dst, res.CombineOutput())
			}

			// formatLabelArgument formats the provided key-value pairs as labels for use in
			// querying Kubernetes.
			formatLabelArgument := func(firstKey, firstValue string, nextLabels ...string) string {
				baseString := fmt.Sprintf("-l %s=%s", firstKey, firstValue)
				if nextLabels == nil {
					return baseString
				} else if len(nextLabels)%2 != 0 {
					Fail("must provide even number of arguments for label key-value pairings")
				} else {
					for i := 0; i < len(nextLabels); i += 2 {
						baseString = fmt.Sprintf("%s,%s=%s", baseString, nextLabels[i], nextLabels[i+1])
					}
				}
				return baseString
			}

			// formatAPI is a helper function which formats a URI to access.
			formatAPI := func(service, port, resource string) string {
				target := fmt.Sprintf(
					"%s.%s.svc.cluster.local:%s",
					service, helpers.DefaultNamespace, port)
				if resource != "" {
					return fmt.Sprintf("%s/%s", target, resource)
				}
				return target
			}

			By("Waiting for pods to be ready")
			err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=bookinfo", helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Pods are not ready after timeout")

			err = kubectl.CiliumEndpointWaitReady()
			ExpectWithOffset(1, err).To(BeNil(), "Endpoints are not ready after timeout")

			By("Waiting for services to be ready")
			for _, service := range []string{details, ratings, reviews, productPage} {
				err = kubectl.WaitForServiceEndpoints(
					helpers.DefaultNamespace, "", service,
					helpers.HelperTimeout)
				Expect(err).Should(BeNil(), "Service %q is not ready after timeout", service)
			}
			By("Validating DNS without Policy")
			for _, name := range dnsChecks {
				err = kubectl.WaitForKubeDNSEntry(name, helpers.DefaultNamespace)
				Expect(err).To(BeNil(), "DNS entry is not ready after timeout")
			}

			By("All pods should be able to connect without policy")

			reviewsPodV1, err := kubectl.GetPods(helpers.DefaultNamespace, formatLabelArgument(app, reviews, version, v1)).Filter(podNameFilter)
			Expect(err).Should(BeNil(), "cannot get reviewsV1 pods")
			productpagePodV1, err := kubectl.GetPods(helpers.DefaultNamespace, formatLabelArgument(app, productPage, version, v1)).Filter(podNameFilter)
			Expect(err).Should(BeNil(), "cannot get productpageV1 pods")

			shouldConnect(reviewsPodV1.String(), formatAPI(ratings, apiPort, health))
			shouldConnect(reviewsPodV1.String(), formatAPI(ratings, apiPort, ratingsPath))

			shouldConnect(productpagePodV1.String(), formatAPI(details, apiPort, health))
			shouldConnect(productpagePodV1.String(), formatAPI(ratings, apiPort, health))
			shouldConnect(productpagePodV1.String(), formatAPI(ratings, apiPort, ratingsPath))

			policyCmd := "cilium policy get io.cilium.k8s.policy.name=cnp-specs"

			By("Importing policy")

			_, err = kubectl.CiliumPolicyAction(helpers.DefaultNamespace, policyPath, helpers.KubectlCreate, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Error creating policy %q", policyPath)

			By("Checking that policies were correctly imported into Cilium")

			ciliumPodK8s1, err = kubectl.GetCiliumPodOnNodeWithLabel(helpers.CiliumNamespace, helpers.K8s1)
			Expect(err).Should(BeNil(), "Cannot get cilium pod on k8s1")
			res := kubectl.ExecPodCmd(helpers.CiliumNamespace, ciliumPodK8s1, policyCmd)
			res.ExpectSuccess("Policy %s is not imported", policyCmd)

			By("Validating DNS with Policy loaded")
			for _, name := range dnsChecks {
				err = kubectl.WaitForKubeDNSEntry(name, helpers.DefaultNamespace)
				Expect(err).To(BeNil(), "DNS entry is not ready after timeout")
			}

			By("After policy import")
			shouldConnect(reviewsPodV1.String(), formatAPI(ratings, apiPort, health))
			shouldNotConnect(reviewsPodV1.String(), formatAPI(ratings, apiPort, ratingsPath))

			shouldConnect(productpagePodV1.String(), formatAPI(details, apiPort, health))

			shouldNotConnect(productpagePodV1.String(), formatAPI(ratings, apiPort, health))
			shouldNotConnect(productpagePodV1.String(), formatAPI(ratings, apiPort, ratingsPath))
		})
	})
})
