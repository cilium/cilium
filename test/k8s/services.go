// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8sTest

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/asaskevich/govalidator"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
)

const (
	appServiceName           = "app1-service"
	appServiceNameIPv6       = "app1-service-ipv6"
	echoServiceName          = "echo"
	echoServiceNameDualStack = "echo-dualstack"
	echoPodLabel             = "name=echo"
	app2PodLabel             = "id=app2"
	// echoServiceNameIPv6 = "echo-ipv6"

	testDSClient = "zgroup=testDSClient"
	testDS       = "zgroup=testDS"
	testDSK8s2   = "zgroup=test-k8s2"

	testDSServiceIPv4 = "testds-service"
	testDSServiceIPv6 = "testds-service-ipv6"
)

// The 5.4 CI job is intended to catch BPF complexity regressions and as such
// doesn't need to execute this test suite.
var _ = SkipDescribeIf(helpers.RunsOn54Kernel, "K8sServicesTest", func() {
	var (
		kubectl        *helpers.Kubectl
		ciliumFilename string
		ni             *helpers.NodesInfo
		err            error
	)

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		ni, err = helpers.GetNodesInfo(kubectl)
		Expect(err).Should(BeNil(), "Cannot get nodes info")

		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
	})

	AfterFailed(func() {
		kubectl.CiliumReport("cilium service list", "cilium endpoint list")
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
	})

	AfterAll(func() {
		ExpectAllPodsTerminated(kubectl)
		UninstallCiliumFromManifest(kubectl, ciliumFilename)
		kubectl.CloseSSHClient()
	})

	Context("Checks E/W loadbalancing (ClusterIP, NodePort from inside cluster, etc)", func() {
		var yamls []string
		var demoPolicyL7 string

		BeforeAll(func() {
			DeployCiliumAndDNS(kubectl, ciliumFilename)

			toApply := []string{"demo.yaml", "demo_ds.yaml", "echo-svc.yaml", "echo-policy.yaml"}
			if helpers.DualStackSupported() {
				toApply = append(toApply, "demo_v6.yaml", "demo_ds_v6.yaml", "echo-svc_v6.yaml")
				if helpers.DualStackSupportBeta() {
					toApply = append(toApply, "echo_svc_dualstack.yaml")
				}
			}
			for _, fn := range toApply {
				path := helpers.ManifestGet(kubectl.BasePath(), fn)
				kubectl.ApplyDefault(path).ExpectSuccess("Unable to apply %s", path)
				yamls = append(yamls, path)
			}

			// Wait for all pods to be in ready state.
			err := kubectl.WaitforPods(helpers.DefaultNamespace, "", helpers.HelperTimeout)
			Expect(err).Should(BeNil())

			demoPolicyL7 = helpers.ManifestGet(kubectl.BasePath(), "l7-policy-demo.yaml")
		})

		AfterAll(func() {
			for _, yaml := range yamls {
				kubectl.Delete(yaml)
			}
			ExpectAllPodsTerminated(kubectl)
		})

		// This is testing bpf_lxc LB (= KPR=disabled) when both client and
		// server are running on the same node. Thus, skipping when running with
		// KPR.
		SkipItIf(func() bool {
			return helpers.RunsWithKubeProxyReplacement()
		}, "Checks service on same node", func() {
			serviceNames := []string{appServiceName}
			if helpers.DualStackSupported() {
				serviceNames = append(serviceNames, appServiceNameIPv6)
			}

			ciliumPodK8s1, err := kubectl.GetCiliumPodOnNode(helpers.K8s1)
			Expect(err).Should(BeNil(), "Cannot get cilium pod on k8s1")
			monitorRes, monitorCancel := kubectl.MonitorStart(ciliumPodK8s1)
			defer func() {
				monitorCancel()
				helpers.WriteToReportFile(monitorRes.CombineOutput().Bytes(), "cluster-ip-same-node.log")
			}()

			ciliumPods, err := kubectl.GetCiliumPods()
			Expect(err).To(BeNil(), "Cannot get cilium pods")

			for _, svcName := range serviceNames {
				clusterIP, _, err := kubectl.GetServiceHostPort(helpers.DefaultNamespace, svcName)
				Expect(err).Should(BeNil(), "Cannot get service %s", svcName)
				Expect(govalidator.IsIP(clusterIP)).Should(BeTrue(), "ClusterIP is not an IP")

				By("testing connectivity via cluster IP %s", clusterIP)

				httpSVCURL := fmt.Sprintf("http://%s/", net.JoinHostPort(clusterIP, "80"))
				tftpSVCURL := fmt.Sprintf("tftp://%s/hello", net.JoinHostPort(clusterIP, "69"))

				status := kubectl.ExecInHostNetNS(context.TODO(), ni.K8s1NodeName,
					helpers.CurlFail(httpSVCURL))
				Expect(status).Should(helpers.CMDSuccess(), "cannot curl to service IP from host: %s", status.CombineOutput())

				status = kubectl.ExecInHostNetNS(context.TODO(), ni.K8s1NodeName,
					helpers.CurlFail(tftpSVCURL))
				Expect(status).Should(helpers.CMDSuccess(), "cannot curl to service IP from host: %s", status.CombineOutput())

				for _, pod := range ciliumPods {
					Expect(ciliumHasServiceIP(kubectl, pod, clusterIP)).Should(BeTrue(),
						"ClusterIP is not present in the cilium service list")
				}
				// Send requests from "app2" pod which runs on the same node as
				// "app1" pods
				testCurlFromPods(kubectl, app2PodLabel, httpSVCURL, 10, 0)
				testCurlFromPods(kubectl, app2PodLabel, tftpSVCURL, 10, 0)
			}
		})

		SkipItIf(func() bool {
			return !helpers.DualStackSupportBeta()
		}, "Checks DualStack services", func() {
			ciliumPods, err := kubectl.GetCiliumPods()
			Expect(err).To(BeNil(), "Cannot get cilium pods")

			clusterIPs, err := kubectl.GetServiceClusterIPs(helpers.DefaultNamespace, echoServiceNameDualStack)
			Expect(err).Should(BeNil(), "Cannot get service %q ClusterIPs", echoServiceNameDualStack)

			for _, clusterIP := range clusterIPs {
				Expect(govalidator.IsIP(clusterIP)).Should(BeTrue(), "ClusterIP is not an IP")

				By("Validating that Cilium is handling all the ClusterIP for service")
				Eventually(func() int {
					validPods := 0
					for _, pod := range ciliumPods {
						if ciliumHasServiceIP(kubectl, pod, clusterIP) {
							validPods++
						}
					}

					return validPods
				}, 30*time.Second, 2*time.Second).
					Should(Equal(len(ciliumPods)), "All Cilium pods must have the ClusterIP in services list")

				By("Validating connectivity to dual stack service ClusterIP")
				url := fmt.Sprintf("http://%s/", net.JoinHostPort(clusterIP, "80"))
				// TODO: Make use of echoPodLabel once the support for hairpin flow of IPv6 services
				// is in.
				testCurlFromPods(kubectl, app2PodLabel, url, 10, 0)
				url = fmt.Sprintf("tftp://%s/hello", net.JoinHostPort(clusterIP, "69"))
				testCurlFromPods(kubectl, app2PodLabel, url, 10, 0)
			}
		})

		SkipContextIf(helpers.DoesNotRunWithKubeProxyReplacement, "Checks in-cluster KPR", func() {
			It("Tests NodePort", func() {
				testNodePort(kubectl, ni, true, false, 0)
			})

			It("Tests NodePort with externalTrafficPolicy=Local", func() {
				// TODO(brb) split testExternalTrafficPolicyLocal into two functions -
				// one for in-cluster, one for outside cluster
				testExternalTrafficPolicyLocal(kubectl, ni)
			})

			It("Tests NodePort with sessionAffinity", func() {
				testSessionAffinity(kubectl, ni, false, true)
			})

			It("Tests HealthCheckNodePort", func() {
				testHealthCheckNodePort(kubectl, ni)
			})

			It("Tests that binding to NodePort port fails", func() {
				testFailBind(kubectl, ni)
			})

			It("Tests HostPort", func() {
				testHostPort(kubectl, ni)
			})

			Context("with L7 policy", func() {
				AfterAll(func() {
					kubectl.Delete(demoPolicyL7)
					// Remove CT entries to avoid packet drops which could happen
					// due to matching stale entries with proxy_redirect = 1
					kubectl.CiliumExecMustSucceedOnAll(context.TODO(),
						"cilium bpf ct flush global", "Unable to flush CT maps")
				})

				It("Tests NodePort with L7 Policy", func() {
					applyPolicy(kubectl, demoPolicyL7)
					testNodePort(kubectl, ni, false, false, 0)
				})
			})
		})

		// The test is relevant only for bpf_lxc LB, while bpf_sock (KPR enabled)
		// doesn't require any special handling for hairpin service flows.
		SkipItIf(helpers.RunsWithKubeProxyReplacement, "Checks service accessing itself (hairpin flow)", func() {
			serviceNames := []string{echoServiceName}
			// Hairpin flow mode is currently not supported for IPv6.
			// TODO: Uncomment after https://github.com/cilium/cilium/pull/14138 is merged
			// if helpers.DualStackSupported() {
			// }
			// 	serviceNames = append(serviceNames, // )

			for _, svcName := range serviceNames {
				clusterIP, _, err := kubectl.GetServiceHostPort(helpers.DefaultNamespace, svcName)
				Expect(err).Should(BeNil(), "Cannot get service %q ClusterIP", svcName)
				Expect(govalidator.IsIP(clusterIP)).Should(BeTrue(), "ClusterIP is not an IP")

				url := fmt.Sprintf("http://%s/", net.JoinHostPort(clusterIP, "80"))
				testCurlFromPods(kubectl, echoPodLabel, url, 10, 0)
				url = fmt.Sprintf("tftp://%s/hello", net.JoinHostPort(clusterIP, "69"))
				testCurlFromPods(kubectl, echoPodLabel, url, 10, 0)
			}

		}, 600)

		SkipContextIf(func() bool {
			return helpers.DoesNotRunWithKubeProxyReplacement() || helpers.DoesNotRunOnNetNextKernel()
		}, "Checks connectivity when skipping socket lb in pod ns", func() {
			var yamls []string

			BeforeAll(func() {
				DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
					"hostServices.hostNamespaceOnly": "true",
					// Enable Maglev to check if traffic destined to ClusterIP from Pod is properly handled
					// by bpf_lxc.c using LB_SELECTION_RANDOM even if Maglev is enabled.
					"loadBalancer.algorithm": "maglev",
				})

				yamls = []string{"demo_ds.yaml"}
				if helpers.DualStackSupported() {
					yamls = append(yamls, "demo_ds_v6.yaml")
				}

				for _, yaml := range yamls {
					path := helpers.ManifestGet(kubectl.BasePath(), yaml)
					kubectl.ApplyDefault(path).
						ExpectSuccess("Unable to apply %s", path)
				}
				waitPodsDs(kubectl, []string{testDS, testDSClient, testDSK8s2})
			})

			AfterAll(func() {
				for _, yaml := range yamls {
					path := helpers.ManifestGet(kubectl.BasePath(), yaml)
					kubectl.Delete(path)
				}
				ExpectAllPodsTerminated(kubectl)
			})

			// In adition to the bpf_sock bypass, this test is testing whether bpf_lxc
			// ClusterIP for IPv6 is working
			It("Checks ClusterIP connectivity", func() {
				services := []string{testDSServiceIPv4}
				if helpers.DualStackSupported() {
					services = append(services, testDSServiceIPv6)
				}

				// Test that socket lb doesn't kick in, aka we see service VIP in monitor output.
				// Note that cilium monitor won't capture service VIP if run with Istio.
				ciliumPodK8s1, err := kubectl.GetCiliumPodOnNode(helpers.K8s1)
				Expect(err).Should(BeNil(), "Cannot get cilium pod on k8s1")
				monitorRes, monitorCancel := kubectl.MonitorStart(ciliumPodK8s1)
				defer func() {
					monitorCancel()
					helpers.WriteToReportFile(monitorRes.CombineOutput().Bytes(), "skip-socket-lb-connectivity-across-nodes.log")
				}()

				for _, service := range services {
					clusterIP, _, err := kubectl.GetServiceHostPort(helpers.DefaultNamespace, service)
					Expect(err).Should(BeNil(), "Cannot get services %s", service)
					Expect(govalidator.IsIP(clusterIP)).Should(BeTrue(), "ClusterIP is not an IP")
					httpURL := fmt.Sprintf("http://%s", net.JoinHostPort(clusterIP, "80"))
					tftpURL := fmt.Sprintf("tftp://%s/hello", net.JoinHostPort(clusterIP, "69"))

					// Test connectivity from root ns (bpf_sock)
					kubectl.ExecInHostNetNS(context.TODO(), ni.K8s1NodeName,
						helpers.CurlFail(httpURL)).
						ExpectSuccess("cannot curl to service IP from host")
					kubectl.ExecInHostNetNS(context.TODO(), ni.K8s1NodeName,
						helpers.CurlFail(tftpURL)).
						ExpectSuccess("cannot curl to service IP from host")

					// Test connectivity from pod netns (bpf_lxc)
					testCurlFromPods(kubectl, testDSClient, httpURL, 10, 0)
					testCurlFromPods(kubectl, testDSClient, tftpURL, 10, 0)

					monitorRes.ExpectContains(clusterIP, "Service VIP not seen in monitor trace, indicating socket lb still in effect")
				}
			})
		})

		SkipContextIf(func() bool {
			return helpers.RunsWithKubeProxyReplacement()
		}, "Tests NodePort inside cluster (kube-proxy)", func() {
			SkipItIf(helpers.DoesNotRunOn419OrLaterKernel, "with IPSec and externalTrafficPolicy=Local", func() {
				deploymentManager.SetKubectl(kubectl)
				deploymentManager.Deploy(helpers.CiliumNamespace, IPSecSecret)
				DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
					"encryption.enabled": "true",
				})
				testExternalTrafficPolicyLocal(kubectl, ni)
				deploymentManager.DeleteAll()
				deploymentManager.DeleteCilium()
			})

			It("with the host firewall and externalTrafficPolicy=Local", func() {
				DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
					"hostFirewall.enabled": "true",
				})
				testExternalTrafficPolicyLocal(kubectl, ni)
			})

			It("with externalTrafficPolicy=Local", func() {
				DeployCiliumAndDNS(kubectl, ciliumFilename)
				testExternalTrafficPolicyLocal(kubectl, ni)
			})

			It("", func() {
				testNodePort(kubectl, ni, false, false, 0)
			})
		})

		SkipContextIf(helpers.RunsWithKubeProxyReplacement, "TFTP with DNS Proxy port collision", func() {
			var (
				demoPolicy    string
				ciliumPodK8s1 string
				ciliumPodK8s2 string
				DNSProxyPort1 int
				DNSProxyPort2 int
			)

			BeforeAll(func() {
				var err error
				ciliumPodK8s1, err = kubectl.GetCiliumPodOnNode(helpers.K8s1)
				Expect(err).Should(BeNil(), "Cannot get cilium pod on %s", helpers.K8s1)
				ciliumPodK8s2, err = kubectl.GetCiliumPodOnNode(helpers.K8s2)
				Expect(err).Should(BeNil(), "Cannot get cilium pod on %s", helpers.K8s2)

				// Find out the DNS proxy ports in use
				DNSProxyPort1 = kubectl.GetDNSProxyPort(ciliumPodK8s1)
				By("DNS Proxy port in k8s1 (%s): %d", ciliumPodK8s1, DNSProxyPort1)
				DNSProxyPort2 = kubectl.GetDNSProxyPort(ciliumPodK8s2)
				By("DNS Proxy port in k8s2 (%s): %d", ciliumPodK8s2, DNSProxyPort2)

				demoPolicy = helpers.ManifestGet(kubectl.BasePath(), "l4-policy-demo.yaml")
			})

			AfterAll(func() {
				kubectl.Delete(demoPolicy)
			})

			It("Tests TFTP from DNS Proxy Port", func() {
				if DNSProxyPort2 == DNSProxyPort1 {
					Skip(fmt.Sprintf("TFTP source port test can not be done when both nodes have the same proxy port (%d == %d)", DNSProxyPort1, DNSProxyPort2))
				}
				monitorRes1, monitorCancel1 := kubectl.MonitorStart(ciliumPodK8s1)
				monitorRes2, monitorCancel2 := kubectl.MonitorStart(ciliumPodK8s2)
				defer func() {
					monitorCancel1()
					monitorCancel2()
					helpers.WriteToReportFile(monitorRes1.CombineOutput().Bytes(), "tftp-with-l4-policy-monitor-k8s1.log")
					helpers.WriteToReportFile(monitorRes2.CombineOutput().Bytes(), "tftp-with-l4-policy-monitor-k8s2.log")
				}()

				applyPolicy(kubectl, demoPolicy)

				var data v1.Service
				err := kubectl.Get(helpers.DefaultNamespace, "service test-nodeport").Unmarshal(&data)
				Expect(err).Should(BeNil(), "Can not retrieve service")

				// Since we address NodePort in k8s2 using the DNS proxy port of k8s2 as
				// the source port from k8s1, one round is enough regardless of the backend
				// selection, as in both cases the replies are reverse NATted at k8s2.
				count := 1
				fails := 0
				// Client from k8s1
				clientPod, _ := kubectl.GetPodOnNodeLabeledWithOffset(helpers.K8s1, testDSClient, 0)
				// Destination is a NodePort in k8s2, curl (in k8s1) binding to the same local port as the DNS proxy port
				// in k8s2
				url := getTFTPLink(ni.K8s2IP, data.Spec.Ports[1].NodePort) + fmt.Sprintf(" --local-port %d", DNSProxyPort2)
				cmd := testCommand(helpers.CurlFailNoStats(url), count, fails)
				By("Making %d curl requests from %s pod to service %s using source port %d", count, clientPod, url, DNSProxyPort2)
				res := kubectl.ExecPodCmd(helpers.DefaultNamespace, clientPod, cmd)
				Expect(res).Should(helpers.CMDSuccess(), "Request from %s pod to service %s failed", clientPod, url)

				if helpers.DualStackSupported() {
					err := kubectl.Get(helpers.DefaultNamespace, "service test-nodeport-ipv6").Unmarshal(&data)
					Expect(err).Should(BeNil(), "Can not retrieve service")

					// Client from k8s1
					clientPod, _ := kubectl.GetPodOnNodeLabeledWithOffset(helpers.K8s1, testDSClient, 0)
					// Destination is a NodePort in k8s2, curl (in k8s1) binding to the same local port as the DNS proxy port
					// in k8s2
					url := getTFTPLink(ni.PrimaryK8s2IPv6, data.Spec.Ports[1].NodePort) + fmt.Sprintf(" --local-port %d", DNSProxyPort2)
					cmd := testCommand(helpers.CurlFailNoStats(url), count, fails)
					By("Making %d curl requests from %s pod to service %s using source port %d", count, clientPod, url, DNSProxyPort2)
					res := kubectl.ExecPodCmd(helpers.DefaultNamespace, clientPod, cmd)
					Expect(res).Should(helpers.CMDSuccess(), "Request from %s pod to service %s failed", clientPod, url)
				}
			})
		})

		SkipContextIf(func() bool {
			return helpers.RunsWithKubeProxyReplacement()
		}, "with L4 policy", func() {
			var (
				demoPolicy string
			)

			BeforeAll(func() {
				demoPolicy = helpers.ManifestGet(kubectl.BasePath(), "l4-policy-demo.yaml")
			})

			AfterAll(func() {
				kubectl.Delete(demoPolicy)
			})

			It("Tests NodePort with L4 Policy", func() {
				ciliumPodK8s1, err := kubectl.GetCiliumPodOnNode(helpers.K8s1)
				Expect(err).Should(BeNil(), "Cannot get cilium pod on k8s1")
				monitorRes1, monitorCancel1 := kubectl.MonitorStart(ciliumPodK8s1)
				ciliumPodK8s2, err := kubectl.GetCiliumPodOnNode(helpers.K8s2)
				Expect(err).Should(BeNil(), "Cannot get cilium pod on k8s2")
				monitorRes2, monitorCancel2 := kubectl.MonitorStart(ciliumPodK8s2)
				defer func() {
					monitorCancel1()
					monitorCancel2()
					helpers.WriteToReportFile(monitorRes1.CombineOutput().Bytes(), "nodeport-with-l4-policy-monitor-k8s1.log")
					helpers.WriteToReportFile(monitorRes2.CombineOutput().Bytes(), "nodeport-with-l4-policy-monitor-k8s2.log")
				}()

				applyPolicy(kubectl, demoPolicy)
				testNodePort(kubectl, ni, false, false, 0)
			})
		})

		SkipContextIf(func() bool {
			return helpers.RunsWithKubeProxyReplacement()
		}, "with L7 policy", func() {
			var demoPolicyL7 string

			BeforeAll(func() {
				demoPolicyL7 = helpers.ManifestGet(kubectl.BasePath(), "l7-policy-demo.yaml")
			})

			AfterAll(func() {
				kubectl.Delete(demoPolicyL7)
				// Same reason as in other L7 test above
				kubectl.CiliumExecMustSucceedOnAll(context.TODO(),
					"cilium bpf ct flush global", "Unable to flush CT maps")
			})

			It("Tests NodePort with L7 Policy", func() {
				ciliumPodK8s1, err := kubectl.GetCiliumPodOnNode(helpers.K8s1)
				Expect(err).Should(BeNil(), "Cannot get cilium pod on k8s1")
				monitorRes1, monitorCancel1 := kubectl.MonitorStart(ciliumPodK8s1)
				ciliumPodK8s2, err := kubectl.GetCiliumPodOnNode(helpers.K8s2)
				Expect(err).Should(BeNil(), "Cannot get cilium pod on k8s2")
				monitorRes2, monitorCancel2 := kubectl.MonitorStart(ciliumPodK8s2)
				defer func() {
					monitorCancel1()
					monitorCancel2()
					helpers.WriteToReportFile(monitorRes1.CombineOutput().Bytes(), "nodeport-with-l7-policy-monitor-k8s1.log")
					helpers.WriteToReportFile(monitorRes2.CombineOutput().Bytes(), "nodeport-with-l7-policy-monitor-k8s2.log")
				}()

				applyPolicy(kubectl, demoPolicyL7)
				testNodePort(kubectl, ni, false, false, 0)
			})
		})
	})

	SkipContextIf(func() bool {
		return helpers.DoesNotRunWithKubeProxyReplacement() ||
			helpers.DoesNotExistNodeWithoutCilium()
	}, "Checks N/S loadbalancing", func() {
		var yamls []string

		BeforeAll(func() {
			DeployCiliumAndDNS(kubectl, ciliumFilename)

			toApply := []string{"demo.yaml", "demo_ds.yaml", "echo-svc.yaml"}
			if helpers.DualStackSupported() {
				toApply = append(toApply, "demo_ds_v6.yaml")
			}
			for _, fn := range toApply {
				path := helpers.ManifestGet(kubectl.BasePath(), fn)
				kubectl.ApplyDefault(path).ExpectSuccess("Unable to apply %s", path)
				yamls = append(yamls, path)
			}

			By(`Connectivity config:: helpers.DualStackSupported(): %v
Primary Interface %s   :: IPv4: (%s, %s), IPv6: (%s, %s)
Secondary Interface %s :: IPv4: (%s, %s), IPv6: (%s, %s)`,
				helpers.DualStackSupported(), ni.PrivateIface,
				ni.K8s1IP, ni.K8s2IP, ni.PrimaryK8s1IPv6, ni.PrimaryK8s2IPv6,
				helpers.SecondaryIface, ni.SecondaryK8s1IPv4, ni.SecondaryK8s2IPv4,
				ni.SecondaryK8s1IPv6, ni.SecondaryK8s2IPv6)

			// Wait for all pods to be in ready state.
			err := kubectl.WaitforPods(helpers.DefaultNamespace, "", helpers.HelperTimeout)
			Expect(err).Should(BeNil())
		})

		AfterAll(func() {
			for _, yaml := range yamls {
				kubectl.Delete(yaml)
			}
			ExpectAllPodsTerminated(kubectl)
		})

		It("Tests NodePort with sessionAffinity from outside", func() {
			testSessionAffinity(kubectl, ni, true, true)
		})

		It("Tests externalIPs", func() {
			testExternalIPs(kubectl, ni)
		})

		It("Tests GH#10983", func() {
			var data v1.Service

			// We need two NodePort services with the same single endpoint,
			// so thus we choose the "test-nodeport{-local,}-k8s2" svc.
			// Both svcs will be accessed via the k8s2 node, because
			// "test-nodeport-local-k8s2" has the local external traffic
			// policy.
			err := kubectl.Get(helpers.DefaultNamespace, "svc test-nodeport-local-k8s2").Unmarshal(&data)
			Expect(err).Should(BeNil(), "Can not retrieve service")
			svc1URL := getHTTPLink(ni.K8s2IP, data.Spec.Ports[0].NodePort)
			err = kubectl.Get(helpers.DefaultNamespace, "svc test-nodeport-k8s2").Unmarshal(&data)
			Expect(err).Should(BeNil(), "Can not retrieve service")
			svc2URL := getHTTPLink(ni.K8s2IP, data.Spec.Ports[0].NodePort)

			// Send two requests from the same src IP and port to the endpoint
			// via two different NodePort svc to trigger the stale conntrack
			// entry issue. Once it's fixed, the second request should not
			// fail.
			testCurlFromOutsideWithLocalPort(kubectl, ni, svc1URL, 1, false, 64002)
			time.Sleep(120 * time.Second) // to reuse the source port
			testCurlFromOutsideWithLocalPort(kubectl, ni, svc2URL, 1, false, 64002)
		})

		It("Tests security id propagation in N/S LB requests fwd-ed over tunnel", func() {
			// This test case checks whether the "wold" identity is passed in
			// the encapsulated N/S LB requests which are forwarded to the node
			// running the service endpoint. The check is performed by installing
			// a network policy which disallows traffic to the service endpoints
			// from outside.

			var netpol string

			// "test-nodeport-k8s2" is the svc with the single endpoint running
			// on the "k8s2". We will send request via the "k8s1", so that we
			// can test the forwarding. In addition, we will send the request
			// via the "k8s2" request to test whether the policy enforcement
			// works as expected in the case of the "backend local" case.
			var data v1.Service
			err := kubectl.Get(helpers.DefaultNamespace, "service test-nodeport-k8s2").Unmarshal(&data)
			Expect(err).Should(BeNil(), "Can not retrieve service")
			svcAddrs := []string{
				getHTTPLink(ni.K8s1IP, data.Spec.Ports[0].NodePort),
				getHTTPLink(ni.K8s2IP, data.Spec.Ports[0].NodePort),
			}
			if helpers.DualStackSupported() {
				err := kubectl.Get(helpers.DefaultNamespace, "service test-nodeport-k8s2-ipv6").Unmarshal(&data)
				Expect(err).Should(BeNil(), "Can not retrieve service")
				svcAddrs = append(svcAddrs,
					getHTTPLink(ni.PrimaryK8s1IPv6, data.Spec.Ports[0].NodePort),
					getHTTPLink(ni.PrimaryK8s2IPv6, data.Spec.Ports[0].NodePort))
			}

			// No policy is applied, no request should be dropped.
			for _, addr := range svcAddrs {
				testCurlFromOutside(kubectl, ni, addr, 1, false)
			}

			netpol = helpers.ManifestGet(kubectl.BasePath(), "netpol-deny-ns-lb-test-k8s2.yaml")
			_, err = kubectl.CiliumClusterwidePolicyAction(netpol,
				helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Policy %s cannot be applied", netpol)

			defer func() {
				_, err := kubectl.CiliumClusterwidePolicyAction(netpol,
					helpers.KubectlDelete, helpers.HelperTimeout)
				Expect(err).Should(BeNil(), "Policy %s cannot be deleted", netpol)
			}()

			// Now let's apply the policy. All request should fail.
			for _, addr := range svcAddrs {
				testCurlFailFromOutside(kubectl, ni, addr, 1)
			}
		})

		SkipItIf(func() bool {
			// Currently, KIND doesn't support multiple interfaces among nodes
			return helpers.IsIntegration(helpers.CIIntegrationKind)
		}, "Tests with secondary NodePort device", func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"loadBalancer.mode": "snat",
				"devices":           fmt.Sprintf(`'{%s,%s}'`, ni.PrivateIface, helpers.SecondaryIface),
			})

			testNodePortExternal(kubectl, ni, true, false, false)
		})

		It("Tests with direct routing and DSR", func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"loadBalancer.mode":    "dsr",
				"tunnel":               "disabled",
				"autoDirectNodeRoutes": "true",
			})

			testDSR(kubectl, ni, 64000)
			testNodePortExternal(kubectl, ni, false, true, true)
		})

		It("Tests with XDP, direct routing, SNAT and Random", func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"loadBalancer.acceleration": "testing-only",
				"loadBalancer.mode":         "snat",
				"loadBalancer.algorithm":    "random",
				"tunnel":                    "disabled",
				"autoDirectNodeRoutes":      "true",
				"devices":                   fmt.Sprintf(`'{%s}'`, ni.PrivateIface),
			})
			testNodePortExternal(kubectl, ni, false, false, false)
		})

		It("Tests with XDP, direct routing, SNAT and Maglev", func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"loadBalancer.acceleration": "testing-only",
				"loadBalancer.mode":         "snat",
				"loadBalancer.algorithm":    "maglev",
				"maglev.tableSize":          "251",
				"tunnel":                    "disabled",
				"autoDirectNodeRoutes":      "true",
				"devices":                   fmt.Sprintf(`'{%s}'`, ni.PrivateIface),
				// Support for host firewall + Maglev is currently broken,
				// see #14047 for details.
				"hostFirewall.enabled": "false",
			})

			testMaglev(kubectl, ni)
			testNodePortExternal(kubectl, ni, false, false, false)
		})

		It("Tests with XDP, direct routing, Hybrid and Random", func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"loadBalancer.acceleration": "testing-only",
				"loadBalancer.mode":         "hybrid",
				"loadBalancer.algorithm":    "random",
				"tunnel":                    "disabled",
				"autoDirectNodeRoutes":      "true",
				"devices":                   fmt.Sprintf(`'{%s}'`, ni.PrivateIface),
			})
			testNodePortExternal(kubectl, ni, false, true, false)
		})

		It("Tests with XDP, direct routing, Hybrid and Maglev", func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"loadBalancer.acceleration": "testing-only",
				"loadBalancer.mode":         "hybrid",
				"loadBalancer.algorithm":    "maglev",
				"maglev.tableSize":          "251",
				"tunnel":                    "disabled",
				"autoDirectNodeRoutes":      "true",
				"devices":                   fmt.Sprintf(`'{%s}'`, ni.PrivateIface),
				// Support for host firewall + Maglev is currently broken,
				// see #14047 for details.
				"hostFirewall.enabled": "false",
			})
			testNodePortExternal(kubectl, ni, false, true, false)
		})

		It("Tests with XDP, direct routing, DSR and Random", func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"loadBalancer.acceleration": "testing-only",
				"loadBalancer.mode":         "dsr",
				"loadBalancer.algorithm":    "random",
				"tunnel":                    "disabled",
				"autoDirectNodeRoutes":      "true",
				"devices":                   fmt.Sprintf(`'{%s}'`, ni.PrivateIface),
			})
			testNodePortExternal(kubectl, ni, false, true, true)
		})

		It("Tests with XDP, direct routing, DSR and Maglev", func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"loadBalancer.acceleration": "testing-only",
				"loadBalancer.mode":         "dsr",
				"loadBalancer.algorithm":    "maglev",
				"maglev.tableSize":          "251",
				"tunnel":                    "disabled",
				"autoDirectNodeRoutes":      "true",
				"devices":                   fmt.Sprintf(`'{%s}'`, ni.PrivateIface),
				// Support for host firewall + Maglev is currently broken,
				// see #14047 for details.
				"hostFirewall.enabled": "false",
			})
			testNodePortExternal(kubectl, ni, false, true, true)
		})

		It("Tests with TC, direct routing and Hybrid", func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"loadBalancer.acceleration": "disabled",
				"loadBalancer.mode":         "hybrid",
				"loadBalancer.algorithm":    "random",
				"tunnel":                    "disabled",
				"autoDirectNodeRoutes":      "true",
				"devices":                   fmt.Sprintf(`'{}'`), // Revert back to auto-detection after XDP.
			})
			testNodePortExternal(kubectl, ni, false, true, false)
		})

		// Run on net-next and 4.19 but not on old versions, because of
		// LRU requirement.
		SkipItIf(func() bool {
			return helpers.DoesNotRunOn419OrLaterKernel() ||
				(helpers.SkipQuarantined() && helpers.RunsOnGKE())
		}, "Supports IPv4 fragments", func() {
			options := map[string]string{}
			// On GKE we need to disable endpoint routes as fragment tracking
			// isn't compatible with that options. See #15958.
			if helpers.RunsOnGKE() {
				options["gke.enabled"] = "false"
				options["tunnel"] = "disabled"
			}
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, options)
			testIPv4FragmentSupport(kubectl, ni)
		})

		SkipContextIf(func() bool { return helpers.RunsOnGKE() || helpers.SkipQuarantined() }, "With host policy", func() {
			var ccnpHostPolicy string

			BeforeAll(func() {
				DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
					"hostFirewall.enabled": "true",
				})

				ccnpHostPolicy = helpers.ManifestGet(kubectl.BasePath(), "ccnp-host-policy-nodeport-tests.yaml")
				_, err := kubectl.CiliumClusterwidePolicyAction(ccnpHostPolicy,
					helpers.KubectlApply, helpers.HelperTimeout)
				Expect(err).Should(BeNil(),
					"Policy %s cannot be applied", ccnpHostPolicy)
			})

			AfterAll(func() {
				_, err := kubectl.CiliumClusterwidePolicyAction(ccnpHostPolicy,
					helpers.KubectlDelete, helpers.HelperTimeout)
				Expect(err).Should(BeNil(),
					"Policy %s cannot be deleted", ccnpHostPolicy)

				DeployCiliumAndDNS(kubectl, ciliumFilename)
			})

			It("Tests NodePort", func() {
				testNodePort(kubectl, ni, true, true, 0)
			})
		})

		It("ClusterIP cannot be accessed externally when access is disabled",
			func() {
				Expect(curlClusterIPFromExternalHost(kubectl, ni)).
					ShouldNot(helpers.CMDSuccess(),
						"External host %s unexpectedly connected to ClusterIP when lbExternalClusterIP was unset", ni.OutsideNodeName)
			})

		Context("With ClusterIP external access", func() {
			var (
				svcIP string
			)
			BeforeAll(func() {
				DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
					"bpf.lbExternalClusterIP": "true",
					// Enable Maglev to check if the Maglev LUT for ClusterIP is properly populated,
					// and external clients can access ClusterIP with it.
					"loadBalancer.algorithm": "maglev",
				})
				clusterIP, _, err := kubectl.GetServiceHostPort(helpers.DefaultNamespace, appServiceName)
				svcIP = clusterIP
				Expect(err).Should(BeNil(), "Cannot get service %s", appServiceName)
				res := kubectl.AddIPRoute(ni.OutsideNodeName, svcIP, ni.K8s1IP, false)
				Expect(res).Should(helpers.CMDSuccess(), "Error adding IP route for %s via %s", svcIP, ni.K8s1IP)
			})

			AfterAll(func() {
				res := kubectl.DelIPRoute(ni.OutsideNodeName, svcIP, ni.K8s1IP)
				Expect(res).Should(helpers.CMDSuccess(), "Error removing IP route for %s via %s", svcIP, ni.K8s1IP)
			})

			It("ClusterIP can be accessed when external access is enabled", func() {
				Expect(curlClusterIPFromExternalHost(kubectl, ni)).
					Should(helpers.CMDSuccess(), "Could not curl ClusterIP %s from external host", svcIP)
			})
		})
	})

	SkipContextIf(func() bool {
		// The graceful termination feature depends on enabling an alpha feature
		// EndpointSliceTerminatingCondition in Kubernetes.
		return helpers.SkipK8sVersions("<1.20.0") || helpers.RunsOnGKE() || helpers.RunsOnEKS() ||
			helpers.RunsWithoutKubeProxy()
	}, "Checks graceful termination of service endpoints", func() {
		const (
			clientPodLabel = "app=graceful-term-client"
			serverPodLabel = "app=graceful-term-server"
			testPodLabel   = "zgroup=testDSClient"
		)
		var (
			gracefulTermYAML string
			clientPod        string
			serverPod        string
			wg               sync.WaitGroup
		)

		terminateServiceEndpointPod := func() {
			By("Deleting service endpoint pod %s", serverPodLabel)
			wg.Add(1)
			// Delete the service pod asynchronously subsequent steps need
			// to be checked while the pod is terminating.
			go func() {
				defer wg.Done()
				res := kubectl.DeleteResource("pod", fmt.Sprintf("-n %s -l %s", helpers.DefaultNamespace, serverPodLabel))
				ExpectWithOffset(1, res).Should(helpers.CMDSuccess(), "Unable to delete %s pod", serverPodLabel)
			}()

			By("Waiting until server is terminating")
			ctx, cancel := context.WithCancel(context.Background())
			res := kubectl.LogsStream(helpers.DefaultNamespace, serverPod, ctx)
			find := "terminating"
			Eventually(func() bool {
				return strings.Contains(res.OutputPrettyPrint(), find)
			}, 60*time.Second, time.Second).Should(BeTrue(), "[%s] is not in the output after timeout\n%s", find, res.Stdout())
			defer cancel()
		}

		BeforeAll(func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"kubeProxyReplacement": "disabled",
			})

			_, err := kubectl.GetCiliumPodOnNode(helpers.K8s1)
			Expect(err).Should(BeNil(), "Cannot get cilium pod on k8s1")
			_, err = kubectl.GetCiliumPodOnNode(helpers.K8s2)
			Expect(err).Should(BeNil(), "Cannot get cilium pod on k8s2")

			gracefulTermYAML = helpers.ManifestGet(kubectl.BasePath(), "graceful-termination.yaml")
			res := kubectl.ApplyDefault(gracefulTermYAML)
			Expect(res).Should(helpers.CMDSuccess(), "Unable to apply %s", gracefulTermYAML)
		})

		BeforeEach(func() {
			gracefulTermYAML = helpers.ManifestGet(kubectl.BasePath(), "graceful-termination.yaml")
			res := kubectl.ApplyDefault(gracefulTermYAML)
			Expect(res).Should(helpers.CMDSuccess(), "Unable to apply %s", gracefulTermYAML)

			pods := waitForServiceBackendPods(kubectl, serverPodLabel, 1)
			serverPod = pods[0]
		})

		AfterFailed(func() {
			kubectl.CiliumReport("cilium service list", "cilium bpf lb list")
			kubectl.LogsPreviousWithLabel(helpers.DefaultNamespace, serverPodLabel)
			kubectl.LogsPreviousWithLabel(helpers.DefaultNamespace, clientPodLabel)
		})

		AfterEach(func() {
			wg.Wait()
			kubectl.Delete(gracefulTermYAML)
			ExpectAllPodsTerminated(kubectl)
		})

		It("Checks client terminates gracefully on service endpoint deletion", func() {
			err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l "+clientPodLabel, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Client pods failed to come up")
			pods, err := kubectl.GetPodNames(helpers.DefaultNamespace, clientPodLabel)
			Expect(err).Should(BeNil(), "Cannot retrieve pod names by filter %s", clientPodLabel)
			Expect(len(pods)).To(Equal(1), "Unexpected number of client pods")
			clientPod = pods[0]
			ctx, cancel := context.WithCancel(context.Background())
			res := kubectl.LogsStream(helpers.DefaultNamespace, clientPod, ctx)
			// Check if the client pod is able to get a response from the server once it's up and running
			find := "client received"
			Eventually(func() bool {
				return strings.Contains(res.OutputPrettyPrint(), find)
			}, 60*time.Second, time.Second).Should(BeTrue(), "[%s] is not in the output after timeout\n%s", find, res.Stdout())
			defer cancel()

			terminateServiceEndpointPod()

			By("Checking if client pod terminated gracefully")
			ctx, cancel = context.WithCancel(context.Background())
			res = kubectl.LogsStream(helpers.DefaultNamespace, clientPod, ctx)
			// The log message indicates that the connectivity between client and
			// server was intact even after the service endpoint pod was terminated,
			// and that the client connection terminated gracefully.
			find = "exiting on graceful termination"
			Eventually(func() bool {
				return strings.Contains(res.OutputPrettyPrint(), find)
			}, 60*time.Second, time.Second).Should(BeTrue(), "[%s] is not in the output after timeout\n%s", find, res.Stdout())
			defer cancel()

			// The client pod exits with status code 0 on graceful termination.
			By("Checking if client pod exited successfully")
			Eventually(func() string {
				filter := `{.status.phase}`
				status, err := kubectl.GetPods(helpers.DefaultNamespace, clientPod).Filter(filter)
				Expect(err).Should(BeNil(), "Failed to get pod status %s", clientPod)
				return status.String()
			}, 15*time.Second, time.Second).Should(BeIdenticalTo("Succeeded"), "Unexpected pod status \n")
		})

		It("Checks if terminating service endpoint doesn't serve new connections", func() {
			err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testDSClient", helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Pods %s failed to come up", testPodLabel)
			podIPs, err := kubectl.GetPodsIPs(helpers.DefaultNamespace, testPodLabel)
			ExpectWithOffset(1, err).Should(BeNil(), "Cannot retrieve pod IPs for %s", testPodLabel)

			terminateServiceEndpointPod()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			for pod, ip := range podIPs {
				// Repeat the command as Kubernetes events propagation may have delays
				Eventually(func() bool {
					By("Checking if test pod connection is unsuccessful")
					res := kubectl.ExecPodCmd(
						helpers.DefaultNamespace, pod,
						helpers.CurlFail("graceful-term-svc.default.svc.cluster.local.:8081"))

					By("Checking if terminating service endpoint did not receive new connection")
					msg := fmt.Sprintf("received connection from %s", ip)
					res2 := kubectl.LogsStream(helpers.DefaultNamespace, serverPod, ctx)

					return !res.WasSuccessful() || !res2.ExpectDoesNotContain(msg, "Server received connection from %s when it should not have", ip)
				}, 10*time.Second, time.Second).Should(BeTrue(), "%q can connect when it should not work \n", pod)
			}
		})
	})

	SkipContextIf(
		func() bool {
			return helpers.RunsWithKubeProxy() || helpers.DoesNotExistNodeWithoutCilium()
		},
		"Checks device reconfiguration",
		func() {
			var (
				demoYAML string
			)
			const (
				ipv4VXLANK8s1    = "192.168.254.1"
				ipv4VXLANOutside = "192.168.254.2"
			)

			BeforeAll(func() {
				demoYAML = helpers.ManifestGet(kubectl.BasePath(), "demo_ds.yaml")

				DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
					"enableRuntimeDeviceDetection": "true",
					"devices":                      "",
				})

				res := kubectl.ApplyDefault(demoYAML)
				Expect(res).Should(helpers.CMDSuccess(), "Unable to apply %s", demoYAML)
				waitPodsDs(kubectl, []string{testDS})

				// Setup a pair of vxlan devices between k8s1 and the outside node.
				devOutside, err := kubectl.GetPrivateIface(ni.OutsideNodeName)
				Expect(err).Should(BeNil(), "Cannot get public interface for %s", ni.OutsideNodeName)

				devK8s1, err := kubectl.GetPrivateIface(helpers.K8s1)
				Expect(err).Should(BeNil(), "Cannot get public interface for %s", helpers.K8s1)

				res = kubectl.AddVXLAN(ni.OutsideNodeName, ni.K8s1IP, devOutside, ipv4VXLANOutside+"/24", 1)
				Expect(res).Should(helpers.CMDSuccess(), "Error adding VXLAN device for outside node")

				res = kubectl.AddVXLAN(ni.K8s1NodeName, ni.OutsideIP, devK8s1, ipv4VXLANK8s1+"/24", 1)
				Expect(res).Should(helpers.CMDSuccess(), "Error adding VXLAN device for k8s1")

			})

			AfterAll(func() {
				_ = kubectl.Delete(demoYAML)
				ExpectAllPodsTerminated(kubectl)

				res := kubectl.DelVXLAN(ni.K8s1NodeName, 1)
				Expect(res).Should(helpers.CMDSuccess(), "Error removing vxlan1 from k8s1")
				res = kubectl.DelVXLAN(ni.OutsideNodeName, 1)
				Expect(res).Should(helpers.CMDSuccess(), "Error removing vxlan1 from outside node")
			})

			It("Detects newly added device and reloads datapath", func() {
				var data v1.Service
				err := kubectl.Get(helpers.DefaultNamespace, "svc test-nodeport").Unmarshal(&data)
				Expect(err).Should(BeNil(), "Cannot retrieve service test-nodeport")
				url := getHTTPLink(ipv4VXLANK8s1, data.Spec.Ports[0].NodePort)

				// Try accessing the NodePort service from the external node over the VXLAN tunnel.
				// We're expecting Cilium to detect the vxlan1 interface and reload the datapath,
				// allowing us to access NodePort services.
				// Note that this can be quite slow due to datapath recompilation!
				Eventually(
					func() bool {
						res := kubectl.ExecInHostNetNS(
							context.TODO(), ni.OutsideNodeName,
							helpers.CurlFail(url))
						return res.WasSuccessful()
					},
					60*time.Second, 1*time.Second,
				).Should(BeTrue(), "Could not curl NodePort service over newly added device")
			})
		})
})
