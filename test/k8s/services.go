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

	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
)

const (
	appServiceName  = "app1-service"
	echoServiceName = "echo"
	echoPodLabel    = "name=echo"
	// echoServiceNameIPv6 = "echo-ipv6"

	testDSClient = "zgroup=testDSClient"
	testDS       = "zgroup=testDS"
	testDSK8s2   = "zgroup=test-k8s2"
)

// The 5.4 CI job is intended to catch BPF complexity regressions and as such
// doesn't need to execute this test suite.
var _ = SkipDescribeIf(helpers.RunsOn54Kernel, "K8sDatapathServicesTest", func() {
	var (
		kubectl        *helpers.Kubectl
		ciliumFilename string
		ni             *helpers.NodesInfo
		err            error
	)

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
		deploymentManager.SetKubectl(kubectl)

		ni, err = helpers.GetNodesInfo(kubectl)
		Expect(err).Should(BeNil(), "Cannot get nodes info")

		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
	})

	AfterFailed(func() {
		kubectl.CiliumReport("cilium-dbg service list", "cilium-dbg endpoint list")
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
			wg := sync.WaitGroup{}
			for _, yaml := range yamls {
				wg.Add(1)
				go func(yaml string) {
					defer wg.Done()
					// Ensure that all deployments are fully cleaned up before
					// proceeding to the next test.
					res := kubectl.DeleteAndWait(yaml, true)

					Expect(res.WasSuccessful()).Should(BeTrue(), "Unable to cleanup yaml: %s", yaml)
				}(yaml)
			}
			wg.Wait()
			ExpectAllPodsTerminated(kubectl)
		})

		SkipContextIf(helpers.DoesNotRunWithKubeProxyReplacement, "Checks in-cluster KPR", func() {
			It("Tests HealthCheckNodePort", func() {
				testHealthCheckNodePort(kubectl, ni)
			})

			It("Tests that binding to NodePort port fails", func() {
				testFailBind(kubectl, ni)
			})

			SkipContextIf(helpers.RunsOnAKS, "with L7 policy", func() {
				AfterAll(func() {
					kubectl.Delete(demoPolicyL7)
					// Remove CT entries to avoid packet drops which could happen
					// due to matching stale entries with proxy_redirect = 1
					kubectl.CiliumExecMustSucceedOnAll(context.TODO(),
						"cilium-dbg bpf ct flush global", "Unable to flush CT maps")
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
				Expect(net.ParseIP(clusterIP) != nil).Should(BeTrue(), "ClusterIP is not an IP")

				url := fmt.Sprintf("http://%s/", net.JoinHostPort(clusterIP, "80"))
				testCurlFromPods(kubectl, echoPodLabel, url, 10, 0)
				url = fmt.Sprintf("tftp://%s/hello", net.JoinHostPort(clusterIP, "69"))
				testCurlFromPods(kubectl, echoPodLabel, url, 10, 0)
			}

		}, 600)

		SkipContextIf(func() bool {
			return helpers.RunsWithKubeProxyReplacement()
		}, "Tests NodePort inside cluster (kube-proxy)", func() {
			It("with IPSec and externalTrafficPolicy=Local", func() {
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

			It("vanilla", func() {
				testNodePort(kubectl, ni, false, false, 0)
			})
		})

		SkipContextIf(func() bool { return helpers.RunsWithKubeProxyReplacement() || helpers.RunsOnAKS() }, "TFTP with DNS Proxy port collision", func() {
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
				applyPolicy(kubectl, demoPolicy)
				testNodePort(kubectl, ni, false, false, 0)
			})
		})

		SkipContextIf(func() bool {
			return helpers.RunsWithKubeProxyReplacement() || helpers.RunsOnAKS()
		}, "with L7 policy", func() {
			var demoPolicyL7 string

			BeforeAll(func() {
				demoPolicyL7 = helpers.ManifestGet(kubectl.BasePath(), "l7-policy-demo.yaml")
			})

			AfterAll(func() {
				kubectl.Delete(demoPolicyL7)
				// Same reason as in other L7 test above
				kubectl.CiliumExecMustSucceedOnAll(context.TODO(),
					"cilium-dbg bpf ct flush global", "Unable to flush CT maps")
			})

			It("Tests NodePort with L7 Policy", func() {
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

		It("Tests with direct routing and DSR", func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"loadBalancer.mode":    "dsr",
				"routingMode":          "native",
				"autoDirectNodeRoutes": "true",
			})

			testDSR(kubectl, ni, ni.K8s1IP, "service test-nodeport-k8s2", 64000)
			if helpers.DualStackSupported() {
				testDSR(kubectl, ni, ni.PrimaryK8s1IPv6, "service test-nodeport-k8s2-ipv6", 64001)
			}
			testNodePortExternal(kubectl, ni, false, true, true)
		})

		It("Tests with XDP, direct routing, SNAT and Random", func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"loadBalancer.acceleration": "testing-only",
				"loadBalancer.mode":         "snat",
				"loadBalancer.algorithm":    "random",
				"routingMode":               "native",
				"autoDirectNodeRoutes":      "true",
				"devices":                   fmt.Sprintf(`'{%s}'`, ni.PrivateIface),
			})
			testNodePortExternal(kubectl, ni, false, false, false)
		})

		It("Tests with XDP, vxlan tunnel, SNAT and Random", func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"loadBalancer.acceleration": "testing-only",
				"loadBalancer.mode":         "snat",
				"loadBalancer.algorithm":    "random",
				"tunnelProtocol":            "vxlan",
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
				"routingMode":               "native",
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
				"routingMode":               "native",
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
				"routingMode":               "native",
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
				"routingMode":               "native",
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
				"routingMode":               "native",
				"autoDirectNodeRoutes":      "true",
				"devices":                   fmt.Sprintf(`'{%s}'`, ni.PrivateIface),
				// Support for host firewall + Maglev is currently broken,
				// see #14047 for details.
				"hostFirewall.enabled": "false",
			})
			testNodePortExternal(kubectl, ni, false, true, true)
		})

		It("Tests with XDP, direct routing, DSR with Geneve and Maglev", func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"loadBalancer.acceleration": "testing-only",
				"loadBalancer.mode":         "dsr",
				"loadBalancer.algorithm":    "maglev",
				"maglev.tableSize":          "251",
				"routingMode":               "native",
				"tunnelProtocol":            "geneve",
				"autoDirectNodeRoutes":      "true",
				"loadBalancer.dsrDispatch":  "geneve",
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
				"routingMode":               "native",
				"autoDirectNodeRoutes":      "true",
				"devices":                   "'{}'", // Revert back to auto-detection after XDP.
			})
			testNodePortExternal(kubectl, ni, false, true, false)
		})

		It("Tests with TC, direct routing and dsr with geneve", func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"loadBalancer.acceleration": "disabled",
				"loadBalancer.mode":         "dsr",
				"loadBalancer.algorithm":    "maglev",
				"maglev.tableSize":          "251",
				"routingMode":               "native",
				"tunnelProtocol":            "geneve",
				"autoDirectNodeRoutes":      "true",
				"loadBalancer.dsrDispatch":  "geneve",
				"devices":                   "'{}'", // Revert back to auto-detection after XDP.
			})
			testNodePortExternal(kubectl, ni, false, true, true)
		})

		It("Tests with TC, direct routing and Hybrid-DSR with Geneve", func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"loadBalancer.acceleration": "disabled",
				"loadBalancer.mode":         "hybrid",
				"loadBalancer.algorithm":    "random",
				"routingMode":               "native",
				"tunnelProtocol":            "geneve",
				"autoDirectNodeRoutes":      "true",
				"loadBalancer.dsrDispatch":  "geneve",
				"devices":                   "'{}'",
			})
			testNodePortExternal(kubectl, ni, false, true, false)
		})

		It("Tests with TC, geneve tunnel, dsr and Maglev", func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"loadBalancer.acceleration": "disabled",
				"loadBalancer.mode":         "dsr",
				"loadBalancer.algorithm":    "maglev",
				"maglev.tableSize":          "251",
				"tunnelProtocol":            "geneve",
				"loadBalancer.dsrDispatch":  "geneve",
				"devices":                   "'{}'", // Revert back to auto-detection after XDP.
			})
			testNodePortExternal(kubectl, ni, false, true, true)
		})

		It("Tests with TC, geneve tunnel, and Hybrid-DSR with Geneve", func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"loadBalancer.acceleration": "disabled",
				"loadBalancer.mode":         "hybrid",
				"loadBalancer.algorithm":    "random",
				"tunnelProtocol":            "geneve",
				"loadBalancer.dsrDispatch":  "geneve",
				"devices":                   "'{}'",
			})
			testNodePortExternal(kubectl, ni, false, true, false)
		})

		It("Supports IPv4 fragments", func() {
			options := map[string]string{}
			// On GKE we need to disable endpoint routes as fragment tracking
			// isn't compatible with that options. See #15958.
			if helpers.RunsOnGKE() {
				options["gke.enabled"] = "false"
				options["routingMode"] = "native"
			}

			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, options)

			cmd := fmt.Sprintf("cilium-dbg config %s=%s", helpers.OptionConntrackAccounting, helpers.OptionEnabled)
			kubectl.CiliumExecMustSucceedOnAll(context.TODO(), cmd, "Unable to enable ConntrackAccounting option")
			kubectl.CiliumPreFlightCheck()
			testIPv4FragmentSupport(kubectl, ni)
		})

		SkipContextIf(helpers.RunsOnGKE, "With host policy", func() {
			hostPolicyFilename := "ccnp-host-policy-nodeport-tests.yaml"
			var ccnpHostPolicy string

			BeforeAll(func() {
				DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
					"hostFirewall.enabled": "true",
				})

				originalCCNPHostPolicy := helpers.ManifestGet(kubectl.BasePath(), hostPolicyFilename)
				res := kubectl.ExecMiddle("mktemp")
				res.ExpectSuccess()
				ccnpHostPolicy = strings.Trim(res.Stdout(), "\n")
				nodeIP, err := kubectl.GetNodeIPByLabel(kubectl.GetFirstNodeWithoutCiliumLabel(), false)
				Expect(err).Should(BeNil())
				kubectl.ExecMiddle(fmt.Sprintf("sed 's/NODE_WITHOUT_CILIUM_IP/%s/' %s > %s",
					nodeIP, originalCCNPHostPolicy, ccnpHostPolicy)).ExpectSuccess()

				prepareHostPolicyEnforcement(kubectl, ccnpHostPolicy)

				_, err = kubectl.CiliumClusterwidePolicyAction(ccnpHostPolicy,
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
					"devices": "",
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
