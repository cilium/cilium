// Copyright 2017-2021 Authors of Cilium
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
	"os"
	"strings"
	"time"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	"github.com/asaskevich/govalidator"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
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

	lbSvcName = "test-lb-with-ip"
)

type nodesInfo struct {
	k8s1NodeName      string
	k8s2NodeName      string
	outsideNodeName   string
	k8s1IP            string
	k8s2IP            string
	outsideIP         string
	privateIface      string
	primaryK8s1IPv6   string
	primaryK8s2IPv6   string
	outsideIPv6       string
	secondaryK8s1IPv4 string
	secondaryK8s2IPv4 string
	secondaryK8s1IPv6 string
	secondaryK8s2IPv6 string
}

// The 5.4 CI job is intended to catch BPF complexity regressions and as such
// doesn't need to execute this test suite.
var _ = SkipDescribeIf(helpers.RunsOn54Kernel, "K8sServicesTest", func() {
	var (
		kubectl        *helpers.Kubectl
		ciliumFilename string

		backgroundCancel       context.CancelFunc = func() {}
		backgroundError        error
		enableBackgroundReport = true

		ni = &nodesInfo{}
	)

	BeforeAll(func() {
		var err error
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		if helpers.DualStackSupported() && helpers.DoesNotRunWithKubeProxyReplacement() {
			// This is a fix required for kube-proxy when running in dual-stack mode.
			// Sometimes there is a condition where kube-proxy repeatedly fails as it is not able
			// to find KUBE-MARK-DROP iptables chain for IPv6 which should be created by kubelet.
			// Error occurred at line: 79
			// Try `ip6tables-restore -h' or 'ip6tables-restore --help' for more information.
			// )
			// I1013 15:26:18.762727       1 proxier.go:850] Sync failed; retrying in 30s
			// E1013 15:26:18.780765       1 proxier.go:1570] Failed to execute iptables-restore: exit status 2 (ip6tables-restore v1.8.3 (legacy):
			// Couldn't load target `KUBE-MARK-DROP':No such file or directory
			//
			// This was fixed upstream for IPVS mode but still fails for iptables mode in our CI.
			// For more information see kubernetes/kubernetes issues #80462 #84422 #85527
			kubeproxyPods, err := kubectl.GetPodNames("kube-system", "k8s-app=kube-proxy")
			if err == nil {
				for _, pod := range kubeproxyPods {
					res := kubectl.ExecPodCmd("kube-system", pod, "ip6tables -t nat -N KUBE-MARK-DROP")
					if !res.WasSuccessful() && !strings.Contains(res.CombineOutput().String(), "Chain already exists") {
						GinkgoPrint("Error adding KUBE-MARK-DROP chain: %s, skipping KUBE-MARK-DROP ensure tests might fail.", res.CombineOutput().String())
					}
				}
			} else {
				GinkgoPrint("Error getting kube-proxy pods: %s, skipping KUBE-MARK-DROP ensure tests might fail.", err)
			}
		}

		ni.k8s1NodeName, ni.k8s1IP = kubectl.GetNodeInfo(helpers.K8s1)
		ni.k8s2NodeName, ni.k8s2IP = kubectl.GetNodeInfo(helpers.K8s2)
		if helpers.ExistNodeWithoutCilium() {
			ni.outsideNodeName, ni.outsideIP = kubectl.GetNodeInfo(helpers.GetNodeWithoutCilium())
		}

		ni.privateIface, err = kubectl.GetPrivateIface()
		Expect(err).Should(BeNil(), "Cannot determine private iface")

		if helpers.GetCurrentIntegration() == "" {
			ni.primaryK8s1IPv6 = getIPv6AddrForIface(kubectl, ni.k8s1NodeName, ni.privateIface)
			ni.primaryK8s2IPv6 = getIPv6AddrForIface(kubectl, ni.k8s2NodeName, ni.privateIface)

			// If there is no integration we assume that these are running in vagrant environment
			// so have a secondary interface with both IPv6 and IPv4 addresses.
			ni.secondaryK8s1IPv4 = getIPv4AddrForIface(kubectl, ni.k8s1NodeName, helpers.SecondaryIface)
			ni.secondaryK8s2IPv4 = getIPv4AddrForIface(kubectl, ni.k8s2NodeName, helpers.SecondaryIface)

			ni.secondaryK8s1IPv6 = getIPv6AddrForIface(kubectl, ni.k8s1NodeName, helpers.SecondaryIface)
			ni.secondaryK8s2IPv6 = getIPv6AddrForIface(kubectl, ni.k8s2NodeName, helpers.SecondaryIface)

			if helpers.ExistNodeWithoutCilium() {
				ni.outsideIPv6 = getIPv6AddrForIface(kubectl, ni.outsideNodeName, ni.privateIface)
			}
		}

		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
		DeployCiliumAndDNS(kubectl, ciliumFilename)
	})

	AfterFailed(func() {
		kubectl.CiliumReport("cilium service list", "cilium endpoint list")
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
		UninstallCiliumFromManifest(kubectl, ciliumFilename)
		kubectl.CloseSSHClient()
	})

	manualIPv6TestingNotRequired := func(f func() bool) func() bool {
		return func() bool {
			// IPv6 tests do not work on Integrations like GKE as we don't have IPv6
			// addresses assigned to nodes in those environments.
			return helpers.DualStackSupported() || helpers.GetCurrentIntegration() != "" || f()
		}
	}

	Context("Testing test script", func() {
		It("Validating test script correctness", func() {
			By("Validating test script correctness")
			res := kubectl.ExecInHostNetNS(context.TODO(), ni.k8s1NodeName, testCommand("echo FOOBAR", 1, 0))
			ExpectWithOffset(1, res).Should(helpers.CMDSuccess(), "Test script could not 'echo'")
			res.ExpectContains("FOOBAR", "Test script failed to execute echo: %s", res.Stdout())

			res = kubectl.ExecInHostNetNS(context.TODO(), ni.k8s1NodeName, testCommand("FOOBAR", 3, 0))
			ExpectWithOffset(1, res).ShouldNot(helpers.CMDSuccess(), "Test script successfully executed FOOBAR")
			res.ExpectMatchesRegexp("failed: :[0-9]*/1=127:[0-9]*/2=127:[0-9]*/3=127", "Test script failed to execute echo 3 times: %s", res.Stdout())

			res = kubectl.ExecInHostNetNS(context.TODO(), ni.k8s1NodeName, testCommand("FOOBAR", 1, 1))
			ExpectWithOffset(1, res).Should(helpers.CMDSuccess(), "Test script could not allow failure")

			res = kubectl.ExecInHostNetNS(context.TODO(), ni.k8s1NodeName, testCommand("echo FOOBAR", 3, 0))
			ExpectWithOffset(1, res).Should(helpers.CMDSuccess(), "Test script could not 'echo' three times")
			res.ExpectMatchesRegexp("(?s)(FOOBAR.*exit code: 0.*){3}", "Test script failed to execute echo 3 times: %s", res.Stdout())
		})
	})

	Context("Checks ClusterIP Connectivity", func() {
		var (
			demoYAML             string
			demoYAMLV6           string
			echoSVCYAML          string
			echoSVCYAMLV6        string
			echoSVCYAMLDualStack string
			echoPolicyYAML       string
		)

		BeforeAll(func() {
			demoYAML = helpers.ManifestGet(kubectl.BasePath(), "demo.yaml")
			echoSVCYAML = helpers.ManifestGet(kubectl.BasePath(), "echo-svc.yaml")
			echoPolicyYAML = helpers.ManifestGet(kubectl.BasePath(), "echo-policy.yaml")

			res := kubectl.ApplyDefault(demoYAML)
			Expect(res).Should(helpers.CMDSuccess(), "unable to apply %s", demoYAML)
			res = kubectl.ApplyDefault(echoSVCYAML)
			Expect(res).Should(helpers.CMDSuccess(), "unable to apply %s", echoSVCYAML)
			res = kubectl.ApplyDefault(echoPolicyYAML)
			Expect(res).Should(helpers.CMDSuccess(), "unable to apply %s", echoPolicyYAML)

			if helpers.DualStackSupported() {
				demoYAMLV6 = helpers.ManifestGet(kubectl.BasePath(), "demo_v6.yaml")
				echoSVCYAMLV6 = helpers.ManifestGet(kubectl.BasePath(), "echo-svc_v6.yaml")

				res = kubectl.ApplyDefault(demoYAMLV6)
				Expect(res).Should(helpers.CMDSuccess(), "unable to apply %s", demoYAMLV6)

				res = kubectl.ApplyDefault(echoSVCYAMLV6)
				Expect(res).Should(helpers.CMDSuccess(), "unable to apply %s", echoSVCYAMLV6)

				if helpers.DualStackSupportBeta() {
					echoSVCYAMLDualStack = helpers.ManifestGet(kubectl.BasePath(), "echo_svc_dualstack.yaml")

					res = kubectl.ApplyDefault(echoSVCYAMLDualStack)
					Expect(res).Should(helpers.CMDSuccess(), "unable to apply %s", echoSVCYAMLDualStack)
				}
			}

			// Wait for all app1, app2 and app3 pods to be in ready state.
			err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", helpers.HelperTimeout)
			Expect(err).Should(BeNil())
			err = kubectl.WaitforPods(helpers.DefaultNamespace, "-l name=echo", helpers.HelperTimeout)
			Expect(err).Should(BeNil())
		})

		AfterAll(func() {
			// Explicitly ignore result of deletion of resources to avoid incomplete
			// teardown if any step fails.
			_ = kubectl.Delete(demoYAML)
			_ = kubectl.Delete(echoSVCYAML)
			_ = kubectl.Delete(echoPolicyYAML)
			if helpers.DualStackSupported() {
				_ = kubectl.Delete(demoYAMLV6)
				_ = kubectl.Delete(echoSVCYAMLV6)

				if helpers.DualStackSupportBeta() {
					_ = kubectl.Delete(echoSVCYAMLDualStack)
				}
			}
		})

		SkipItIf(helpers.RunsWithKubeProxyReplacement, "Checks service on same node", func() {
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

				status := kubectl.ExecInHostNetNS(context.TODO(), ni.k8s1NodeName,
					helpers.CurlFail(httpSVCURL))
				Expect(status).Should(helpers.CMDSuccess(), "cannot curl to service IP from host: %s", status.CombineOutput())

				status = kubectl.ExecInHostNetNS(context.TODO(), ni.k8s1NodeName,
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

		It("Checks service accessing itself (hairpin flow)", func() {
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

		SkipContextIf(manualIPv6TestingNotRequired(helpers.DoesNotRunWithKubeProxyReplacement), "IPv6 Connectivity", func() {
			// Because the deployed K8s does not have dual-stack mode enabled,
			// we install the Cilium service rules manually via Cilium CLI.
			demoClusterIPv6 := "fd03::100"
			echoClusterIPv6 := "fd03::200"

			BeforeAll(func() {
				// Installs the IPv6 equivalent of app1-service (demo.yaml)
				httpBackends := ciliumIPv6Backends(kubectl, "-l k8s:id=app1,k8s:io.kubernetes.pod.namespace=default", "80")
				ciliumAddService(kubectl, 10080, net.JoinHostPort(demoClusterIPv6, "80"), httpBackends, "ClusterIP", "Cluster")
				tftpBackends := ciliumIPv6Backends(kubectl, "-l k8s:id=app1,k8s:io.kubernetes.pod.namespace=default", "69")
				ciliumAddService(kubectl, 10069, net.JoinHostPort(demoClusterIPv6, "69"), tftpBackends, "ClusterIP", "Cluster")
				// Installs the IPv6 equivalent of echo (echo-svc.yaml)
				httpBackends = ciliumIPv6Backends(kubectl, "-l k8s:name=echo,k8s:io.kubernetes.pod.namespace=default", "80")
				ciliumAddService(kubectl, 20080, net.JoinHostPort(echoClusterIPv6, "80"), httpBackends, "ClusterIP", "Cluster")
				tftpBackends = ciliumIPv6Backends(kubectl, "-l k8s:name=echo,k8s:io.kubernetes.pod.namespace=default", "69")
				ciliumAddService(kubectl, 20069, net.JoinHostPort(echoClusterIPv6, "69"), tftpBackends, "ClusterIP", "Cluster")
			})

			AfterAll(func() {
				ciliumDelService(kubectl, 10080)
				ciliumDelService(kubectl, 10069)
				ciliumDelService(kubectl, 20080)
				ciliumDelService(kubectl, 20069)
			})

			It("Checks service on same node", func() {
				status := kubectl.ExecInHostNetNS(context.TODO(), ni.k8s1NodeName,
					helpers.CurlFail(`"http://[%s]/"`, demoClusterIPv6))
				status.ExpectSuccess("cannot curl to service IP from host")

				status = kubectl.ExecInHostNetNS(context.TODO(), ni.k8s1NodeName,
					helpers.CurlFail(`"tftp://[%s]/hello"`, demoClusterIPv6))
				status.ExpectSuccess("cannot curl to service IP from host")
			})

			It("Checks service accessing itself (hairpin flow)", func() {
				url := fmt.Sprintf(`"http://[%s]/"`, echoClusterIPv6)
				testCurlFromPods(kubectl, echoPodLabel, url, 10, 0)
				url = fmt.Sprintf(`"tftp://[%s]/hello"`, echoClusterIPv6)
				testCurlFromPods(kubectl, echoPodLabel, url, 10, 0)
			})
		})

		// This label should be respected for all the service types, but testing for ClusterIP is enough.
		// As service type does not influence if Cilium selects the service for management or not.
		It("Checks service.kubernetes.io/service-proxy-name label implementation", func() {
			serviceProxyLabelName := "service.kubernetes.io/service-proxy-name"

			ciliumPods, err := kubectl.GetCiliumPods()
			Expect(err).To(BeNil(), "Cannot get cilium pods")

			serviceNames := []string{echoServiceName}
			// TODO: Uncomment after https://github.com/cilium/cilium/pull/14138 is merged
			// if helpers.DualStackSupported() {
			// }
			// 	serviceNames = append(serviceNames, // )

			for _, svcName := range serviceNames {
				clusterIP, _, err := kubectl.GetServiceHostPort(helpers.DefaultNamespace, svcName)
				Expect(err).Should(BeNil(), "Cannot get service %q ClusterIP", svcName)
				Expect(govalidator.IsIP(clusterIP)).Should(BeTrue(), "ClusterIP is not an IP")

				By("Labelling echo service with dummy service-proxy-name")
				res := kubectl.Exec(fmt.Sprintf("kubectl label services/%s %s=%s", svcName, serviceProxyLabelName, "dummy-lb"))
				Expect(res).Should(helpers.CMDSuccess(), "cannot label service")

				// Wait for all cilium pods to remove the serivce from its list.
				By("Validating that Cilium is not handling the service")
				Eventually(func() int {
					validPods := 0
					for _, pod := range ciliumPods {
						if !ciliumHasServiceIP(kubectl, pod, clusterIP) {
							validPods++
						}
					}

					return validPods
				}, 30*time.Second, 2*time.Second).
					Should(Equal(len(ciliumPods)), "All Cilium pods should remove the service from its services list")

				url := fmt.Sprintf("http://%s/", net.JoinHostPort(clusterIP, "80"))

				By("Checking that service should not be reachable with dummy service-proxy-name")
				testCurlFromPods(kubectl, echoPodLabel, url, 5, 5)

				By("Removing echo service service-proxy-name label")
				res = kubectl.Exec(fmt.Sprintf("kubectl label services/%s %s-", svcName, serviceProxyLabelName))
				Expect(res).Should(helpers.CMDSuccess(), "cannot remove label from service")

				By("Validating that Cilium is handling the service")
				Eventually(func() int {
					validPods := 0
					for _, pod := range ciliumPods {
						if ciliumHasServiceIP(kubectl, pod, clusterIP) {
							validPods++
						}
					}

					return validPods
				}, 30*time.Second, 2*time.Second).
					Should(Equal(len(ciliumPods)), "All Cilium pods must have the service in its services list")

				By("Checking that service should be reachable with no service-proxy-name")
				testCurlFromPods(kubectl, echoPodLabel, url, 5, 0)
			}
		})

		SkipItIf(func() bool { return helpers.DoesNotExistNodeWithoutCilium() },
			"ClusterIP cannot be accessed externally when access is disabled",
			func() {
				Expect(curlClusterIPFromExternalHost(kubectl, ni)).
					ShouldNot(helpers.CMDSuccess(),
						"External host %s unexpectedly connected to ClusterIP when lbExternalClusterIP was unset", ni.outsideNodeName)
			})

		SkipContextIf(func() bool { return helpers.DoesNotExistNodeWithoutCilium() }, "With ClusterIP external access", func() {
			var (
				svcIP string
			)
			BeforeAll(func() {
				DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
					"bpf.lbExternalClusterIP": "true",
				})
				clusterIP, _, err := kubectl.GetServiceHostPort(helpers.DefaultNamespace, appServiceName)
				svcIP = clusterIP
				Expect(err).Should(BeNil(), "Cannot get service %s", appServiceName)
				res := kubectl.AddIPRoute(ni.outsideNodeName, svcIP, ni.k8s1IP, false)
				Expect(res).Should(helpers.CMDSuccess(), "Error adding IP route for %s via %s", svcIP, ni.k8s1IP)
			})

			AfterAll(func() {
				res := kubectl.DelIPRoute(ni.outsideNodeName, svcIP, ni.k8s1IP)
				Expect(res).Should(helpers.CMDSuccess(), "Error removing IP route for %s via %s", svcIP, ni.k8s1IP)
				DeployCiliumAndDNS(kubectl, ciliumFilename)
			})

			It("ClusterIP can be accessed when external access is enabled", func() {
				Expect(curlClusterIPFromExternalHost(kubectl, ni)).
					Should(helpers.CMDSuccess(), "Could not curl ClusterIP %s from external host", svcIP)
			})
		})
	})

	SkipContextIf(func() bool {
		return helpers.DoesNotRunWithKubeProxyReplacement() || helpers.DoesNotRunOnNetNextKernel()
	}, "Checks connectivity when skipping socket lb in pod ns", func() {
		var (
			demoDSYAML  string
			demoYAML    string
			serviceName = testDSServiceIPv4
		)

		BeforeAll(func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"hostServices.hostNamespaceOnly": "true",
			})
			demoDSYAML = helpers.ManifestGet(kubectl.BasePath(), "demo_ds.yaml")
			res := kubectl.ApplyDefault(demoDSYAML)
			res.ExpectSuccess("Unable to apply %s", demoDSYAML)
			demoYAML = helpers.ManifestGet(kubectl.BasePath(), "demo.yaml")
			res = kubectl.ApplyDefault(demoYAML)
			res.ExpectSuccess("unable to apply %s", demoYAML)
			waitPodsDs(kubectl, []string{testDS, testDSClient, testDSK8s2})
		})

		AfterAll(func() {
			_ = kubectl.Delete(demoDSYAML)
			_ = kubectl.Delete(demoYAML)
			ExpectAllPodsTerminated(kubectl)
		})

		It("Checks ClusterIP connectivity on the same node", func() {
			clusterIP, _, err := kubectl.GetServiceHostPort(helpers.DefaultNamespace, serviceName)
			Expect(err).Should(BeNil(), "Cannot get service %s", serviceName)
			Expect(govalidator.IsIP(clusterIP)).Should(BeTrue(), "ClusterIP is not an IP")

			// Test that socket lb doesn't kick in, aka we see service VIP in monitor trace.
			// Note that cilium monitor won't capture service VIP if run with Istio.
			ciliumPodK8s1, err := kubectl.GetCiliumPodOnNode(helpers.K8s1)
			Expect(err).Should(BeNil(), "Cannot get cilium pod on k8s1")
			monitorRes, monitorCancel := kubectl.MonitorStart(ciliumPodK8s1)
			defer func() {
				monitorCancel()
				helpers.WriteToReportFile(monitorRes.CombineOutput().Bytes(), "skip-socket-lb-connectivity-same-node.log")
			}()

			httpSVCURL := fmt.Sprintf("http://%s/", clusterIP)
			tftpSVCURL := fmt.Sprintf("tftp://%s/hello", clusterIP)

			// Test connectivbity from root ns
			status := kubectl.ExecInHostNetNS(context.TODO(), ni.k8s1NodeName,
				helpers.CurlFail(httpSVCURL))
			status.ExpectSuccess("cannot curl to service IP from host")
			status = kubectl.ExecInHostNetNS(context.TODO(), ni.k8s1NodeName,
				helpers.CurlFail(tftpSVCURL))
			status.ExpectSuccess("cannot curl to service IP from host")

			// Test connectivity from pod ns
			testCurlFromPods(kubectl, "id=app2", httpSVCURL, 10, 0)
			testCurlFromPods(kubectl, "id=app2", tftpSVCURL, 10, 0)

			monitorRes.ExpectContains(clusterIP, "Service VIP not seen in monitor trace, indicating socket lb still in effect")
		})

		It("Checks ClusterIP connectivity across nodes", func() {
			service := "testds-service"

			clusterIP, _, err := kubectl.GetServiceHostPort(helpers.DefaultNamespace, service)
			Expect(err).Should(BeNil(), "Cannot get services %s", service)
			Expect(govalidator.IsIP(clusterIP)).Should(BeTrue(), "ClusterIP is not an IP")

			// Test that socket lb doesn't kick in, aka we see service VIP in monitor output.
			// Note that cilium monitor won't capture service VIP if run with Istio.
			ciliumPodK8s1, err := kubectl.GetCiliumPodOnNode(helpers.K8s1)
			Expect(err).Should(BeNil(), "Cannot get cilium pod on k8s1")
			monitorRes, monitorCancel := kubectl.MonitorStart(ciliumPodK8s1)
			defer func() {
				monitorCancel()
				helpers.WriteToReportFile(monitorRes.CombineOutput().Bytes(), "skip-socket-lb-connectivity-across-nodes.log")
			}()

			url := fmt.Sprintf("http://%s/", clusterIP)
			testCurlFromPods(kubectl, testDSClient, url, 10, 0)

			url = fmt.Sprintf("tftp://%s/hello", clusterIP)
			testCurlFromPods(kubectl, testDSClient, url, 10, 0)

			monitorRes.ExpectContains(clusterIP, "Service VIP not seen in monitor trace, indicating socket lb still in effect")
		})
	})

	Context("Checks service across nodes", func() {

		var (
			demoYAML   string
			demoYAMLV6 string

			demoPolicyL7 string
		)

		BeforeAll(func() {
			demoYAML = helpers.ManifestGet(kubectl.BasePath(), "demo_ds.yaml")

			DeployCiliumAndDNS(kubectl, ciliumFilename)

			res := kubectl.ApplyDefault(demoYAML)
			Expect(res).Should(helpers.CMDSuccess(), "Unable to apply %s", demoYAML)

			if helpers.DualStackSupported() {
				demoYAMLV6 = helpers.ManifestGet(kubectl.BasePath(), "demo_ds_v6.yaml")

				res = kubectl.ApplyDefault(demoYAMLV6)
				Expect(res).Should(helpers.CMDSuccess(), "Unable to apply %s", demoYAMLV6)
			}

			By(`Connectivity config:: helpers.DualStackSupported(): %v
Primary Interface %s   :: IPv4: (%s, %s), IPv6: (%s, %s)
Secondary Interface %s :: IPv4: (%s, %s), IPv6: (%s, %s)`, helpers.DualStackSupported(), ni.privateIface, ni.k8s1IP, ni.k8s2IP, ni.primaryK8s1IPv6, ni.primaryK8s2IPv6,
				helpers.SecondaryIface, ni.secondaryK8s1IPv4, ni.secondaryK8s2IPv4, ni.secondaryK8s1IPv6, ni.secondaryK8s2IPv6)

			demoPolicyL7 = helpers.ManifestGet(kubectl.BasePath(), "l7-policy-demo.yaml")
			waitPodsDs(kubectl, []string{testDS, testDSClient, testDSK8s2})
		})

		AfterAll(func() {
			// Explicitly ignore result of deletion of resources to avoid incomplete
			// teardown if any step fails.
			_ = kubectl.Delete(demoYAML)
			if helpers.DualStackSupported() {
				_ = kubectl.Delete(demoYAMLV6)
			}
			ExpectAllPodsTerminated(kubectl)
		})

		SkipItIf(helpers.RunsWithKubeProxyReplacement, "Checks ClusterIP Connectivity", func() {
			services := []string{testDSServiceIPv4}
			if helpers.DualStackSupported() {
				services = append(services, testDSServiceIPv6)
			}

			for _, svcName := range services {
				clusterIP, _, err := kubectl.GetServiceHostPort(helpers.DefaultNamespace, svcName)
				Expect(err).Should(BeNil(), "Cannot get service %s", svcName)
				Expect(govalidator.IsIP(clusterIP)).Should(BeTrue(), "ClusterIP is not an IP")

				url := fmt.Sprintf("http://%s", net.JoinHostPort(clusterIP, "80"))
				testCurlFromPods(kubectl, testDSClient, url, 10, 0)

				url = fmt.Sprintf("tftp://%s/hello", net.JoinHostPort(clusterIP, "69"))
				testCurlFromPods(kubectl, testDSClient, url, 10, 0)
			}
		})

		SkipContextIf(manualIPv6TestingNotRequired(helpers.DoesNotRunWithKubeProxyReplacement), "IPv6 Connectivity", func() {
			testDSIPv6 := "fd03::310"

			BeforeAll(func() {
				// Install rules for testds-service (demo_ds.yaml)
				httpBackends := ciliumIPv6Backends(kubectl, "-l k8s:zgroup=testDS,k8s:io.kubernetes.pod.namespace=default", "80")
				ciliumAddService(kubectl, 31080, net.JoinHostPort(testDSIPv6, "80"), httpBackends, "ClusterIP", "Cluster")
				tftpBackends := ciliumIPv6Backends(kubectl, "-l k8s:zgroup=testDS,k8s:io.kubernetes.pod.namespace=default", "69")
				ciliumAddService(kubectl, 31069, net.JoinHostPort(testDSIPv6, "69"), tftpBackends, "ClusterIP", "Cluster")
			})

			AfterAll(func() {
				ciliumDelService(kubectl, 31080)
				ciliumDelService(kubectl, 31069)
			})

			It("Checks ClusterIP Connectivity", func() {
				url := fmt.Sprintf(`"http://[%s]/"`, testDSIPv6)
				testCurlFromPods(kubectl, testDSClient, url, 10, 0)

				url = fmt.Sprintf(`"tftp://[%s]/hello"`, testDSIPv6)
				testCurlFromPods(kubectl, testDSClient, url, 10, 0)
			})
		})

		SkipContextIf(func() bool {
			return helpers.RunsWithKubeProxyReplacement() || helpers.GetCurrentIntegration() != ""
		}, "IPv6 masquerading", func() {
			var (
				k8s1EndpointIPs map[string]string

				testDSK8s1IPv6 string = "fd03::310"
			)

			BeforeAll(func() {
				DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
					"tunnel":               "disabled",
					"autoDirectNodeRoutes": "true",
				})

				pod, err := kubectl.GetCiliumPodOnNode(helpers.K8s1)
				Expect(err).Should(BeNil(), "Cannot get cilium pod on node %s", helpers.K8s1)
				k8s1EndpointIPs = kubectl.CiliumEndpointIPv6(pod, "-l k8s:zgroup=testDS,k8s:io.kubernetes.pod.namespace=default")

				k8s1Backends := []string{}
				for _, epIP := range k8s1EndpointIPs {
					k8s1Backends = append(k8s1Backends, net.JoinHostPort(epIP, "80"))
				}

				ciliumAddService(kubectl, 31080, net.JoinHostPort(testDSK8s1IPv6, "80"), k8s1Backends, "ClusterIP", "Cluster")
			})

			It("across K8s nodes", func() {
				url := fmt.Sprintf(`"http://[%s]:80/"`, testDSK8s1IPv6)
				testCurlFromPodWithSourceIPCheck(kubectl, testDSK8s2, url, 5, ni.primaryK8s2IPv6)

				for _, epIP := range k8s1EndpointIPs {
					url = fmt.Sprintf(`"http://[%s]:80/"`, epIP)
					testCurlFromPodWithSourceIPCheck(kubectl, testDSK8s2, url, 5, ni.primaryK8s2IPv6)
				}
			})

			AfterAll(func() {
				ciliumDelService(kubectl, 31080)
				DeployCiliumAndDNS(kubectl, ciliumFilename)
			})
		})

		SkipContextIf(helpers.RunsWithKubeProxyReplacement, "Tests NodePort (kube-proxy)", func() {
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
					"hostFirewall": "true",
				})
				testExternalTrafficPolicyLocal(kubectl, ni)
			})

			It("with externalTrafficPolicy=Local", func() {
				DeployCiliumAndDNS(kubectl, ciliumFilename)
				testExternalTrafficPolicyLocal(kubectl, ni)
			})

			It("", func() {
				testNodePort(kubectl, ni, false, false, false, 0)
			})
		})

		SkipContextIf(manualIPv6TestingNotRequired(helpers.DoesNotRunWithKubeProxyReplacement), "Tests IPv6 NodePort Services", func() {
			var (
				testDSIPv6 string = "fd03::310"
				data       v1.Service
			)

			BeforeAll(func() {
				err := kubectl.Get(helpers.DefaultNamespace, "service test-nodeport").Unmarshal(&data)
				Expect(err).Should(BeNil(), "Cannot retrieve service")

				// Install rules for testds-service NodePort Service(demo_ds.yaml)
				httpBackends := ciliumIPv6Backends(kubectl, "-l k8s:zgroup=testDS,k8s:io.kubernetes.pod.namespace=default", "80")
				ciliumAddService(kubectl, 31080, net.JoinHostPort(testDSIPv6, fmt.Sprintf("%d", data.Spec.Ports[0].NodePort)), httpBackends, "NodePort", "Cluster")
				ciliumAddService(kubectl, 31081, net.JoinHostPort("::", fmt.Sprintf("%d", data.Spec.Ports[0].NodePort)), httpBackends, "NodePort", "Cluster")
				// Add service corresponding to IPv6 address of the nodes so that they become
				// reachable from outside the cluster.
				ciliumAddServiceOnNode(kubectl, helpers.K8s1, 31082, net.JoinHostPort(ni.primaryK8s1IPv6, fmt.Sprintf("%d", data.Spec.Ports[0].NodePort)),
					httpBackends, "NodePort", "Cluster")
				ciliumAddServiceOnNode(kubectl, helpers.K8s2, 31082, net.JoinHostPort(ni.primaryK8s2IPv6, fmt.Sprintf("%d", data.Spec.Ports[0].NodePort)),
					httpBackends, "NodePort", "Cluster")

				tftpBackends := ciliumIPv6Backends(kubectl, "-l k8s:zgroup=testDS,k8s:io.kubernetes.pod.namespace=default", "69")
				ciliumAddService(kubectl, 31069, net.JoinHostPort(testDSIPv6, fmt.Sprintf("%d", data.Spec.Ports[1].NodePort)), tftpBackends, "NodePort", "Cluster")
				ciliumAddService(kubectl, 31070, net.JoinHostPort("::", fmt.Sprintf("%d", data.Spec.Ports[1].NodePort)), tftpBackends, "NodePort", "Cluster")
				ciliumAddServiceOnNode(kubectl, helpers.K8s1, 31071, net.JoinHostPort(ni.primaryK8s1IPv6, fmt.Sprintf("%d", data.Spec.Ports[1].NodePort)),
					tftpBackends, "NodePort", "Cluster")
				ciliumAddServiceOnNode(kubectl, helpers.K8s2, 31071, net.JoinHostPort(ni.primaryK8s2IPv6, fmt.Sprintf("%d", data.Spec.Ports[1].NodePort)),
					tftpBackends, "NodePort", "Cluster")
			})

			AfterAll(func() {
				ciliumDelService(kubectl, 31080)
				ciliumDelService(kubectl, 31081)
				ciliumDelService(kubectl, 31082)
				ciliumDelService(kubectl, 31069)
				ciliumDelService(kubectl, 31070)
				ciliumDelService(kubectl, 31071)
			})

			It("Test IPv6 connectivity to NodePort service", func() {
				testNodePortIPv6(kubectl, ni, helpers.ExistNodeWithoutCilium(), &data)
			})
		})

		Context("TFTP with DNS Proxy port collision", func() {
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
				// Explicitly ignore result of deletion of resources to avoid incomplete
				// teardown if any step fails.
				_ = kubectl.Delete(demoPolicy)
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
				url := getTFTPLink(ni.k8s2IP, data.Spec.Ports[1].NodePort) + fmt.Sprintf(" --local-port %d", DNSProxyPort2)
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
					url := getTFTPLink(ni.primaryK8s2IPv6, data.Spec.Ports[1].NodePort) + fmt.Sprintf(" --local-port %d", DNSProxyPort2)
					cmd := testCommand(helpers.CurlFailNoStats(url), count, fails)
					By("Making %d curl requests from %s pod to service %s using source port %d", count, clientPod, url, DNSProxyPort2)
					res := kubectl.ExecPodCmd(helpers.DefaultNamespace, clientPod, cmd)
					Expect(res).Should(helpers.CMDSuccess(), "Request from %s pod to service %s failed", clientPod, url)
				}
			})
		})

		Context("with L4 policy", func() {
			var (
				demoPolicy string
			)

			BeforeAll(func() {
				demoPolicy = helpers.ManifestGet(kubectl.BasePath(), "l4-policy-demo.yaml")
			})

			AfterAll(func() {
				// Explicitly ignore result of deletion of resources to avoid incomplete
				// teardown if any step fails.
				_ = kubectl.Delete(demoPolicy)
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
				testNodePort(kubectl, ni, false, false, false, 0)
			})
		})

		SkipContextIf(helpers.RunsWithKubeProxyReplacement, "with L7 policy", func() {
			AfterAll(func() {
				// Explicitly ignore result of deletion of resources to avoid incomplete
				// teardown if any step fails.
				_ = kubectl.Delete(demoPolicyL7)
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
				testNodePort(kubectl, ni, false, false, false, 0)
			})
		})

		SkipContextIf(helpers.DoesNotRunWithKubeProxyReplacement, "Tests NodePort BPF",
			func() {
				BeforeAll(func() {
					enableBackgroundReport = false
				})

				AfterAll(func() {
					enableBackgroundReport = true
				})

				Context("Tests with vxlan", func() {
					It("Tests NodePort", func() {
						testNodePort(kubectl, ni, true, false, helpers.ExistNodeWithoutCilium(), 0)
					})

					It("Tests NodePort with externalTrafficPolicy=Local", func() {
						testExternalTrafficPolicyLocal(kubectl, ni)
					})

					It("Tests NodePort with sessionAffinity", func() {
						testSessionAffinity(kubectl, ni, false, true)
					})

					SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests NodePort with sessionAffinity from outside", func() {
						testSessionAffinity(kubectl, ni, true, true)
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

					SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests externalIPs", func() {
						testExternalIPs(kubectl, ni)
					})

					SkipContextIf(helpers.RunsOnGKE, "With host policy", func() {
						var ccnpHostPolicy string

						BeforeAll(func() {
							DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
								"hostFirewall": "true",
							})

							ccnpHostPolicy = helpers.ManifestGet(kubectl.BasePath(), "ccnp-host-policy-nodeport-tests.yaml")
							_, err := kubectl.CiliumPolicyAction(helpers.DefaultNamespace, ccnpHostPolicy,
								helpers.KubectlApply, helpers.HelperTimeout)
							Expect(err).Should(BeNil(),
								"Policy %s cannot be applied", ccnpHostPolicy)
						})

						AfterAll(func() {
							_, err := kubectl.CiliumPolicyAction(helpers.DefaultNamespace, ccnpHostPolicy,
								helpers.KubectlDelete, helpers.HelperTimeout)
							Expect(err).Should(BeNil(),
								"Policy %s cannot be deleted", ccnpHostPolicy)

							DeployCiliumAndDNS(kubectl, ciliumFilename)
						})

						It("Tests NodePort", func() {
							testNodePort(kubectl, ni, true, false, helpers.ExistNodeWithoutCilium(), 0)
						})
					})

					Context("with L7 policy", func() {
						AfterAll(func() { kubectl.Delete(demoPolicyL7) })

						It("Tests NodePort with L7 Policy", func() {
							applyPolicy(kubectl, demoPolicyL7)
							testNodePort(kubectl, ni, false, false, false, 0)
						})
					})

					Context("Tests NodePort with Maglev", func() {
						var echoYAML string

						BeforeAll(func() {
							DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
								"loadBalancer.algorithm": "maglev",
								// The echo svc has two backends. the closest supported
								// prime number which is greater than 100 * |backends_count|
								// is 251.
								"maglev.tableSize": "251",
								// Support for host firewall + Maglev is currently broken,
								// see #14047 for details.
								"hostFirewall": "false",
							})

							echoYAML = helpers.ManifestGet(kubectl.BasePath(), "echo-svc.yaml")
							kubectl.ApplyDefault(echoYAML).ExpectSuccess("unable to apply %s", echoYAML)
							err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l name=echo", helpers.HelperTimeout)
							Expect(err).Should(BeNil())
						})

						AfterAll(func() {
							kubectl.Delete(echoYAML)
						})

						It("Tests NodePort", func() {
							testNodePort(kubectl, ni, true, false, helpers.ExistNodeWithoutCilium(), 0)
						})

						SkipItIf(helpers.DoesNotExistNodeWithoutCilium,
							"Tests Maglev backend selection", func() {
								testMaglev(kubectl, ni)
							})
					})

					SkipItIf(func() bool {
						// Quarantine when running with the third node as it's
						// flaky. See #12511.
						return helpers.GetCurrentIntegration() != "" ||
							(helpers.SkipQuarantined() && helpers.ExistNodeWithoutCilium())
					}, "Tests with secondary NodePort device", func() {
						DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
							"devices": fmt.Sprintf(`'{%s,%s}'`, ni.privateIface, helpers.SecondaryIface),
						})

						testNodePort(kubectl, ni, true, true, helpers.ExistNodeWithoutCilium(), 0)
					})
				})

				Context("Tests with direct routing", func() {

					var directRoutingOpts = map[string]string{
						"tunnel":               "disabled",
						"autoDirectNodeRoutes": "true",
					}

					BeforeAll(func() {
						DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, directRoutingOpts)
					})

					It("Tests NodePort", func() {
						testNodePort(kubectl, ni, true, false, helpers.ExistNodeWithoutCilium(), 0)
					})

					It("Tests NodePort with externalTrafficPolicy=Local", func() {
						testExternalTrafficPolicyLocal(kubectl, ni)
					})

					It("Tests NodePort with sessionAffinity", func() {
						testSessionAffinity(kubectl, ni, false, false)
					})

					SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests NodePort with sessionAffinity from outside", func() {
						testSessionAffinity(kubectl, ni, true, false)
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

					SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests externalIPs", func() {
						testExternalIPs(kubectl, ni)
					})

					SkipContextIf(helpers.RunsOnGKE, "With host policy", func() {
						var ccnpHostPolicy string

						BeforeAll(func() {
							DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
								"tunnel":               "disabled",
								"autoDirectNodeRoutes": "true",
								"hostFirewall":         "true",
							})

							ccnpHostPolicy = helpers.ManifestGet(kubectl.BasePath(), "ccnp-host-policy-nodeport-tests.yaml")
							_, err := kubectl.CiliumPolicyAction(helpers.DefaultNamespace, ccnpHostPolicy,
								helpers.KubectlApply, helpers.HelperTimeout)
							Expect(err).Should(BeNil(),
								"Policy %s cannot be applied", ccnpHostPolicy)
						})

						AfterAll(func() {
							_, err := kubectl.CiliumPolicyAction(helpers.DefaultNamespace, ccnpHostPolicy,
								helpers.KubectlDelete, helpers.HelperTimeout)
							Expect(err).Should(BeNil(),
								"Policy %s cannot be deleted", ccnpHostPolicy)

							DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
								"tunnel":               "disabled",
								"autoDirectNodeRoutes": "true",
							})
						})

						It("Tests NodePort", func() {
							testNodePort(kubectl, ni, true, false, helpers.ExistNodeWithoutCilium(), 0)
						})
					})

					Context("with L7 policy", func() {
						AfterAll(func() { kubectl.Delete(demoPolicyL7) })

						It("Tests NodePort with L7 Policy", func() {
							applyPolicy(kubectl, demoPolicyL7)
							testNodePort(kubectl, ni, false, false, false, 0)
						})
					})

					Context("Tests NodePort with Maglev", func() {
						var echoYAML string

						BeforeAll(func() {
							DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
								"tunnel":                 "disabled",
								"autoDirectNodeRoutes":   "true",
								"loadBalancer.algorithm": "maglev",
								// The echo svc has two backends. the closest supported
								// prime number which is greater than 100 * |backends_count|
								// is 251.
								"maglev.tableSize": "251",
								// Support for host firewall + Maglev is currently broken,
								// see #14047 for details.
								"hostFirewall": "false",
							})

							echoYAML = helpers.ManifestGet(kubectl.BasePath(), "echo-svc.yaml")
							kubectl.ApplyDefault(echoYAML).ExpectSuccess("unable to apply %s", echoYAML)
							err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l name=echo", helpers.HelperTimeout)
							Expect(err).Should(BeNil())
						})

						AfterAll(func() {
							_ = kubectl.Delete(echoYAML)
						})

						It("Tests NodePort", func() {
							testNodePort(kubectl, ni, true, false, helpers.ExistNodeWithoutCilium(), 0)
						})

						SkipItIf(helpers.DoesNotExistNodeWithoutCilium,
							"Tests Maglev backend selection", func() {
								testMaglev(kubectl, ni)
							})
					})

					SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests GH#10983", func() {
						var data v1.Service

						// We need two NodePort services with the same single endpoint,
						// so thus we choose the "test-nodeport{-local,}-k8s2" svc.
						// Both svcs will be accessed via the k8s2 node, because
						// "test-nodeport-local-k8s2" has the local external traffic
						// policy.
						err := kubectl.Get(helpers.DefaultNamespace, "svc test-nodeport-local-k8s2").Unmarshal(&data)
						Expect(err).Should(BeNil(), "Can not retrieve service")
						svc1URL := getHTTPLink(ni.k8s2IP, data.Spec.Ports[0].NodePort)
						err = kubectl.Get(helpers.DefaultNamespace, "svc test-nodeport-k8s2").Unmarshal(&data)
						Expect(err).Should(BeNil(), "Can not retrieve service")
						svc2URL := getHTTPLink(ni.k8s2IP, data.Spec.Ports[0].NodePort)

						// Send two requests from the same src IP and port to the endpoint
						// via two different NodePort svc to trigger the stale conntrack
						// entry issue. Once it's fixed, the second request should not
						// fail.
						testCurlFromOutsideWithLocalPort(kubectl, ni, svc1URL, 1, false, 64002)
						time.Sleep(120 * time.Second) // to reuse the source port
						testCurlFromOutsideWithLocalPort(kubectl, ni, svc2URL, 1, false, 64002)
					})

					SkipContextIf(helpers.DoesNotExistNodeWithoutCilium, "Tests LoadBalancer", func() {
						var (
							frr      string // BGP router
							routerIP string

							bgpConfigMap string

							lbSVC string

							ciliumPodK8s1, ciliumPodK8s2 string
							testStartTime                time.Time
						)

						BeforeAll(func() {
							frr = applyFRRTemplate(kubectl, ni)
							kubectl.ApplyDefault(frr).ExpectSuccess("Unable to apply rendered tempplate %s", frr)

							Eventually(func() string {
								frrPod, err := kubectl.GetPodsIPs(helpers.KubeSystemNamespace, "app=frr")
								if _, ok := frrPod["frr"]; err != nil || !ok {
									return ""
								}
								routerIP = frrPod["frr"]
								return routerIP
							}, 30*time.Second, 1*time.Second).Should(Not(BeEmpty()), "BGP router is not ready")

							bgpConfigMap = applyBGPCMTemplate(kubectl, routerIP)
							kubectl.ApplyDefault(bgpConfigMap).ExpectSuccess("Unable to apply BGP ConfigMap %s", bgpConfigMap)

							RedeployCiliumWithMerge(kubectl, ciliumFilename, directRoutingOpts,
								map[string]string{
									"bgp.enabled":                 "true",
									"bgp.announce.loadbalancerIP": "true",

									"debug.verbose": "datapath", // https://github.com/cilium/cilium/issues/16399
								})

							lbSVC = helpers.ManifestGet(kubectl.BasePath(), "test_lb_with_ip.yaml")
							kubectl.ApplyDefault(lbSVC).ExpectSuccess("Unable to apply %s", lbSVC)

							var err error
							ciliumPodK8s1, err = kubectl.GetCiliumPodOnNode(helpers.K8s1)
							ExpectWithOffset(1, err).ShouldNot(HaveOccurred(), "Cannot determine cilium pod name")
							ciliumPodK8s2, err = kubectl.GetCiliumPodOnNode(helpers.K8s2)
							ExpectWithOffset(1, err).ShouldNot(HaveOccurred(), "Cannot determine cilium pod name")
							testStartTime = time.Now()
						})

						AfterAll(func() {
							kubectl.Delete(frr)
							kubectl.Delete(bgpConfigMap)
							kubectl.Delete(lbSVC)
							// Delete temp files
							os.Remove(frr)
							os.Remove(bgpConfigMap)
						})

						AfterFailed(func() {
							res := kubectl.CiliumExecContext(
								context.TODO(),
								ciliumPodK8s1,
								fmt.Sprintf(
									"hubble observe debug-events --since %v -o json",
									testStartTime.Format(time.RFC3339),
								),
							)
							helpers.WriteToReportFile(
								res.CombineOutput().Bytes(),
								"tests-loadbalancer-hubble-observe-debug-events-k8s1.log",
							)
							res = kubectl.CiliumExecContext(
								context.TODO(),
								ciliumPodK8s2,
								fmt.Sprintf(
									"hubble observe debug-events --since %v -o json",
									testStartTime.Format(time.RFC3339),
								),
							)
							helpers.WriteToReportFile(
								res.CombineOutput().Bytes(),
								"tests-loadbalancer-hubble-observe-debug-events-k8s2.log",
							)
						})

						It("Connectivity to endpoint via LB", func() {
							By("Waiting until the Operator has assigned the LB IP")
							lbIP, err := kubectl.GetLoadBalancerIP(
								helpers.DefaultNamespace, lbSvcName, 30*time.Second)
							Expect(err).Should(BeNil(), "Cannot retrieve LB IP for test-lb")

							By("Waiting until the Agents have announced the LB IP via BGP")
							Eventually(func() string {
								return kubectl.ExecInHostNetNS(
									context.TODO(),
									ni.outsideNodeName,
									"ip route",
								).GetStdOut().String()
							}, 30*time.Second, 1*time.Second).Should(ContainSubstring(lbIP),
								"BGP router does not have route for LB IP")

							// Check connectivity from outside
							url := "http://" + lbIP
							testCurlFromOutside(kubectl, ni, url, 10, false)

							// Patch service to add a LB source range to disallow requests
							// from the outsideNode
							kubectl.Patch(helpers.DefaultNamespace, "service", lbSvcName,
								`{"spec": {"loadBalancerSourceRanges": ["1.1.1.0/24"]}}`)
							time.Sleep(5 * time.Second)
							testCurlFailFromOutside(kubectl, ni, url, 1)
							// Patch again, but this time add outsideNode IP addr
							kubectl.Patch(helpers.DefaultNamespace, "service", lbSvcName,
								fmt.Sprintf(
									`{"spec": {"loadBalancerSourceRanges": ["1.1.1.0/24", "%s/32"]}}`,
									ni.outsideIP))
							time.Sleep(5 * time.Second)
							testCurlFromOutside(kubectl, ni, url, 10, false)
						})
					})
				})

				SkipContextIf(func() bool { return helpers.DoesNotRunOnNetNextKernel() || helpers.DoesNotExistNodeWithoutCilium() },
					"Tests L2-less with Wireguard provisioned via kube-wireguarder", func() {
						var wgYAML string

						BeforeAll(func() {
							// kube-wireguarder will setup wireguard tunnels and patch CiliumNode
							// objects so that wg IP addrs will be used for pod direct routing
							// routes.
							wgYAML = helpers.ManifestGet(kubectl.BasePath(), "kube-wireguarder.yaml")
							res := kubectl.ApplyDefault(wgYAML)
							Expect(res).Should(helpers.CMDSuccess(), "unable to apply %s", wgYAML)
							err := kubectl.WaitforPods(helpers.KubeSystemNamespace, "-l app=kube-wireguarder", time.Duration(240*time.Second))
							Expect(err).Should(BeNil())
						})

						AfterAll(func() {
							// First delete DS, as otherwise the cleanup routine executed upon
							// SIGTERM won't have access to k8s {Cilium,}Node objects.
							kubectl.DeleteResource("ds", "-n "+helpers.KubeSystemNamespace+" kube-wireguarder --wait=true")
							kubectl.WaitTerminatingPodsInNsWithFilter(helpers.KubeSystemNamespace, "-l app=kube-wireguarder", helpers.HelperTimeout)
							kubectl.Delete(wgYAML)
							// The SIGTEM based cleanup is not reliable enough, so just in case
							// remove  wg0 ifaces on each node.
							for _, node := range []string{ni.k8s1NodeName, ni.k8s2NodeName, ni.outsideNodeName} {
								kubectl.ExecInHostNetNS(context.TODO(), node, "ip l del wg0")
							}
						})

						It("Tests NodePort BPF", func() {
							var data v1.Service
							err := kubectl.Get(helpers.DefaultNamespace, "service test-nodeport").Unmarshal(&data)
							Expect(err).Should(BeNil(), "Cannot retrieve service")

							By("SNAT with direct routing device wg0")

							DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
								"devices":                      fmt.Sprintf(`'{%s,%s}'`, ni.privateIface, "wg0"),
								"nodePort.directRoutingDevice": "wg0",
								"tunnel":                       "disabled",
								"autoDirectNodeRoutes":         "true",
							})

							// Test via k8s1 private iface
							url := getHTTPLink(ni.k8s1IP, data.Spec.Ports[0].NodePort)
							testCurlFromOutside(kubectl, ni, url, 10, false)
							// Test via k8s1 wg0 iface
							wgK8s1IPv4 := getIPv4AddrForIface(kubectl, ni.k8s1NodeName, "wg0")
							url = getHTTPLink(wgK8s1IPv4, data.Spec.Ports[0].NodePort)
							testCurlFromOutside(kubectl, ni, url, 10, false)

							// DSR when direct routing device is wg0 does not make
							// much sense, as all possible client IPs should be specified
							// in wg's allowed IPs on k8s2. Otherwise, a forwarded
							// request with the original client IP by k8s1 will be
							// dropped by k8s2. Therefore, we are not testing such
							// case.

							// Disable setting direct routes via kube-wireguarder, as non-wg device
							// is going to be used for direct routing.
							res := kubectl.Patch(helpers.KubeSystemNamespace, "configmap", "kube-wireguarder-config",
								`{"data":{"setup-direct-routes": "false"}}`)
							res.ExpectSuccess("Failed to patch kube-wireguarder-config")
							res = kubectl.DeleteResource("pod", "-n "+helpers.KubeSystemNamespace+" -l app=kube-wireguarder --wait=true")
							res.ExpectSuccess("Failed to delete kube-wireguarder pods")

							By("SNAT with direct routing device private")

							DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
								"devices":                      fmt.Sprintf(`'{%s,%s}'`, ni.privateIface, "wg0"),
								"nodePort.directRoutingDevice": ni.privateIface,
								"tunnel":                       "disabled",
								"autoDirectNodeRoutes":         "true",
							})

							// Test via k8s1 private iface
							url = getHTTPLink(ni.k8s1IP, data.Spec.Ports[0].NodePort)
							testCurlFromOutside(kubectl, ni, url, 10, false)
							// Test via k8s1 wg0 iface
							url = getHTTPLink(wgK8s1IPv4, data.Spec.Ports[0].NodePort)
							testCurlFromOutside(kubectl, ni, url, 10, false)

							By("DSR with direct routing device private")

							// Do the same test for DSR
							DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
								"devices":                      fmt.Sprintf(`'{%s,%s}'`, ni.privateIface, "wg0"),
								"nodePort.directRoutingDevice": ni.privateIface,
								"tunnel":                       "disabled",
								"autoDirectNodeRoutes":         "true",
								"loadBalancer.mode":            "dsr",
							})

							// Test via k8s1 private iface
							url = getHTTPLink(ni.k8s1IP, data.Spec.Ports[0].NodePort)
							testCurlFromOutside(kubectl, ni, url, 10, false)
							// Sending over k8s1 wg0 iface won't work, as a DSR reply
							// from k8s2 to k8s3 (client) will have a src IP of k8s1
							// wg0 iface. Because there cannot be overlapping allowed
							// IPs, we cannot configure wireguard for such cases.
						})
					})

				SkipItIf(func() bool {
					// Quarantine when running with the third node as it's
					// flaky. See #12511.
					return helpers.GetCurrentIntegration() != "" ||
						(helpers.SkipQuarantined() && helpers.ExistNodeWithoutCilium())
				}, "Tests with secondary NodePort device", func() {
					DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
						"tunnel":               "disabled",
						"autoDirectNodeRoutes": "true",
						"loadBalancer.mode":    "snat",
						"devices":              fmt.Sprintf(`'{%s,%s}'`, ni.privateIface, helpers.SecondaryIface),
					})

					testNodePort(kubectl, ni, true, true, helpers.ExistNodeWithoutCilium(), 0)
				})

				SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests with direct routing and DSR", func() {
					DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
						"loadBalancer.mode":    "dsr",
						"tunnel":               "disabled",
						"autoDirectNodeRoutes": "true",
					})

					testDSR(kubectl, ni, 64000)
					testNodePort(kubectl, ni, true, false, false, 0)
				})

				SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests with XDP, direct routing, SNAT and Random", func() {
					DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
						"loadBalancer.acceleration": "testing-only",
						"loadBalancer.mode":         "snat",
						"loadBalancer.algorithm":    "random",
						"tunnel":                    "disabled",
						"autoDirectNodeRoutes":      "true",
						"devices":                   fmt.Sprintf(`'{%s}'`, ni.privateIface),
					})
					testNodePortExternal(kubectl, ni, false, false)
				})

				SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests with XDP, direct routing, SNAT and Maglev", func() {
					DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
						"loadBalancer.acceleration": "testing-only",
						"loadBalancer.mode":         "snat",
						"loadBalancer.algorithm":    "maglev",
						"maglev.tableSize":          "251",
						"tunnel":                    "disabled",
						"autoDirectNodeRoutes":      "true",
						"devices":                   fmt.Sprintf(`'{%s}'`, ni.privateIface),
						// Support for host firewall + Maglev is currently broken,
						// see #14047 for details.
						"hostFirewall": "false",
					})
					testNodePortExternal(kubectl, ni, false, false)
				})

				SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests with XDP, direct routing, Hybrid and Random", func() {
					DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
						"loadBalancer.acceleration": "testing-only",
						"loadBalancer.mode":         "hybrid",
						"loadBalancer.algorithm":    "random",
						"tunnel":                    "disabled",
						"autoDirectNodeRoutes":      "true",
						"devices":                   fmt.Sprintf(`'{%s}'`, ni.privateIface),
					})
					testNodePortExternal(kubectl, ni, true, false)
				})

				SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests with XDP, direct routing, Hybrid and Maglev", func() {
					DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
						"loadBalancer.acceleration": "testing-only",
						"loadBalancer.mode":         "hybrid",
						"loadBalancer.algorithm":    "maglev",
						"maglev.tableSize":          "251",
						"tunnel":                    "disabled",
						"autoDirectNodeRoutes":      "true",
						"devices":                   fmt.Sprintf(`'{%s}'`, ni.privateIface),
						// Support for host firewall + Maglev is currently broken,
						// see #14047 for details.
						"hostFirewall": "false",
					})
					testNodePortExternal(kubectl, ni, true, false)
				})

				SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests with XDP, direct routing, DSR and Random", func() {
					DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
						"loadBalancer.acceleration": "testing-only",
						"loadBalancer.mode":         "dsr",
						"loadBalancer.algorithm":    "random",
						"tunnel":                    "disabled",
						"autoDirectNodeRoutes":      "true",
						"devices":                   fmt.Sprintf(`'{%s}'`, ni.privateIface),
					})
					testNodePortExternal(kubectl, ni, true, true)
				})

				SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests with XDP, direct routing, DSR and Maglev", func() {
					DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
						"loadBalancer.acceleration": "testing-only",
						"loadBalancer.mode":         "dsr",
						"loadBalancer.algorithm":    "maglev",
						"maglev.tableSize":          "251",
						"tunnel":                    "disabled",
						"autoDirectNodeRoutes":      "true",
						"devices":                   fmt.Sprintf(`'{%s}'`, ni.privateIface),
						// Support for host firewall + Maglev is currently broken,
						// see #14047 for details.
						"hostFirewall": "false",
					})
					testNodePortExternal(kubectl, ni, true, true)
				})

				SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests with TC, direct routing and Hybrid", func() {
					DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
						"loadBalancer.acceleration": "disabled",
						"loadBalancer.mode":         "hybrid",
						"loadBalancer.algorithm":    "random",
						"tunnel":                    "disabled",
						"autoDirectNodeRoutes":      "true",
						"devices":                   fmt.Sprintf(`'{}'`), // Revert back to auto-detection after XDP.
					})
					testNodePortExternal(kubectl, ni, true, false)
				})
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

		validateEgress := func(kubectl *helpers.Kubectl) {
			By("Checking that toServices CIDR is plumbed into the policy")
			Eventually(func() string {
				output, err := kubectl.LoadedPolicyInFirstAgent()
				ExpectWithOffset(1, err).To(BeNil(), "unable to retrieve policy")
				return output
			}, 2*time.Minute, 2*time.Second).Should(ContainSubstring(expectedCIDR))
		}

		validateEgressAfterDeletion := func(kubectl *helpers.Kubectl) {
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

			applyPolicy(kubectl, policyPath)
			validateEgress(kubectl)

			kubectl.Delete(policyPath)
			kubectl.Delete(endpointPath)
			validateEgressAfterDeletion(kubectl)
		})

		It("To Services first policy", func() {
			applyPolicy(kubectl, policyPath)
			res := kubectl.ApplyDefault(endpointPath)
			res.ExpectSuccess()

			validateEgress(kubectl)

			kubectl.Delete(policyPath)
			kubectl.Delete(endpointPath)
			validateEgressAfterDeletion(kubectl)
		})

		It("To Services first endpoint creation match service by labels", func() {
			By("Creating Kubernetes Endpoint")
			res := kubectl.ApplyDefault(endpointPath)
			res.ExpectSuccess()

			applyPolicy(kubectl, policyLabeledPath)

			validateEgress(kubectl)

			kubectl.Delete(policyLabeledPath)
			kubectl.Delete(endpointPath)
			validateEgressAfterDeletion(kubectl)
		})

		It("To Services first policy, match service by labels", func() {
			applyPolicy(kubectl, policyLabeledPath)

			By("Creating Kubernetes Endpoint")
			res := kubectl.ApplyDefault(endpointPath)
			res.ExpectSuccess()

			validateEgress(kubectl)

			kubectl.Delete(policyLabeledPath)
			kubectl.Delete(endpointPath)
			validateEgressAfterDeletion(kubectl)
		})
	})
})
