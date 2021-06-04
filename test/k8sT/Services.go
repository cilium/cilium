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
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	"github.com/asaskevich/govalidator"
	. "github.com/onsi/gomega"
	v1 "k8s.io/api/core/v1"
)

// The 5.4 CI job is intended to catch BPF complexity regressions and as such
// doesn't need to execute this test suite.
var _ = SkipDescribeIf(helpers.RunsOn54Kernel, "K8sServicesTest", func() {
	var (
		kubectl        *helpers.Kubectl
		ciliumFilename string

		backgroundCancel       context.CancelFunc = func() {}
		backgroundError        error
		enableBackgroundReport = true

		k8s1NodeName    string
		k8s2NodeName    string
		outsideNodeName string
		k8s1IP          string
		k8s2IP          string
		outsideIP       string
		privateIface    string
	)

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

		k8s1NodeName, k8s1IP = kubectl.GetNodeInfo(helpers.K8s1)
		k8s2NodeName, k8s2IP = kubectl.GetNodeInfo(helpers.K8s2)
		if helpers.ExistNodeWithoutCilium() {
			outsideNodeName, outsideIP = kubectl.GetNodeInfo(helpers.GetNodeWithoutCilium())
		}

		privateIface, err = kubectl.GetPrivateIface()
		Expect(err).Should(BeNil(), "Cannot determine private iface")

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

	applyPolicy := func(path string) {
		By(fmt.Sprintf("Applying policy %s", path))
		_, err := kubectl.CiliumPolicyAction(helpers.DefaultNamespace, path, helpers.KubectlApply, helpers.HelperTimeout)
		ExpectWithOffset(1, err).Should(BeNil(), fmt.Sprintf("Error creating resource %s: %s", path, err))
	}

	ciliumIPv6Backends := func(label string, port string) (backends []string) {
		ciliumPods, err := kubectl.GetCiliumPods()
		Expect(err).To(BeNil(), "Cannot get cilium pods")
		for _, pod := range ciliumPods {
			endpointIPs := kubectl.CiliumEndpointIPv6(pod, label)
			for _, ip := range endpointIPs {
				backends = append(backends, net.JoinHostPort(ip, port))
			}
		}
		ExpectWithOffset(1, backends).To(Not(BeEmpty()), "Cannot find any IPv6 backends")
		return backends
	}

	ciliumAddService := func(id int64, frontend string, backends []string, svcType, trafficPolicy string) {
		ciliumPods, err := kubectl.GetCiliumPods()
		ExpectWithOffset(1, err).To(BeNil(), "Cannot get cilium pods")
		for _, pod := range ciliumPods {
			err := kubectl.CiliumServiceAdd(pod, id, frontend, backends, svcType, trafficPolicy)
			ExpectWithOffset(1, err).To(BeNil(), "Failed to add cilium service")
		}
	}

	ciliumAddServiceOnNode := func(node string, id int64, frontend string, backends []string, svcType, trafficPolicy string) {
		ciliumPod, err := kubectl.GetCiliumPodOnNode(node)
		ExpectWithOffset(1, err).To(BeNil(), fmt.Sprintf("Cannot get cilium pod on node %s", node))

		err = kubectl.CiliumServiceAdd(ciliumPod, id, frontend, backends, svcType, trafficPolicy)
		ExpectWithOffset(1, err).To(BeNil(), fmt.Sprintf("Failed to add cilium service on node %s", node))
	}

	ciliumDelService := func(id int64) {
		ciliumPods, err := kubectl.GetCiliumPods()
		ExpectWithOffset(1, err).To(BeNil(), "Cannot get cilium pods")
		for _, pod := range ciliumPods {
			// ignore result so tear down still continues on failures
			_ = kubectl.CiliumServiceDel(pod, id)
		}
	}

	ciliumHasServiceIP := func(pod, vip string) bool {
		service := kubectl.CiliumExecMustSucceed(context.TODO(), pod, "cilium service list", "Cannot retrieve services on cilium Pod")
		vip4 := fmt.Sprintf(" %s:", vip)
		if strings.Contains(service.Stdout(), vip4) {
			return true
		}
		vip6 := fmt.Sprintf(" [%s]:", vip)
		return strings.Contains(service.Stdout(), vip6)
	}

	newlineRegexp := regexp.MustCompile(`\n[ \t\n]*`)
	trimNewlines := func(script string) string {
		return newlineRegexp.ReplaceAllLiteralString(script, " ")
	}

	// Return a command string for bash test loop.
	testCommand := func(cmd string, count, fails int) string {
		// Repeat 'cmd' 'count' times, while recording return codes of failed invocations.
		// Successful cmd exit values are also echoed for debugging this script itself.
		// Prints "failed:" followed by colon separated list of command ordinals and exit codes.
		// Returns success (0) if no more than 'fails' rounds fail, otherwise returns 42.
		//
		// Note: All newlines and the following whitespace is removed from the script below.
		//       This requires explicit semicolons also at the ends of lines!
		return trimNewlines(fmt.Sprintf(
			`/bin/bash -c
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

	Context("Testing test script", func() {
		It("Validating test script correctness", func() {
			By("Validating test script correctness")
			res := kubectl.ExecInHostNetNS(context.TODO(), k8s1NodeName, testCommand("echo FOOBAR", 1, 0))
			ExpectWithOffset(1, res).Should(helpers.CMDSuccess(), "Test script could not 'echo'")
			res.ExpectContains("FOOBAR", "Test script failed to execute echo: %s", res.Stdout())

			res = kubectl.ExecInHostNetNS(context.TODO(), k8s1NodeName, testCommand("FOOBAR", 3, 0))
			ExpectWithOffset(1, res).ShouldNot(helpers.CMDSuccess(), "Test script successfully executed FOOBAR")
			res.ExpectMatchesRegexp("failed: :[0-9]*/1=127:[0-9]*/2=127:[0-9]*/3=127", "Test script failed to execute echo 3 times: %s", res.Stdout())

			res = kubectl.ExecInHostNetNS(context.TODO(), k8s1NodeName, testCommand("FOOBAR", 1, 1))
			ExpectWithOffset(1, res).Should(helpers.CMDSuccess(), "Test script could not allow failure")

			res = kubectl.ExecInHostNetNS(context.TODO(), k8s1NodeName, testCommand("echo FOOBAR", 3, 0))
			ExpectWithOffset(1, res).Should(helpers.CMDSuccess(), "Test script could not 'echo' three times")
			res.ExpectMatchesRegexp("(?s)(FOOBAR.*exit code: 0.*){3}", "Test script failed to execute echo 3 times: %s", res.Stdout())
		})
	})

	testCurlFromPods := func(clientPodLabel, url string, count, fails int) {
		pods, err := kubectl.GetPodNames(helpers.DefaultNamespace, clientPodLabel)
		ExpectWithOffset(1, err).Should(BeNil(), "cannot retrieve pod names by filter %q", clientPodLabel)
		cmd := testCommand(helpers.CurlFailNoStats(url), count, fails)
		for _, pod := range pods {
			By("Making %d curl requests from %s pod to service %s", count, pod, url)
			res := kubectl.ExecPodCmd(helpers.DefaultNamespace, pod, cmd)
			ExpectWithOffset(1, res).Should(helpers.CMDSuccess(), "Request from %s pod to service %s failed", pod, url)
		}
	}

	testCurlFromPodWithSourceIPCheck :=
		func(clientPodLabel, url string, count int, sourceIP string) {
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
						outIP := net.ParseIP(strings.TrimSpace(strings.Split(res.Stdout(), "=")[1]))
						srcIP := net.ParseIP(sourceIP)
						ExpectWithOffset(1, outIP).To(Equal(srcIP))
					}
				}
			}
		}

	testCurlFromPodsFail := func(clientPodLabel, url string) {
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

	Context("Checks ClusterIP Connectivity", func() {
		const (
			serviceName              = "app1-service"
			serviceNameIPv6          = "app1-service-ipv6"
			echoServiceName          = "echo"
			echoServiceNameDualStack = "echo-dualstack"
			echoPodLabel             = "name=echo"
			app2PodLabel             = "id=app2"
			// echoServiceNameIPv6 = "echo-ipv6"
		)

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
			serviceNames := []string{serviceName}
			if helpers.DualStackSupported() {
				serviceNames = append(serviceNames, serviceNameIPv6)
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

				status := kubectl.ExecInHostNetNS(context.TODO(), k8s1NodeName,
					helpers.CurlFail(httpSVCURL))
				Expect(status).Should(helpers.CMDSuccess(), "cannot curl to service IP from host: %s", status.CombineOutput())

				status = kubectl.ExecInHostNetNS(context.TODO(), k8s1NodeName,
					helpers.CurlFail(tftpSVCURL))
				Expect(status).Should(helpers.CMDSuccess(), "cannot curl to service IP from host: %s", status.CombineOutput())

				for _, pod := range ciliumPods {
					Expect(ciliumHasServiceIP(pod, clusterIP)).Should(BeTrue(),
						"ClusterIP is not present in the cilium service list")
				}
				// Send requests from "app2" pod which runs on the same node as
				// "app1" pods
				testCurlFromPods(app2PodLabel, httpSVCURL, 10, 0)
				testCurlFromPods(app2PodLabel, tftpSVCURL, 10, 0)
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
						if ciliumHasServiceIP(pod, clusterIP) {
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
				testCurlFromPods(app2PodLabel, url, 10, 0)
				url = fmt.Sprintf("tftp://%s/hello", net.JoinHostPort(clusterIP, "69"))
				testCurlFromPods(app2PodLabel, url, 10, 0)
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
				testCurlFromPods(echoPodLabel, url, 10, 0)
				url = fmt.Sprintf("tftp://%s/hello", net.JoinHostPort(clusterIP, "69"))
				testCurlFromPods(echoPodLabel, url, 10, 0)
			}

		}, 600)

		SkipContextIf(manualIPv6TestingNotRequired(helpers.DoesNotRunWithKubeProxyReplacement), "IPv6 Connectivity", func() {
			// Because the deployed K8s does not have dual-stack mode enabled,
			// we install the Cilium service rules manually via Cilium CLI.
			demoClusterIPv6 := "fd03::100"
			echoClusterIPv6 := "fd03::200"

			BeforeAll(func() {
				// Installs the IPv6 equivalent of app1-service (demo.yaml)
				httpBackends := ciliumIPv6Backends("-l k8s:id=app1,k8s:io.kubernetes.pod.namespace=default", "80")
				ciliumAddService(10080, net.JoinHostPort(demoClusterIPv6, "80"), httpBackends, "ClusterIP", "Cluster")
				tftpBackends := ciliumIPv6Backends("-l k8s:id=app1,k8s:io.kubernetes.pod.namespace=default", "69")
				ciliumAddService(10069, net.JoinHostPort(demoClusterIPv6, "69"), tftpBackends, "ClusterIP", "Cluster")
				// Installs the IPv6 equivalent of echo (echo-svc.yaml)
				httpBackends = ciliumIPv6Backends("-l k8s:name=echo,k8s:io.kubernetes.pod.namespace=default", "80")
				ciliumAddService(20080, net.JoinHostPort(echoClusterIPv6, "80"), httpBackends, "ClusterIP", "Cluster")
				tftpBackends = ciliumIPv6Backends("-l k8s:name=echo,k8s:io.kubernetes.pod.namespace=default", "69")
				ciliumAddService(20069, net.JoinHostPort(echoClusterIPv6, "69"), tftpBackends, "ClusterIP", "Cluster")
			})

			AfterAll(func() {
				ciliumDelService(10080)
				ciliumDelService(10069)
				ciliumDelService(20080)
				ciliumDelService(20069)
			})

			It("Checks service on same node", func() {
				status := kubectl.ExecInHostNetNS(context.TODO(), k8s1NodeName,
					helpers.CurlFail(`"http://[%s]/"`, demoClusterIPv6))
				status.ExpectSuccess("cannot curl to service IP from host")

				status = kubectl.ExecInHostNetNS(context.TODO(), k8s1NodeName,
					helpers.CurlFail(`"tftp://[%s]/hello"`, demoClusterIPv6))
				status.ExpectSuccess("cannot curl to service IP from host")
			})

			It("Checks service accessing itself (hairpin flow)", func() {
				url := fmt.Sprintf(`"http://[%s]/"`, echoClusterIPv6)
				testCurlFromPods(echoPodLabel, url, 10, 0)
				url = fmt.Sprintf(`"tftp://[%s]/hello"`, echoClusterIPv6)
				testCurlFromPods(echoPodLabel, url, 10, 0)
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
						if !ciliumHasServiceIP(pod, clusterIP) {
							validPods++
						}
					}

					return validPods
				}, 30*time.Second, 2*time.Second).
					Should(Equal(len(ciliumPods)), "All Cilium pods should remove the service from its services list")

				url := fmt.Sprintf("http://%s/", net.JoinHostPort(clusterIP, "80"))

				By("Checking that service should not be reachable with dummy service-proxy-name")
				testCurlFromPods(echoPodLabel, url, 5, 5)

				By("Removing echo service service-proxy-name label")
				res = kubectl.Exec(fmt.Sprintf("kubectl label services/%s %s-", svcName, serviceProxyLabelName))
				Expect(res).Should(helpers.CMDSuccess(), "cannot remove label from service")

				By("Validating that Cilium is handling the service")
				Eventually(func() int {
					validPods := 0
					for _, pod := range ciliumPods {
						if ciliumHasServiceIP(pod, clusterIP) {
							validPods++
						}
					}

					return validPods
				}, 30*time.Second, 2*time.Second).
					Should(Equal(len(ciliumPods)), "All Cilium pods must have the service in its services list")

				By("Checking that service should be reachable with no service-proxy-name")
				testCurlFromPods(echoPodLabel, url, 5, 0)
			}
		})
	})

	SkipContextIf(func() bool { return !helpers.RunsOn419OrLaterKernel() }, "Checks local redirect policy", func() {
		const (
			lrpServiceName = "lrp-demo-service"
			be1Name        = "k8s1-backend"
			be2Name        = "k8s2-backend"
			feFilter       = "role=frontend"
			beFilter       = "role=backend"
		)

		var (
			deploymentYAML string
			lrpSvcYAML     string
			svcIP          string
			curl4TCP       string
			curl4UDP       string
			curl4in6TCP    string
			curl4in6UDP    string
		)

		BeforeAll(func() {
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"localRedirectPolicy": "true",
			})
			deploymentYAML = helpers.ManifestGet(kubectl.BasePath(), "lrp-test.yaml")
			lrpSvcYAML = helpers.ManifestGet(kubectl.BasePath(), "lrp-svc.yaml")
			res := kubectl.ApplyDefault(deploymentYAML)
			res.ExpectSuccess("Unable to apply %s", deploymentYAML)
			for _, pod := range []string{feFilter, beFilter} {
				err := kubectl.WaitforPods(helpers.DefaultNamespace, fmt.Sprintf("-l %s", pod), helpers.HelperTimeout)
				Expect(err).Should(BeNil())
			}
			clusterIP, _, err := kubectl.GetServiceHostPort(helpers.DefaultNamespace, lrpServiceName)
			svcIP = clusterIP
			Expect(err).To(BeNil(), "Cannot get svc IP")

			http4SVCURL := getHTTPLink(svcIP, 80)
			tftp4SVCURL := getTFTPLink(svcIP, 69)
			http4in6SVCURL := getHTTPLink("::ffff:"+svcIP, 80)
			tftp4in6SVCURL := getTFTPLink("::ffff:"+svcIP, 69)

			curl4TCP = helpers.CurlFailNoStats(http4SVCURL)
			curl4UDP = helpers.CurlFailNoStats(tftp4SVCURL)
			curl4in6TCP = helpers.CurlFailNoStats(http4in6SVCURL)
			curl4in6UDP = helpers.CurlFailNoStats(tftp4in6SVCURL)
		})

		AfterAll(func() {
			_ = kubectl.Delete(deploymentYAML)
		})

		It("LRP connectivity", func() {
			type lrpTestCase struct {
				selector string
				cmd      string
				want     string
				notWant  string
			}

			// Basic sanity check
			ciliumPods, err := kubectl.GetCiliumPods()
			Expect(err).To(BeNil(), "Cannot get cilium pods")
			for _, pod := range ciliumPods {
				service := kubectl.CiliumExecMustSucceed(context.TODO(), pod, fmt.Sprintf("cilium service list | grep \" %s:\"", svcIP), "Cannot retrieve services on cilium pod")
				service.ExpectContains("LocalRedirect", "LocalRedirect is not present in the cilium service list")
			}

			By("Checking traffic goes to local backend")
			testCases := []lrpTestCase{
				{
					selector: "id=app1",
					cmd:      curl4TCP,
					// Expects to see local backend name in returned Hostname field
					want: be1Name,
					// Expects never to see remote backend name in returned Hostname field
					notWant: be2Name,
				},
				{
					selector: "id=app2",
					cmd:      curl4TCP,
					want:     be2Name,
					notWant:  be1Name,
				},
				{
					selector: "id=app1",
					cmd:      curl4UDP,
					want:     be1Name,
					notWant:  be2Name,
				},
				{
					selector: "id=app2",
					cmd:      curl4UDP,
					want:     be2Name,
					notWant:  be1Name,
				},
				{
					selector: "id=app1",
					cmd:      curl4in6TCP,
					want:     be1Name,
					notWant:  be2Name,
				},
				{
					selector: "id=app2",
					cmd:      curl4in6TCP,
					want:     be2Name,
					notWant:  be1Name,
				},
				{
					selector: "id=app1",
					cmd:      curl4in6UDP,
					want:     be1Name,
					notWant:  be2Name,
				},
				{
					selector: "id=app2",
					cmd:      curl4in6UDP,
					want:     be2Name,
					notWant:  be1Name,
				},
			}

			var wg sync.WaitGroup
			for _, testCase := range testCases {
				wg.Add(1)
				go func(tc lrpTestCase) {
					defer GinkgoRecover()
					defer wg.Done()
					Consistently(func() bool {
						pods, err := kubectl.GetPodNames(helpers.DefaultNamespace, tc.selector)
						Expect(err).Should(BeNil(), "cannot retrieve pod names by filter %q", tc.selector)
						Expect(len(pods)).Should(BeNumerically(">", 0), "no pod exists by filter %q", tc.selector)
						ret := true
						for _, pod := range pods {
							res := kubectl.ExecPodCmd(helpers.DefaultNamespace, pod, tc.cmd)
							Expect(err).To(BeNil(), "%s failed in %s pod", tc.cmd, pod)
							ret = ret && strings.Contains(res.Stdout(), tc.want) && !strings.Contains(res.Stdout(), tc.notWant)
						}
						return ret
					}, 30*time.Second, 1*time.Second).Should(BeTrue(), "assertion fails for test case: %v", tc)
				}(testCase)
			}
			wg.Wait()
		})

		It("LRP restores service when removed", func() {
			type lrpTestCase struct {
				selector string
				cmd      string
				pod      string
			}

			_ = kubectl.Delete(lrpSvcYAML)
			// Basic sanity check
			ciliumPods, err := kubectl.GetCiliumPods()
			Expect(err).To(BeNil(), "Cannot get cilium pods")
			for _, pod := range ciliumPods {
				service := kubectl.CiliumExecMustSucceed(context.TODO(), pod, fmt.Sprintf("cilium service list | grep \" %s:\"", svcIP), "Cannot retrieve services on cilium pod")
				service.ExpectContains("ClusterIP", "Original service is not present in the cilium service list")
			}

			By("Checking traffic goes to both backends")
			testCases := []lrpTestCase{
				{
					selector: "id=app1",
					cmd:      curl4TCP,
				},
				{
					selector: "id=app2",
					cmd:      curl4TCP,
				},
				{
					selector: "id=app1",
					cmd:      curl4UDP,
				},
				{
					selector: "id=app2",
					cmd:      curl4UDP,
				},
			}

			var wg sync.WaitGroup
			for _, tc := range testCases {
				pods, err := kubectl.GetPodNames(helpers.DefaultNamespace, tc.selector)
				Expect(err).Should(BeNil(), "cannot retrieve pod names by filter %q", tc.selector)
				Expect(len(pods)).Should(BeNumerically(">", 0), "no pod exists by filter %q", tc.selector)
				for _, pod := range pods {
					wg.Add(1)
					go func(tc lrpTestCase, pod string) {
						defer GinkgoRecover()
						defer wg.Done()
						want := []string{be1Name, be2Name}
						be1Found := false
						be2Found := false
						Eventually(func() bool {
							res := kubectl.ExecPodCmd(helpers.DefaultNamespace, pod, tc.cmd)
							ExpectWithOffset(1, res).Should(helpers.CMDSuccess(),
								"%s failed in %s pod", tc.cmd, pod)
							be1Found = be1Found || strings.Contains(res.Stdout(), want[0])
							be2Found = be2Found || strings.Contains(res.Stdout(), want[1])
							return be1Found && be2Found
						}, 30*time.Second, 1*time.Second).Should(BeTrue(), "assertion fails for test case: %v", tc)
					}(tc, pod)
				}
			}
			wg.Wait()
		})
	})

	Context("Checks service across nodes", func() {
		const (
			testDSClient = "zgroup=testDSClient"
			testDS       = "zgroup=testDS"
			testDSK8s2   = "zgroup=test-k8s2"

			testDSServiceIPv4 = "testds-service"
			testDSServiceIPv6 = "testds-service-ipv6"
		)

		var (
			demoYAML   string
			demoYAMLV6 string

			primaryK8s1IPv6, primaryK8s2IPv6 string
			outsideIPv6                      string

			secondaryK8s1IPv4, secondaryK8s2IPv4 string
			secondaryK8s1IPv6, secondaryK8s2IPv6 string

			demoPolicyL7 string
		)

		waitPodsDs := func() {
			groups := []string{testDS, testDSClient, testDSK8s2}
			for _, pod := range groups {
				err := kubectl.WaitforPods(helpers.DefaultNamespace, fmt.Sprintf("-l %s", pod), helpers.HelperTimeout)
				ExpectWithOffset(1, err).Should(BeNil())
			}
		}

		getIPv4AddrForIface := func(nodeName, iface string) string {
			cmd := fmt.Sprintf("ip -family inet -oneline address show dev %s scope global | awk '{print $4}' | cut -d/ -f1", iface)
			res := kubectl.ExecInHostNetNS(context.TODO(), nodeName, cmd)
			ExpectWithOffset(1, res).Should(helpers.CMDSuccess(),
				"Cannot get IPv4 address for interface(%q): %s", iface, res.CombineOutput())
			ipv4 := strings.Trim(res.Stdout(), "\n")

			return ipv4
		}

		getIPv6AddrForIface := func(nodeName, iface string) string {
			cmd := fmt.Sprintf("ip -family inet6 -oneline address show dev %s scope global | awk '{print $4}' | cut -d/ -f1", iface)
			res := kubectl.ExecInHostNetNS(context.TODO(), nodeName, cmd)
			ExpectWithOffset(1, res).Should(helpers.CMDSuccess(),
				"Cannot get IPv6 address for interface(%q): %s", iface, res.CombineOutput())
			ipv6 := strings.Trim(res.Stdout(), "\n")

			return ipv6
		}

		BeforeAll(func() {
			demoYAML = helpers.ManifestGet(kubectl.BasePath(), "demo_ds.yaml")

			DeployCiliumAndDNS(kubectl, ciliumFilename)

			res := kubectl.ApplyDefault(demoYAML)
			Expect(res).Should(helpers.CMDSuccess(), "Unable to apply %s", demoYAML)

			if helpers.GetCurrentIntegration() == "" {
				primaryK8s1IPv6 = getIPv6AddrForIface(k8s1NodeName, privateIface)
				primaryK8s2IPv6 = getIPv6AddrForIface(k8s2NodeName, privateIface)

				// If there is no integration we assume that these are running in vagrant environment
				// so have a secondary interface with both IPv6 and IPv4 addresses.
				secondaryK8s1IPv4 = getIPv4AddrForIface(k8s1NodeName, helpers.SecondaryIface)
				secondaryK8s2IPv4 = getIPv4AddrForIface(k8s2NodeName, helpers.SecondaryIface)

				secondaryK8s1IPv6 = getIPv6AddrForIface(k8s1NodeName, helpers.SecondaryIface)
				secondaryK8s2IPv6 = getIPv6AddrForIface(k8s2NodeName, helpers.SecondaryIface)

				if helpers.ExistNodeWithoutCilium() {
					outsideIPv6 = getIPv6AddrForIface(outsideNodeName, privateIface)
				}
			}

			if helpers.DualStackSupported() {
				demoYAMLV6 = helpers.ManifestGet(kubectl.BasePath(), "demo_ds_v6.yaml")

				res = kubectl.ApplyDefault(demoYAMLV6)
				Expect(res).Should(helpers.CMDSuccess(), "Unable to apply %s", demoYAMLV6)
			}

			By(`Connectivity config:: helpers.DualStackSupported(): %v
Primary Interface %s   :: IPv4: (%s, %s), IPv6: (%s, %s)
Secondary Interface %s :: IPv4: (%s, %s), IPv6: (%s, %s)`, helpers.DualStackSupported(), privateIface, k8s1IP, k8s2IP, primaryK8s1IPv6, primaryK8s2IPv6,
				helpers.SecondaryIface, secondaryK8s1IPv4, secondaryK8s2IPv4, secondaryK8s1IPv6, secondaryK8s2IPv6)

			demoPolicyL7 = helpers.ManifestGet(kubectl.BasePath(), "l7-policy-demo.yaml")
			waitPodsDs()
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

		testCurlFromPodInHostNetNS := func(url string, count, fails int, fromPod string) {
			By("Making %d curl requests from pod (host netns) %s to %q", count, fromPod, url)
			cmd := testCommand(helpers.CurlFailNoStats(url), count, fails)
			res := kubectl.ExecInHostNetNS(context.TODO(), fromPod, cmd)
			ExpectWithOffset(1, res).Should(helpers.CMDSuccess(),
				"Request from %s to service %s failed", fromPod, url)
		}

		testCurlFailFromPodInHostNetNS := func(url string, count int, fromPod string) {
			By("Making %d curl requests from %s to %q", count, fromPod, url)
			for i := 1; i <= count; i++ {
				res := kubectl.ExecInHostNetNS(context.TODO(), fromPod, helpers.CurlFail(url))
				ExpectWithOffset(1, res).ShouldNot(helpers.CMDSuccess(),
					"%s host unexpectedly connected to service %q, it should fail", fromPod, url)
			}
		}

		failBind := func(addr string, port int32, proto, fromPod string) {
			By("Trying to bind NodePort addr %q:%d on %s", addr, port, fromPod)
			res := kubectl.ExecInHostNetNS(context.TODO(), fromPod,
				helpers.PythonBind(addr, uint16(port), proto))
			ExpectWithOffset(2, res).ShouldNot(helpers.CMDSuccess(),
				"%s host unexpectedly was able to bind on %q:%d, it should fail", fromPod, addr, port)
		}

		testCurlFromPodInHostNetNSExpectingHTTPCode := func(url string, count int, expectedCode string, fromPod string) {
			By("Making %d HTTP requests from %s to %q, expecting HTTP %s", count, fromPod, url, expectedCode)
			for i := 1; i <= count; i++ {
				res := kubectl.ExecInHostNetNS(context.TODO(), fromPod, helpers.CurlWithHTTPCode(url))
				ExpectWithOffset(1, res).Should(helpers.CMDSuccess(),
					"%s host can not connect to service %q", fromPod, url)
				res.ExpectContains(expectedCode, "Request from %s to %q returned HTTP Code %q, expected %q",
					fromPod, url, res.GetStdOut(), expectedCode)
			}
		}

		testCurlFromOutsideWithLocalPort :=
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
					res := kubectl.ExecInHostNetNS(context.TODO(), outsideNodeName, cmd)
					ExpectWithOffset(1, res).Should(helpers.CMDSuccess(),
						"Can not connect to service %q from outside cluster (%d/%d)", url, i, count)
					if checkSourceIP {
						// Parse the IPs to avoid issues with 4-in-6 formats
						sourceIP := net.ParseIP(strings.TrimSpace(strings.Split(res.Stdout(), "=")[1]))
						var outIP net.IP
						if sourceIP.To4() != nil {
							outIP = net.ParseIP(outsideIP)
						} else {
							outIP = net.ParseIP(outsideIPv6)
						}
						ExpectWithOffset(1, sourceIP).To(Equal(outIP))
					}
				}
			}

		testCurlFailFromOutside :=
			func(url string, count int) {
				By("Making %d HTTP requests from outside cluster to %q", count, url)
				for i := 1; i <= count; i++ {
					res := kubectl.ExecInHostNetNS(context.TODO(), outsideNodeName, helpers.CurlFail(url))
					ExpectWithOffset(1, res).ShouldNot(helpers.CMDSuccess(),
						"%s host unexpectedly connected to service %q, it should fail", outsideNodeName, url)
				}
			}

		testCurlFromOutside := func(url string, count int, checkSourceIP bool) {
			testCurlFromOutsideWithLocalPort(url, count, checkSourceIP, 0)
		}

		// srcPod:     Name of pod sending the datagram
		// srcPort:    Source UDP port (should be different for each doFragmentRequest invocation to allow distinct CT table entries)
		// dstPodIP:   Receiver pod IP (for checking in CT table)
		// dstPodPort: Receiver pod port (for checking in CT table)
		// dstIP:      Target endpoint IP for sending the datagram
		// dstPort:    Target endpoint port for sending the datagram
		// hasDNAT:    True if DNAT is used for target IP and port
		doFragmentedRequest := func(srcPod string, srcPort, dstPodPort int, dstIP string, dstPort int32, hasDNAT bool) {
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
			), "Failed to account for INGRESS IPv4 fragments in BPF metrics", dstIP)
		}

		testNodePort := func(bpfNodePort, testSecondaryNodePortIP, testFromOutside bool, fails int) {
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

				getHTTPLink(k8s1IP, data.Spec.Ports[0].NodePort),
				getTFTPLink(k8s1IP, data.Spec.Ports[1].NodePort),

				getHTTPLink("::ffff:"+k8s1IP, data.Spec.Ports[0].NodePort),
				getTFTPLink("::ffff:"+k8s1IP, data.Spec.Ports[1].NodePort),

				getHTTPLink(k8s2IP, data.Spec.Ports[0].NodePort),
				getTFTPLink(k8s2IP, data.Spec.Ports[1].NodePort),

				getHTTPLink("::ffff:"+k8s2IP, data.Spec.Ports[0].NodePort),
				getTFTPLink("::ffff:"+k8s2IP, data.Spec.Ports[1].NodePort),
			}

			if helpers.DualStackSupported() {
				testURLsFromPods = append(testURLsFromPods,
					getHTTPLink(v6Data.Spec.ClusterIP, v6Data.Spec.Ports[0].Port),
					getTFTPLink(v6Data.Spec.ClusterIP, v6Data.Spec.Ports[1].Port),

					getHTTPLink(primaryK8s1IPv6, v6Data.Spec.Ports[0].NodePort),
					getTFTPLink(primaryK8s1IPv6, v6Data.Spec.Ports[1].NodePort),

					getHTTPLink(primaryK8s2IPv6, v6Data.Spec.Ports[0].NodePort),
					getTFTPLink(primaryK8s2IPv6, v6Data.Spec.Ports[1].NodePort),
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

				getHTTPLink(k8s1IP, data.Spec.Ports[0].NodePort),
				getTFTPLink(k8s1IP, data.Spec.Ports[1].NodePort),

				getHTTPLink("::ffff:"+k8s1IP, data.Spec.Ports[0].NodePort),
				getTFTPLink("::ffff:"+k8s1IP, data.Spec.Ports[1].NodePort),

				getHTTPLink(k8s2IP, data.Spec.Ports[0].NodePort),
				getTFTPLink(k8s2IP, data.Spec.Ports[1].NodePort),

				getHTTPLink("::ffff:"+k8s2IP, data.Spec.Ports[0].NodePort),
				getTFTPLink("::ffff:"+k8s2IP, data.Spec.Ports[1].NodePort),
			}

			if helpers.DualStackSupported() {
				testURLsFromHosts = append(testURLsFromHosts,
					getHTTPLink(v6Data.Spec.ClusterIP, v6Data.Spec.Ports[0].Port),
					getTFTPLink(v6Data.Spec.ClusterIP, v6Data.Spec.Ports[1].Port),

					getHTTPLink(primaryK8s1IPv6, v6Data.Spec.Ports[0].NodePort),
					getTFTPLink(primaryK8s1IPv6, v6Data.Spec.Ports[1].NodePort),

					getHTTPLink(primaryK8s2IPv6, v6Data.Spec.Ports[0].NodePort),
					getTFTPLink(primaryK8s2IPv6, v6Data.Spec.Ports[1].NodePort),
				)
			}

			if testSecondaryNodePortIP {
				testURLsFromHosts = append(testURLsFromHosts,
					getHTTPLink(secondaryK8s1IPv4, data.Spec.Ports[0].NodePort),
					getTFTPLink(secondaryK8s1IPv4, data.Spec.Ports[1].NodePort),

					getHTTPLink(secondaryK8s2IPv4, data.Spec.Ports[0].NodePort),
					getTFTPLink(secondaryK8s2IPv4, data.Spec.Ports[1].NodePort),
				)

				if helpers.DualStackSupported() {
					testURLsFromHosts = append(testURLsFromHosts,
						getHTTPLink(secondaryK8s1IPv6, v6Data.Spec.Ports[0].NodePort),
						getTFTPLink(secondaryK8s1IPv6, v6Data.Spec.Ports[1].NodePort),

						getHTTPLink(secondaryK8s2IPv6, v6Data.Spec.Ports[0].NodePort),
						getTFTPLink(secondaryK8s2IPv6, v6Data.Spec.Ports[1].NodePort),
					)
				}
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
					getHTTPLink(k8s1IP, data.Spec.Ports[0].NodePort),
					getTFTPLink(k8s1IP, data.Spec.Ports[1].NodePort),

					getHTTPLink(k8s2IP, data.Spec.Ports[0].NodePort),
					getTFTPLink(k8s2IP, data.Spec.Ports[1].NodePort),
				}

				if helpers.DualStackSupported() {
					testURLsFromOutside = append(testURLsFromOutside,
						getHTTPLink(primaryK8s1IPv6, v6Data.Spec.Ports[0].NodePort),
						getTFTPLink(primaryK8s1IPv6, v6Data.Spec.Ports[1].NodePort),

						getHTTPLink(primaryK8s2IPv6, v6Data.Spec.Ports[0].NodePort),
						getTFTPLink(primaryK8s2IPv6, v6Data.Spec.Ports[1].NodePort),
					)
				}

				if testSecondaryNodePortIP {
					testURLsFromOutside = append(testURLsFromOutside,
						getHTTPLink(secondaryK8s1IPv4, data.Spec.Ports[0].NodePort),
						getTFTPLink(secondaryK8s1IPv4, data.Spec.Ports[1].NodePort),

						getHTTPLink(secondaryK8s2IPv4, data.Spec.Ports[0].NodePort),
						getTFTPLink(secondaryK8s2IPv4, data.Spec.Ports[1].NodePort),
					)

					if helpers.DualStackSupported() {
						testURLsFromOutside = append(testURLsFromOutside,
							getHTTPLink(secondaryK8s1IPv6, v6Data.Spec.Ports[0].NodePort),
							getTFTPLink(secondaryK8s1IPv6, v6Data.Spec.Ports[1].NodePort),

							getHTTPLink(secondaryK8s2IPv6, v6Data.Spec.Ports[0].NodePort),
							getTFTPLink(secondaryK8s2IPv6, v6Data.Spec.Ports[1].NodePort),
						)
					}
				}
			}

			count := 10
			for _, url := range testURLsFromPods {
				wg.Add(1)
				go func(url string) {
					defer GinkgoRecover()
					defer wg.Done()
					testCurlFromPods(testDSClient, url, count, fails)
				}(url)
			}
			for _, url := range testURLsFromHosts {
				wg.Add(1)
				go func(url string) {
					defer GinkgoRecover()
					defer wg.Done()
					testCurlFromPodInHostNetNS(url, count, fails, k8s1NodeName)
				}(url)
			}
			for _, url := range testURLsFromOutside {
				wg.Add(1)
				go func(url string) {
					defer GinkgoRecover()
					defer wg.Done()
					testCurlFromOutside(url, count, false)
				}(url)
			}
			// TODO: IPv6
			if bpfNodePort && helpers.RunsOnNetNextKernel() {
				httpURL := getHTTPLink("127.0.0.1", data.Spec.Ports[0].NodePort)
				tftpURL := getTFTPLink("127.0.0.1", data.Spec.Ports[1].NodePort)
				testCurlFromPodsFail(testDSClient, httpURL)
				testCurlFromPodsFail(testDSClient, tftpURL)

				if helpers.DualStackSupported() {
					httpURL = getHTTPLink("::1", v6Data.Spec.Ports[0].NodePort)
					tftpURL = getTFTPLink("::1", v6Data.Spec.Ports[1].NodePort)
					testCurlFromPodsFail(testDSClient, httpURL)
					testCurlFromPodsFail(testDSClient, tftpURL)
				}

				httpURL = getHTTPLink("::ffff:127.0.0.1", data.Spec.Ports[0].NodePort)
				tftpURL = getTFTPLink("::ffff:127.0.0.1", data.Spec.Ports[1].NodePort)
				testCurlFromPodsFail(testDSClient, httpURL)
				testCurlFromPodsFail(testDSClient, tftpURL)
			}

			wg.Wait()
		}

		// This function tests NodePort services using IPV6 addresses
		// It is the job of the caller to make sure that all the node have assigned
		// routable IPV6 addresses reachable from other nodes.
		// This is not required when dual stack support is enabled for the cluster.
		testNodePortIPv6 := func(k8s1IPv6, k8s2IPv6 string, testFromOutside bool, data *v1.Service) {
			var wg sync.WaitGroup

			testURLs := []string{
				getHTTPLink(k8s1IPv6, data.Spec.Ports[0].NodePort),
				getTFTPLink(k8s1IPv6, data.Spec.Ports[1].NodePort),

				getHTTPLink(k8s2IPv6, data.Spec.Ports[0].NodePort),
				getTFTPLink(k8s2IPv6, data.Spec.Ports[1].NodePort),
			}

			count := 10
			for _, url := range testURLs {
				wg.Add(1)
				go func(url string) {
					defer GinkgoRecover()
					defer wg.Done()
					testCurlFromPods(testDSClient, url, count, 0)
				}(url)
			}

			for _, url := range testURLs {
				wg.Add(1)
				go func(url string) {
					defer GinkgoRecover()
					defer wg.Done()
					testCurlFromPodInHostNetNS(url, count, 0, k8s1NodeName)
					testCurlFromPodInHostNetNS(url, count, 0, k8s2NodeName)
				}(url)
			}

			// Test IPv6 NodePort service connectivity from outside of K8s cluster.
			if testFromOutside {
				for _, url := range testURLs {
					wg.Add(1)
					go func(url string) {
						defer GinkgoRecover()
						defer wg.Done()
						testCurlFromOutside(url, count, false)
					}(url)
				}
			}

			wg.Wait()
		}

		testExternalIPs := func() {
			var (
				data                v1.Service
				nodePortService     = "test-external-ips"
				nodePortServiceIPv6 = "test-external-ips-ipv6"
			)
			count := 10

			services := map[string]string{
				nodePortService: k8s1IP,
			}
			if helpers.DualStackSupported() {
				services[nodePortServiceIPv6] = primaryK8s1IPv6
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

				httpURL := getHTTPLink(svcExternalIP, data.Spec.Ports[0].Port)
				tftpURL := getTFTPLink(svcExternalIP, data.Spec.Ports[1].Port)

				// Add the route on the outside node to the external IP addr
				res = kubectl.AddIPRoute(outsideNodeName, svcExternalIP, nodeIP, false)
				ExpectWithOffset(1, res).Should(helpers.CMDSuccess(), "Error removing IP route for %s via %s", svcExternalIP, nodeIP)
				defer func(externalIP, nodeIP string) {
					res := kubectl.DelIPRoute(outsideNodeName, externalIP, nodeIP)
					ExpectWithOffset(1, res).Should(helpers.CMDSuccess(), "Error removing IP route for %s via %s", externalIP, nodeIP)
				}(svcExternalIP, nodeIP)

				// Should work from outside via the external IP
				testCurlFromOutside(httpURL, count, false)
				testCurlFromOutside(tftpURL, count, false)
				// Should fail from inside a pod & hostns
				testCurlFromPodsFail(testDSClient, httpURL)
				testCurlFromPodsFail(testDSClient, tftpURL)
				testCurlFailFromPodInHostNetNS(httpURL, 1, k8s1NodeName)
				testCurlFailFromPodInHostNetNS(httpURL, 1, k8s1NodeName)
				testCurlFailFromPodInHostNetNS(httpURL, 1, k8s2NodeName)
				testCurlFailFromPodInHostNetNS(httpURL, 1, k8s2NodeName)
				// However, it should work via the k8s1 IP addr
				httpURL = getHTTPLink(nodeIP, data.Spec.Ports[0].Port)
				tftpURL = getTFTPLink(nodeIP, data.Spec.Ports[1].Port)
				testCurlFromPodInHostNetNS(httpURL, count, 0, k8s1NodeName)
				testCurlFromPodInHostNetNS(tftpURL, count, 0, k8s1NodeName)
				// TODO(fristonio): fix IPv6 access issue for external IP from non k8s1
				// pod.
				if svcName != nodePortServiceIPv6 {
					testCurlFromPods(testDSClient, httpURL, 10, 0)
					testCurlFromPods(testDSClient, tftpURL, 10, 0)
				}
			}
		}

		testFailBind := func() {
			var data v1.Service

			err := kubectl.Get(helpers.DefaultNamespace, "service test-nodeport").Unmarshal(&data)
			ExpectWithOffset(1, err).Should(BeNil(), "Can not retrieve service")

			// Ensure the NodePort cannot be bound from any redirected address
			failBind("127.0.0.1", data.Spec.Ports[0].NodePort, "tcp", k8s1NodeName)
			failBind("127.0.0.1", data.Spec.Ports[1].NodePort, "udp", k8s1NodeName)
			failBind("", data.Spec.Ports[0].NodePort, "tcp", k8s1NodeName)
			failBind("", data.Spec.Ports[1].NodePort, "udp", k8s1NodeName)

			failBind("::ffff:127.0.0.1", data.Spec.Ports[0].NodePort, "tcp", k8s1NodeName)
			failBind("::ffff:127.0.0.1", data.Spec.Ports[1].NodePort, "udp", k8s1NodeName)
		}

		testNodePortExternal := func(checkTCP, checkUDP bool) {
			var (
				data                v1.Service
				nodePortService     = "test-nodeport"
				nodePortServiceIPv6 = "test-nodeport-ipv6"
			)

			services := map[string]string{
				nodePortService: k8s1IP,
			}
			if helpers.DualStackSupported() {
				services[nodePortServiceIPv6] = primaryK8s1IPv6
			}

			for svcName, nodeIP := range services {
				err := kubectl.Get(helpers.DefaultNamespace, fmt.Sprintf("service %s", svcName)).Unmarshal(&data)
				ExpectWithOffset(1, err).Should(BeNil(), "Cannot retrieve service")

				httpURL := getHTTPLink(nodeIP, data.Spec.Ports[0].NodePort)
				tftpURL := getTFTPLink(nodeIP, data.Spec.Ports[1].NodePort)

				// Test from external connectivity
				// Note:
				//   In case of SNAT checkSourceIP is false here since the HTTP request
				//   won't have the client IP but the service IP (given the request comes
				//   from the Cilium node to the backend, not from the client directly).
				//   Same in case of Hybrid mode for UDP.
				testCurlFromOutside(httpURL, 10, checkTCP)
				testCurlFromOutside(tftpURL, 10, checkUDP)

				// Make sure all the rest works as expected as well
				testNodePort(true, false, false, 0)

				// Clear CT tables on both Cilium nodes
				pod, err := kubectl.GetCiliumPodOnNode(helpers.K8s1)
				ExpectWithOffset(1, err).Should(BeNil(), "Cannot determine cilium pod name")
				kubectl.CiliumExecMustSucceed(context.TODO(), pod, "cilium bpf ct flush global", "Unable to flush CT maps")

				pod, err = kubectl.GetCiliumPodOnNode(helpers.K8s2)
				ExpectWithOffset(1, err).Should(BeNil(), "Cannot determine cilium pod name")
				kubectl.CiliumExecMustSucceed(context.TODO(), pod, "cilium bpf ct flush global", "Unable to flush CT maps")
			}

		}

		// fromOutside=true tests session affinity implementation from lb.h, while
		// fromOutside=false tests from  bpf_sock.c.
		testSessionAffinity := func(fromOutside, vxlan bool) {
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
				serviceAffinityServiceIPv4: k8s1IP,
			}
			if helpers.DualStackSupported() {
				services[serviceAffinityServiceIPv6] = primaryK8s1IPv6
			}

			for svcName, nodeIP := range services {
				err = kubectl.Get(helpers.DefaultNamespace, fmt.Sprintf("service %s", svcName)).Unmarshal(&data)
				ExpectWithOffset(1, err).Should(BeNil(), "Cannot retrieve service %s", svcName)

				httpURL := getHTTPLink(nodeIP, data.Spec.Ports[0].NodePort)
				cmd := helpers.CurlFail(httpURL) + " | grep 'Hostname:' " // pod name is in the hostname

				if fromOutside {
					from = outsideNodeName
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
				waitPodsDs()
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

		testExternalTrafficPolicyLocal := func() {
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
					k8s1IP,
					k8s2IP,
					localNodePortSvcIPv4,
					localNodePortK8s2SvcIpv4,
				},
			}
			if helpers.DualStackSupported() {
				services = append(services, nodeInfo{
					primaryK8s1IPv6,
					primaryK8s2IPv6,
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
					testCurlFromOutside(httpURL, count, true)
					testCurlFromOutside(tftpURL, count, true)
				} else {
					GinkgoPrint("Skipping externalTrafficPolicy=Local test from external node")
				}

				err = kubectl.Get(helpers.DefaultNamespace, fmt.Sprintf("service %s", node.k8s2LocalSvc)).Unmarshal(&data)
				ExpectWithOffset(1, err).Should(BeNil(), "Can not retrieve service %s", node.k8s2LocalSvc)

				// Checks that requests to k8s2 succeed where Pod is also running
				httpURL = getHTTPLink(node.node2IP, data.Spec.Ports[0].NodePort)
				tftpURL = getTFTPLink(node.node2IP, data.Spec.Ports[1].NodePort)
				testCurlFromPodInHostNetNS(httpURL, count, 0, k8s1NodeName)
				testCurlFromPodInHostNetNS(tftpURL, count, 0, k8s1NodeName)
				testCurlFromPodInHostNetNS(httpURL, count, 0, k8s2NodeName)
				testCurlFromPodInHostNetNS(tftpURL, count, 0, k8s2NodeName)
				if helpers.ExistNodeWithoutCilium() {
					testCurlFromOutside(httpURL, count, true)
					testCurlFromOutside(tftpURL, count, true)
				}

				// Local requests should be load-balanced on kube-proxy 1.15+.
				// See kubernetes/kubernetes#77523 for the PR which introduced this
				// behavior on the iptables-backend for kube-proxy.
				httpURL = getHTTPLink(node.node1IP, data.Spec.Ports[0].NodePort)
				tftpURL = getTFTPLink(node.node1IP, data.Spec.Ports[1].NodePort)
				testCurlFromPodInHostNetNS(httpURL, count, 0, k8s1NodeName)
				testCurlFromPodInHostNetNS(tftpURL, count, 0, k8s1NodeName)
				// In-cluster connectivity from k8s2 to k8s1 IP will still work with
				// HostReachableServices (regardless of if we are running with or
				// without kube-proxy) since we'll hit the wildcard rule in bpf_sock
				// and k8s1 IP is in ipcache as REMOTE_NODE_ID. But that is fine since
				// it's all in-cluster connectivity w/ client IP preserved.
				// This is a known incompatibility with kube-proxy:
				// kube-proxy 1.15+ will only load-balance requests from k8s1 to k8s1,
				// but not from k8s2 to k8s1. In the k8s2 to k8s1 case, kube-proxy
				// would send traffic to k8s1, where it would be subsequently
				// dropped, because k8s1 has no service backend.
				// If HostReachableServices is enabled, Cilium does the service
				// translation for ClusterIP services on the client node, bypassing
				// kube-proxy completely. Here, we are probing NodePort service, so we
				// need BPF NodePort to be enabled as well for the requests to succeed.
				hostReachableServicesTCP := kubectl.HasHostReachableServices(ciliumPodK8s2, true, false)
				hostReachableServicesUDP := kubectl.HasHostReachableServices(ciliumPodK8s2, false, true)
				bpfNodePort := kubectl.HasBPFNodePort(ciliumPodK8s2)
				if hostReachableServicesTCP && bpfNodePort {
					testCurlFromPodInHostNetNS(httpURL, count, 0, k8s2NodeName)
				} else {
					testCurlFailFromPodInHostNetNS(httpURL, 1, k8s2NodeName)
				}
				if hostReachableServicesUDP && bpfNodePort {
					testCurlFromPodInHostNetNS(tftpURL, count, 0, k8s2NodeName)
				} else {
					testCurlFailFromPodInHostNetNS(tftpURL, 1, k8s2NodeName)
				}

				// Requests from a non-Cilium node to k8s1 IP will fail though.
				if helpers.ExistNodeWithoutCilium() {
					testCurlFailFromOutside(tftpURL, 1)
				}
			}
		}

		testHostPort := func() {
			var (
				httpURL string
				tftpURL string
			)

			httpHostPort := int32(8080)
			tftpHostPort := int32(6969)

			httpHostPortStr := strconv.Itoa(int(httpHostPort))
			tftpHostPortStr := strconv.Itoa(int(tftpHostPort))

			count := 10

			pod, err := kubectl.GetCiliumPodOnNode(helpers.K8s2)
			ExpectWithOffset(1, err).Should(BeNil(), "Cannot determine cilium pod name")

			res := kubectl.CiliumExecContext(context.TODO(), pod, "cilium service list | grep "+k8s2IP+":"+httpHostPortStr+" | grep HostPort")
			ExpectWithOffset(1, res.Stdout()).ShouldNot(BeEmpty(), "No HostPort entry for "+k8s2IP+":"+httpHostPortStr)

			res = kubectl.CiliumExecContext(context.TODO(), pod, "cilium service list | grep "+k8s2IP+":"+tftpHostPortStr+" | grep HostPort")
			ExpectWithOffset(1, res.Stdout()).ShouldNot(BeEmpty(), "No HostPort entry for "+k8s2IP+":"+tftpHostPortStr)

			if helpers.DualStackSupported() {
				res := kubectl.CiliumExecContext(context.TODO(), pod, "cilium service list | grep ["+primaryK8s2IPv6+"]:"+httpHostPortStr+" | grep HostPort")
				ExpectWithOffset(1, res.Stdout()).ShouldNot(BeEmpty(), "No HostPort entry for ["+primaryK8s2IPv6+"]:"+httpHostPortStr)

				res = kubectl.CiliumExecContext(context.TODO(), pod, "cilium service list | grep ["+primaryK8s2IPv6+"]:"+tftpHostPortStr+" | grep HostPort")
				ExpectWithOffset(1, res.Stdout()).ShouldNot(BeEmpty(), "No HostPort entry for ["+primaryK8s2IPv6+"]:"+tftpHostPortStr)
			}

			// Cluster-internal connectivity via node address to HostPort
			httpURL = getHTTPLink(k8s2IP, httpHostPort)
			tftpURL = getTFTPLink(k8s2IP, tftpHostPort)

			// ... from same node
			testCurlFromPodInHostNetNS(httpURL, count, 0, k8s2NodeName)
			testCurlFromPodInHostNetNS(tftpURL, count, 0, k8s2NodeName)

			// ... from different node
			testCurlFromPodInHostNetNS(httpURL, count, 0, k8s1NodeName)
			testCurlFromPodInHostNetNS(tftpURL, count, 0, k8s1NodeName)

			// Cluster-internal connectivity via loopback to HostPort
			httpURL = getHTTPLink("127.0.0.1", httpHostPort)
			tftpURL = getTFTPLink("127.0.0.1", tftpHostPort)

			// ... from same node
			testCurlFromPodInHostNetNS(httpURL, count, 0, k8s2NodeName)
			testCurlFromPodInHostNetNS(tftpURL, count, 0, k8s2NodeName)

			// ... from different node
			testCurlFailFromPodInHostNetNS(httpURL, 1, k8s1NodeName)
			testCurlFailFromPodInHostNetNS(tftpURL, 1, k8s1NodeName)

			// Cluster-internal connectivity via v4-in-v6 node address to HostPort
			httpURL = getHTTPLink("::ffff:"+k8s2IP, httpHostPort)
			tftpURL = getTFTPLink("::ffff:"+k8s2IP, tftpHostPort)

			// ... from same node
			testCurlFromPodInHostNetNS(httpURL, count, 0, k8s2NodeName)
			testCurlFromPodInHostNetNS(tftpURL, count, 0, k8s2NodeName)

			// Cluster-internal connectivity via v4-in-v6 loopback to HostPort
			httpURL = getHTTPLink("::ffff:127.0.0.1", httpHostPort)
			tftpURL = getTFTPLink("::ffff:127.0.0.1", tftpHostPort)

			// ... from same node
			testCurlFromPodInHostNetNS(httpURL, count, 0, k8s2NodeName)
			testCurlFromPodInHostNetNS(tftpURL, count, 0, k8s2NodeName)

			if helpers.DualStackSupported() {
				// Cluster-internal connectivity via node address to HostPort
				httpURL = getHTTPLink(primaryK8s2IPv6, httpHostPort)
				tftpURL = getTFTPLink(primaryK8s2IPv6, tftpHostPort)

				// ... from same node
				testCurlFromPodInHostNetNS(httpURL, count, 0, k8s2NodeName)
				testCurlFromPodInHostNetNS(tftpURL, count, 0, k8s2NodeName)

				// ... from different node
				testCurlFromPodInHostNetNS(httpURL, count, 0, k8s1NodeName)
				testCurlFromPodInHostNetNS(tftpURL, count, 0, k8s1NodeName)

				// Cluster-internal connectivity via loopback to HostPort
				httpURL = getHTTPLink("::1", httpHostPort)
				tftpURL = getTFTPLink("::1", tftpHostPort)

				// ... from same node
				testCurlFromPodInHostNetNS(httpURL, count, 0, k8s2NodeName)
				testCurlFromPodInHostNetNS(tftpURL, count, 0, k8s2NodeName)

				// ... from different node
				testCurlFailFromPodInHostNetNS(httpURL, 1, k8s1NodeName)
				testCurlFailFromPodInHostNetNS(tftpURL, 1, k8s1NodeName)
			}
		}

		testHealthCheckNodePort := func() {
			var data v1.Service

			// Service with HealthCheckNodePort that only has backends on k8s2
			err := kubectl.Get(helpers.DefaultNamespace, "service test-lb-local-k8s2").Unmarshal(&data)
			ExpectWithOffset(1, err).Should(BeNil(), "Can not retrieve service")

			count := 10

			// Checks that requests to k8s2 return 200
			url := getHTTPLink(k8s2IP, data.Spec.HealthCheckNodePort)
			testCurlFromPodInHostNetNSExpectingHTTPCode(url, count, "200", k8s1NodeName)
			testCurlFromPodInHostNetNSExpectingHTTPCode(url, count, "200", k8s2NodeName)

			// Checks that requests to k8s1 return 503 Service Unavailable
			url = getHTTPLink(k8s1IP, data.Spec.HealthCheckNodePort)
			testCurlFromPodInHostNetNSExpectingHTTPCode(url, count, "503", k8s1NodeName)
			testCurlFromPodInHostNetNSExpectingHTTPCode(url, count, "503", k8s2NodeName)
		}

		testIPv4FragmentSupport := func() {
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
				hasDNAT = kubectl.HasHostReachableServices(ciliumPodK8s1, false, true)
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
			doFragmentedRequest(clientPod, srcPort, serverPort, data.Spec.ClusterIP, data.Spec.Ports[1].Port, true)

			// From pod via node IPs
			doFragmentedRequest(clientPod, srcPort+1, serverPort, k8s1IP, nodePort, hasDNAT)
			doFragmentedRequest(clientPod, srcPort+2, serverPort, "::ffff:"+k8s1IP, nodePort, hasDNAT)
			doFragmentedRequest(clientPod, srcPort+3, serverPort, k8s2IP, nodePort, hasDNAT)
			doFragmentedRequest(clientPod, srcPort+4, serverPort, "::ffff:"+k8s2IP, nodePort, hasDNAT)
		}

		testMaglev := func() {
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

				for _, host := range []string{k8s1IP, k8s2IP} {
					url := getTFTPLink(host, data.Spec.Ports[1].NodePort)
					cmd := helpers.CurlFail("--local-port %d %s", port, url) + " | grep 'Hostname:' " // pod name is in the hostname

					By("Making %d HTTP requests from %s:%d to %q", count, outsideNodeName, port, url)

					for i := 1; i <= count; i++ {
						res := kubectl.ExecInHostNetNS(context.TODO(), outsideNodeName, cmd)
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
				testCurlFromPods(testDSClient, url, 10, 0)

				url = fmt.Sprintf("tftp://%s/hello", net.JoinHostPort(clusterIP, "69"))
				testCurlFromPods(testDSClient, url, 10, 0)
			}
		})

		SkipContextIf(manualIPv6TestingNotRequired(helpers.DoesNotRunWithKubeProxyReplacement), "IPv6 Connectivity", func() {
			testDSIPv6 := "fd03::310"

			BeforeAll(func() {
				// Install rules for testds-service (demo_ds.yaml)
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
				testCurlFromPods(testDSClient, url, 10, 0)

				url = fmt.Sprintf(`"tftp://[%s]/hello"`, testDSIPv6)
				testCurlFromPods(testDSClient, url, 10, 0)
			})
		})

		SkipContextIf(func() bool {
			return helpers.RunsWithKubeProxyReplacement() || helpers.GetCurrentIntegration() != ""
		}, "IPv6 masquerading", func() {
			var (
				k8s2NodeIP      string
				k8s1EndpointIPs map[string]string

				testDSK8s1IPv6 string = "fd03::310"
			)

			BeforeAll(func() {
				DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
					"tunnel":               "disabled",
					"autoDirectNodeRoutes": "true",
				})

				privateIface, err := kubectl.GetPrivateIface()
				Expect(err).Should(BeNil(), "Cannot determine private iface")

				k8s2NodeIP = getIPv6AddrForIface(k8s2NodeName, privateIface)
				Expect(k8s2NodeIP).ToNot(BeEmpty(), "Cannot get primary IPv6 address for K8s2 node")

				pod, err := kubectl.GetCiliumPodOnNode(helpers.K8s1)
				Expect(err).Should(BeNil(), "Cannot get cilium pod on node %s", helpers.K8s1)
				k8s1EndpointIPs = kubectl.CiliumEndpointIPv6(pod, "-l k8s:zgroup=testDS,k8s:io.kubernetes.pod.namespace=default")

				k8s1Backends := []string{}
				for _, epIP := range k8s1EndpointIPs {
					k8s1Backends = append(k8s1Backends, net.JoinHostPort(epIP, "80"))
				}

				ciliumAddService(31080, net.JoinHostPort(testDSK8s1IPv6, "80"), k8s1Backends, "ClusterIP", "Cluster")
			})

			It("across K8s nodes", func() {
				url := fmt.Sprintf(`"http://[%s]:80/"`, testDSK8s1IPv6)
				testCurlFromPodWithSourceIPCheck(testDSK8s2, url, 5, k8s2NodeIP)

				for _, epIP := range k8s1EndpointIPs {
					url = fmt.Sprintf(`"http://[%s]:80/"`, epIP)
					testCurlFromPodWithSourceIPCheck(testDSK8s2, url, 5, k8s2NodeIP)
				}
			})

			AfterAll(func() {
				ciliumDelService(31080)
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
				testExternalTrafficPolicyLocal()
				deploymentManager.DeleteAll()
				deploymentManager.DeleteCilium()
			})

			It("with the host firewall and externalTrafficPolicy=Local", func() {
				DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
					"hostFirewall": "true",
				})
				testExternalTrafficPolicyLocal()
			})

			It("with externalTrafficPolicy=Local", func() {
				DeployCiliumAndDNS(kubectl, ciliumFilename)
				testExternalTrafficPolicyLocal()
			})

			It("", func() {
				testNodePort(false, false, false, 0)
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
				httpBackends := ciliumIPv6Backends("-l k8s:zgroup=testDS,k8s:io.kubernetes.pod.namespace=default", "80")
				ciliumAddService(31080, net.JoinHostPort(testDSIPv6, fmt.Sprintf("%d", data.Spec.Ports[0].NodePort)), httpBackends, "NodePort", "Cluster")
				ciliumAddService(31081, net.JoinHostPort("::", fmt.Sprintf("%d", data.Spec.Ports[0].NodePort)), httpBackends, "NodePort", "Cluster")
				// Add service corresponding to IPv6 address of the nodes so that they become
				// reachable from outside the cluster.
				ciliumAddServiceOnNode(helpers.K8s1, 31082, net.JoinHostPort(primaryK8s1IPv6, fmt.Sprintf("%d", data.Spec.Ports[0].NodePort)),
					httpBackends, "NodePort", "Cluster")
				ciliumAddServiceOnNode(helpers.K8s2, 31082, net.JoinHostPort(primaryK8s2IPv6, fmt.Sprintf("%d", data.Spec.Ports[0].NodePort)),
					httpBackends, "NodePort", "Cluster")

				tftpBackends := ciliumIPv6Backends("-l k8s:zgroup=testDS,k8s:io.kubernetes.pod.namespace=default", "69")
				ciliumAddService(31069, net.JoinHostPort(testDSIPv6, fmt.Sprintf("%d", data.Spec.Ports[1].NodePort)), tftpBackends, "NodePort", "Cluster")
				ciliumAddService(31070, net.JoinHostPort("::", fmt.Sprintf("%d", data.Spec.Ports[1].NodePort)), tftpBackends, "NodePort", "Cluster")
				ciliumAddServiceOnNode(helpers.K8s1, 31071, net.JoinHostPort(primaryK8s1IPv6, fmt.Sprintf("%d", data.Spec.Ports[1].NodePort)),
					tftpBackends, "NodePort", "Cluster")
				ciliumAddServiceOnNode(helpers.K8s2, 31071, net.JoinHostPort(primaryK8s2IPv6, fmt.Sprintf("%d", data.Spec.Ports[1].NodePort)),
					tftpBackends, "NodePort", "Cluster")
			})

			AfterAll(func() {
				ciliumDelService(31080)
				ciliumDelService(31081)
				ciliumDelService(31082)
				ciliumDelService(31069)
				ciliumDelService(31070)
				ciliumDelService(31071)
			})

			It("Test IPv6 connectivity to NodePort service", func() {
				testNodePortIPv6(primaryK8s1IPv6, primaryK8s2IPv6, helpers.ExistNodeWithoutCilium(), &data)
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

				applyPolicy(demoPolicy)

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
				url := getTFTPLink(k8s2IP, data.Spec.Ports[1].NodePort) + fmt.Sprintf(" --local-port %d", DNSProxyPort2)
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
					url := getTFTPLink(primaryK8s2IPv6, data.Spec.Ports[1].NodePort) + fmt.Sprintf(" --local-port %d", DNSProxyPort2)
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

				applyPolicy(demoPolicy)
				testNodePort(false, false, false, 0)
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

				applyPolicy(demoPolicyL7)
				testNodePort(false, false, false, 0)
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
						testNodePort(true, false, helpers.ExistNodeWithoutCilium(), 0)
					})

					It("Tests NodePort with externalTrafficPolicy=Local", func() {
						testExternalTrafficPolicyLocal()
					})

					It("Tests NodePort with sessionAffinity", func() {
						testSessionAffinity(false, true)
					})

					SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests NodePort with sessionAffinity from outside", func() {
						testSessionAffinity(true, true)
					})

					It("Tests HealthCheckNodePort", func() {
						testHealthCheckNodePort()
					})

					It("Tests that binding to NodePort port fails", func() {
						testFailBind()
					})

					It("Tests HostPort", func() {
						testHostPort()
					})

					SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests externalIPs", func() {
						testExternalIPs()
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
							testNodePort(true, false, helpers.ExistNodeWithoutCilium(), 0)
						})
					})

					Context("with L7 policy", func() {
						AfterAll(func() { kubectl.Delete(demoPolicyL7) })

						It("Tests NodePort with L7 Policy", func() {
							applyPolicy(demoPolicyL7)
							testNodePort(false, false, false, 0)
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
							testNodePort(true, false, helpers.ExistNodeWithoutCilium(), 0)
						})

						SkipItIf(helpers.DoesNotExistNodeWithoutCilium,
							"Tests Maglev backend selection", func() {
								testMaglev()
							})
					})

					SkipItIf(func() bool {
						// Quarantine when running with the third node as it's
						// flaky. See #12511.
						return helpers.GetCurrentIntegration() != "" ||
							(helpers.SkipQuarantined() && helpers.ExistNodeWithoutCilium())
					}, "Tests with secondary NodePort device", func() {
						DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
							"devices": fmt.Sprintf(`'{%s,%s}'`, privateIface, helpers.SecondaryIface),
						})

						testNodePort(true, true, helpers.ExistNodeWithoutCilium(), 0)
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
						testNodePort(true, false, helpers.ExistNodeWithoutCilium(), 0)
					})

					It("Tests NodePort with externalTrafficPolicy=Local", func() {
						testExternalTrafficPolicyLocal()
					})

					It("Tests NodePort with sessionAffinity", func() {
						testSessionAffinity(false, false)
					})

					SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests NodePort with sessionAffinity from outside", func() {
						testSessionAffinity(true, false)
					})

					It("Tests HealthCheckNodePort", func() {
						testHealthCheckNodePort()
					})

					It("Tests that binding to NodePort port fails", func() {
						testFailBind()
					})

					It("Tests HostPort", func() {
						testHostPort()
					})

					SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests externalIPs", func() {
						testExternalIPs()
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
							testNodePort(true, false, helpers.ExistNodeWithoutCilium(), 0)
						})
					})

					Context("with L7 policy", func() {
						AfterAll(func() { kubectl.Delete(demoPolicyL7) })

						It("Tests NodePort with L7 Policy", func() {
							applyPolicy(demoPolicyL7)
							testNodePort(false, false, false, 0)
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
							testNodePort(true, false, helpers.ExistNodeWithoutCilium(), 0)
						})

						SkipItIf(helpers.DoesNotExistNodeWithoutCilium,
							"Tests Maglev backend selection", func() {
								testMaglev()
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
						svc1URL := getHTTPLink(k8s2IP, data.Spec.Ports[0].NodePort)
						err = kubectl.Get(helpers.DefaultNamespace, "svc test-nodeport-k8s2").Unmarshal(&data)
						Expect(err).Should(BeNil(), "Can not retrieve service")
						svc2URL := getHTTPLink(k8s2IP, data.Spec.Ports[0].NodePort)

						// Send two requests from the same src IP and port to the endpoint
						// via two different NodePort svc to trigger the stale conntrack
						// entry issue. Once it's fixed, the second request should not
						// fail.
						testCurlFromOutsideWithLocalPort(svc1URL, 1, false, 64002)
						time.Sleep(120 * time.Second) // to reuse the source port
						testCurlFromOutsideWithLocalPort(svc2URL, 1, false, 64002)
					})

					SkipContextIf(helpers.DoesNotExistNodeWithoutCilium, "Tests LoadBalancer", func() {
						const svcName = "test-lb-with-ip"

						var (
							frr      string // BGP router
							routerIP string

							bgpConfigMap string

							lbSVC string

							ciliumPodK8s1, ciliumPodK8s2 string
							testStartTime                time.Time
						)

						applyFRRTemplate := func() string {
							tmpl := helpers.ManifestGet(kubectl.BasePath(), "frr.yaml.tmpl")
							content, err := os.ReadFile(tmpl)
							ExpectWithOffset(1, err).ToNot(HaveOccurred())
							ExpectWithOffset(1, content).ToNot(BeEmpty())

							render, err := ioutil.TempFile(os.TempDir(), "frr-")
							ExpectWithOffset(1, err).ToNot(HaveOccurred())
							defer render.Close()

							t := template.Must(template.New("").Parse(string(content)))
							err = t.Execute(render, struct {
								OutsideNodeName string
								Nodes           []string
							}{
								OutsideNodeName: outsideNodeName,
								Nodes:           []string{k8s1IP, k8s2IP},
							})
							ExpectWithOffset(1, err).ToNot(HaveOccurred())

							path, err := filepath.Abs(render.Name())
							ExpectWithOffset(1, err).ToNot(HaveOccurred())
							return path
						}

						applyBGPCMTemplate := func(ip string) string {
							tmpl := helpers.ManifestGet(kubectl.BasePath(), "bgp-configmap.yaml.tmpl")
							content, err := os.ReadFile(tmpl)
							ExpectWithOffset(1, err).ToNot(HaveOccurred())
							ExpectWithOffset(1, content).ToNot(BeEmpty())

							render, err := ioutil.TempFile(os.TempDir(), "bgp-cm-")
							ExpectWithOffset(1, err).ToNot(HaveOccurred())
							defer render.Close()

							t := template.Must(template.New("").Parse(string(content)))
							err = t.Execute(render, struct {
								RouterIP string
							}{
								RouterIP: ip,
							})
							ExpectWithOffset(1, err).ToNot(HaveOccurred())

							path, err := filepath.Abs(render.Name())
							ExpectWithOffset(1, err).ToNot(HaveOccurred())
							return path
						}

						BeforeAll(func() {
							frr = applyFRRTemplate()
							kubectl.ApplyDefault(frr).ExpectSuccess("Unable to apply rendered tempplate %s", frr)

							Eventually(func() string {
								frrPod, err := kubectl.GetPodsIPs(helpers.KubeSystemNamespace, "app=frr")
								if _, ok := frrPod["frr"]; err != nil || !ok {
									return ""
								}
								routerIP = frrPod["frr"]
								return routerIP
							}, 30*time.Second, 1*time.Second).Should(Not(BeEmpty()), "BGP router is not ready")

							bgpConfigMap = applyBGPCMTemplate(routerIP)
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

							kubectl.Delete(frr)
							kubectl.Delete(bgpConfigMap)
							kubectl.Delete(lbSVC)
							// Delete temp files
							os.Remove(frr)
							os.Remove(bgpConfigMap)
						})

						It("Connectivity to endpoint via LB", func() {
							By("Waiting until the Operator has assigned the LB IP")
							lbIP, err := kubectl.GetLoadBalancerIP(
								helpers.DefaultNamespace, svcName, 30*time.Second)
							Expect(err).Should(BeNil(), "Cannot retrieve LB IP for test-lb")

							By("Waiting until the Agents have announced the LB IP via BGP")
							Eventually(func() string {
								return kubectl.ExecInHostNetNS(
									context.TODO(),
									outsideNodeName,
									"ip route",
								).GetStdOut().String()
							}, 30*time.Second, 1*time.Second).Should(ContainSubstring(lbIP),
								"BGP router does not have route for LB IP")

							// Check connectivity from outside
							url := "http://" + lbIP
							testCurlFromOutside(url, 10, false)

							// Patch service to add a LB source range to disallow requests
							// from the outsideNode
							kubectl.Patch(helpers.DefaultNamespace, "service", svcName,
								`{"spec": {"loadBalancerSourceRanges": ["1.1.1.0/24"]}}`)
							time.Sleep(5 * time.Second)
							testCurlFailFromOutside(url, 1)
							// Patch again, but this time add outsideNode IP addr
							kubectl.Patch(helpers.DefaultNamespace, "service", svcName,
								fmt.Sprintf(
									`{"spec": {"loadBalancerSourceRanges": ["1.1.1.0/24", "%s/32"]}}`,
									outsideIP))
							time.Sleep(5 * time.Second)
							testCurlFromOutside(url, 10, false)
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
							for _, node := range []string{k8s1NodeName, k8s2NodeName, outsideNodeName} {
								kubectl.ExecInHostNetNS(context.TODO(), node, "ip l del wg0")
							}
						})

						It("Tests NodePort BPF", func() {
							var data v1.Service
							err := kubectl.Get(helpers.DefaultNamespace, "service test-nodeport").Unmarshal(&data)
							Expect(err).Should(BeNil(), "Cannot retrieve service")

							By("SNAT with direct routing device wg0")

							DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
								"devices":                      fmt.Sprintf(`'{%s,%s}'`, privateIface, "wg0"),
								"nodePort.directRoutingDevice": "wg0",
								"tunnel":                       "disabled",
								"autoDirectNodeRoutes":         "true",
								"bpf.masquerade":               "false",
							})

							// Test via k8s1 private iface
							url := getHTTPLink(k8s1IP, data.Spec.Ports[0].NodePort)
							testCurlFromOutside(url, 10, false)
							// Test via k8s1 wg0 iface
							wgK8s1IPv4 := getIPv4AddrForIface(k8s1NodeName, "wg0")
							url = getHTTPLink(wgK8s1IPv4, data.Spec.Ports[0].NodePort)
							testCurlFromOutside(url, 10, false)

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
								"devices":                      fmt.Sprintf(`'{%s,%s}'`, privateIface, "wg0"),
								"nodePort.directRoutingDevice": privateIface,
								"tunnel":                       "disabled",
								"autoDirectNodeRoutes":         "true",
								"bpf.masquerade":               "false",
							})

							// Test via k8s1 private iface
							url = getHTTPLink(k8s1IP, data.Spec.Ports[0].NodePort)
							testCurlFromOutside(url, 10, false)
							// Test via k8s1 wg0 iface
							url = getHTTPLink(wgK8s1IPv4, data.Spec.Ports[0].NodePort)
							testCurlFromOutside(url, 10, false)

							By("DSR with direct routing device private")

							// Do the same test for DSR
							DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
								"devices":                      fmt.Sprintf(`'{%s,%s}'`, privateIface, "wg0"),
								"nodePort.directRoutingDevice": privateIface,
								"tunnel":                       "disabled",
								"autoDirectNodeRoutes":         "true",
								"loadBalancer.mode":            "dsr",
							})

							// Test via k8s1 private iface
							url = getHTTPLink(k8s1IP, data.Spec.Ports[0].NodePort)
							testCurlFromOutside(url, 10, false)
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
						"devices":              fmt.Sprintf(`'{%s,%s}'`, privateIface, helpers.SecondaryIface),
					})

					testNodePort(true, true, helpers.ExistNodeWithoutCilium(), 0)
				})

				testDSR := func(sourcePortForCTGCtest int) {
					var data v1.Service
					err := kubectl.Get(helpers.DefaultNamespace, "service test-nodeport").Unmarshal(&data)
					ExpectWithOffset(1, err).Should(BeNil(), "Cannot retrieve service")
					url := getHTTPLink(k8s1IP, data.Spec.Ports[0].NodePort)
					testCurlFromOutside(url, 10, true)

					// Test whether DSR NAT entries are evicted by GC

					pod, err := kubectl.GetCiliumPodOnNode(helpers.K8s2)
					ExpectWithOffset(1, err).Should(BeNil(), "Cannot determine cilium pod name")
					// "test-nodeport-k8s2" because we want to trigger SNAT with a single request:
					// client -> k8s1 -> endpoint @ k8s2.
					err = kubectl.Get(helpers.DefaultNamespace, "service test-nodeport-k8s2").Unmarshal(&data)
					ExpectWithOffset(1, err).Should(BeNil(), "Cannot retrieve service")
					url = getHTTPLink(k8s1IP, data.Spec.Ports[0].NodePort)

					testCurlFromOutsideWithLocalPort(url, 1, true, sourcePortForCTGCtest)
					res := kubectl.CiliumExecContext(context.TODO(), pod, fmt.Sprintf("cilium bpf nat list | grep %d", sourcePortForCTGCtest))
					ExpectWithOffset(1, res.Stdout()).ShouldNot(BeEmpty(), "NAT entry was not evicted")
					// Flush CT maps to trigger eviction of the NAT entries (simulates CT GC)
					_ = kubectl.CiliumExecMustSucceed(context.TODO(), pod, "cilium bpf ct flush global", "Unable to flush CT maps")
					res = kubectl.CiliumExecContext(context.TODO(), pod, fmt.Sprintf("cilium bpf nat list | grep %d", sourcePortForCTGCtest))
					res.ExpectFail("NAT entry was not evicted")
				}

				SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests with direct routing and DSR", func() {
					DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
						"loadBalancer.mode":    "dsr",
						"tunnel":               "disabled",
						"autoDirectNodeRoutes": "true",
					})

					testDSR(64000)
					testNodePort(true, false, false, 0) // no need to test from outside, as testDSR did it
				})

				SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests with XDP, direct routing, SNAT and Random", func() {
					DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
						"loadBalancer.acceleration": "testing-only",
						"loadBalancer.mode":         "snat",
						"loadBalancer.algorithm":    "random",
						"tunnel":                    "disabled",
						"autoDirectNodeRoutes":      "true",
						"devices":                   fmt.Sprintf(`'{%s}'`, privateIface),
					})
					testNodePortExternal(false, false)
				})

				SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests with XDP, direct routing, SNAT and Maglev", func() {
					DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
						"loadBalancer.acceleration": "testing-only",
						"loadBalancer.mode":         "snat",
						"loadBalancer.algorithm":    "maglev",
						"maglev.tableSize":          "251",
						"tunnel":                    "disabled",
						"autoDirectNodeRoutes":      "true",
						"devices":                   fmt.Sprintf(`'{%s}'`, privateIface),
						// Support for host firewall + Maglev is currently broken,
						// see #14047 for details.
						"hostFirewall": "false",
					})
					testNodePortExternal(false, false)
				})

				SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests with XDP, direct routing, Hybrid and Random", func() {
					DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
						"loadBalancer.acceleration": "testing-only",
						"loadBalancer.mode":         "hybrid",
						"loadBalancer.algorithm":    "random",
						"tunnel":                    "disabled",
						"autoDirectNodeRoutes":      "true",
						"devices":                   fmt.Sprintf(`'{%s}'`, privateIface),
					})
					testNodePortExternal(true, false)
				})

				SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests with XDP, direct routing, Hybrid and Maglev", func() {
					DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
						"loadBalancer.acceleration": "testing-only",
						"loadBalancer.mode":         "hybrid",
						"loadBalancer.algorithm":    "maglev",
						"maglev.tableSize":          "251",
						"tunnel":                    "disabled",
						"autoDirectNodeRoutes":      "true",
						"devices":                   fmt.Sprintf(`'{%s}'`, privateIface),
						// Support for host firewall + Maglev is currently broken,
						// see #14047 for details.
						"hostFirewall": "false",
					})
					testNodePortExternal(true, false)
				})

				SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests with XDP, direct routing, DSR and Random", func() {
					DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
						"loadBalancer.acceleration": "testing-only",
						"loadBalancer.mode":         "dsr",
						"loadBalancer.algorithm":    "random",
						"tunnel":                    "disabled",
						"autoDirectNodeRoutes":      "true",
						"devices":                   fmt.Sprintf(`'{%s}'`, privateIface),
					})
					testNodePortExternal(true, true)
				})

				SkipItIf(helpers.DoesNotExistNodeWithoutCilium, "Tests with XDP, direct routing, DSR and Maglev", func() {
					DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
						"loadBalancer.acceleration": "testing-only",
						"loadBalancer.mode":         "dsr",
						"loadBalancer.algorithm":    "maglev",
						"maglev.tableSize":          "251",
						"tunnel":                    "disabled",
						"autoDirectNodeRoutes":      "true",
						"devices":                   fmt.Sprintf(`'{%s}'`, privateIface),
						// Support for host firewall + Maglev is currently broken,
						// see #14047 for details.
						"hostFirewall": "false",
					})
					testNodePortExternal(true, true)
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
					testNodePortExternal(true, false)
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

		BeforeAll(func() {
			DeployCiliumAndDNS(kubectl, ciliumFilename)

			bookinfoV1YAML = helpers.ManifestGet(kubectl.BasePath(), "bookinfo-v1.yaml")
			bookinfoV2YAML = helpers.ManifestGet(kubectl.BasePath(), "bookinfo-v2.yaml")
			policyPath = helpers.ManifestGet(kubectl.BasePath(), "cnp-specs.yaml")

			resourceYAMLs = []string{bookinfoV1YAML, bookinfoV2YAML}

			for _, resourcePath := range resourceYAMLs {
				By("Creating objects in file %q", resourcePath)
				res := kubectl.Create(resourcePath)
				res.ExpectSuccess("unable to create resource %q", resourcePath)
			}

			By("Waiting for pods to be ready")
			err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=bookinfo", helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Pods are not ready after timeout")
		})

		AfterAll(func() {

			// Explicitly do not check result to avoid having assertions in AfterAll.
			_ = kubectl.Delete(policyPath)

			for _, resourcePath := range resourceYAMLs {
				By("Deleting resource %s", resourcePath)
				// Explicitly do not check result to avoid having assertions in AfterAll.
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

			err := kubectl.CiliumEndpointWaitReady()
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

			ciliumPodK8s1, err := kubectl.GetCiliumPodOnNode(helpers.K8s1)
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
