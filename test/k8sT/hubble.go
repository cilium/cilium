// Copyright 2020 Authors of Cilium
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

	"github.com/asaskevich/govalidator"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/hubble/defaults"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"

	. "github.com/onsi/gomega"
)

var _ = Describe("K8sHubbleTest", func() {
	// We want to run Hubble tests both with and without our kube-proxy
	// replacement, as the trace events depend on it. We thus run the tests
	// on GKE and our 4.9 pipeline.
	SkipContextIf(helpers.RunsOnNetNextOr419Kernel, "Hubble Observe", func() {
		var (
			kubectl        *helpers.Kubectl
			ciliumFilename string
			k8s1NodeName   string
			ciliumPodK8s1  string

			hubbleRelayNamespace = helpers.CiliumNamespace
			hubbleRelayService   = "hubble-relay"
			hubbleRelayAddress   string

			demoPath string

			app1Service    = "app1-service"
			app1Labels     = "id=app1,zgroup=testapp"
			apps           = []string{helpers.App1, helpers.App2, helpers.App3}
			prometheusPort = "9091"

			namespaceForTest string
			appPods          map[string]string
			app1ClusterIP    string
			app1Port         int
		)

		addVisibilityAnnotation := func(ns, podLabels, direction, port, l4proto, l7proto string) {
			visibilityAnnotation := fmt.Sprintf("<%s/%s/%s/%s>", direction, port, l4proto, l7proto)
			By("Adding visibility annotation %s on pod with labels %s", visibilityAnnotation, podLabels)

			// Prints <node>=<ns>/<podname> for each pod the annotation was applied to
			res := kubectl.Exec(fmt.Sprintf("%s annotate pod -n %s -l %s %s=%q"+
				" -o 'jsonpath={.spec.nodeName}={.metadata.namespace}/{.metadata.name}{\"\\n\"}'",
				helpers.KubectlCmd,
				ns, app1Labels,
				annotation.ProxyVisibility, visibilityAnnotation))
			res.ExpectSuccess("adding proxy visibility annotation failed")

			// For each pod, check that the Cilium proxy-statistics contain the new annotation
			expectedProxyState := strings.ToLower(visibilityAnnotation)
			for node, podName := range res.KVOutput() {
				ciliumPod, err := kubectl.GetCiliumPodOnNode(node)
				Expect(err).To(BeNil())

				// Extract annotation from endpoint model of pod. It does not have the l4proto, so we insert it manually.
				cmd := fmt.Sprintf("cilium endpoint get pod-name:%s"+
					" -o jsonpath='{range [*].status.policy.proxy-statistics[*]}<{.location}/{.port}/%s/{.protocol}>{\"\\n\"}{end}'",
					podName, strings.ToLower(l4proto))
				err = kubectl.CiliumExecUntilMatch(ciliumPod, cmd, expectedProxyState)
				Expect(err).To(BeNil(), "timed out waiting for endpoint to regenerate for visibility annotation")
			}
		}

		removeVisibilityAnnotation := func(ns, podLabels string) {
			By("Removing visibility annotation on pod with labels %s", app1Labels)
			res := kubectl.Exec(fmt.Sprintf("%s annotate pod -n %s -l %s %s-", helpers.KubectlCmd, ns, podLabels, annotation.ProxyVisibility))
			res.ExpectSuccess("removing proxy visibility annotation failed")
		}

		hubbleObserveUntilMatch := func(hubblePod, args, filter, expected string, timeout time.Duration) {
			hubbleObserve := func() bool {
				res := kubectl.HubbleObserve(hubblePod, args)
				res.ExpectSuccess("hubble observe invocation failed: %q", res.OutputPrettyPrint())

				lines, err := res.FilterLines(filter)
				Expect(err).Should(BeNil(), "hubble observe: invalid filter: %q", filter)

				for _, line := range lines {
					if line.String() == expected {
						return true
					}
				}

				return false
			}

			Eventually(hubbleObserve, timeout, time.Second).Should(BeTrue(),
				"hubble observe: filter %q never matched expected string %q", filter, expected)
		}

		BeforeAll(func() {
			kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
			k8s1NodeName, _ = kubectl.GetNodeInfo(helpers.K8s1)

			demoPath = helpers.ManifestGet(kubectl.BasePath(), "demo.yaml")

			ciliumFilename = helpers.TimestampFilename("cilium.yaml")
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"hubble.metrics.enabled": `"{dns:query;ignoreAAAA,drop,tcp,flow,port-distribution,icmp,http}"`,
				"hubble.relay.enabled":   "true",
			})

			var err error
			ciliumPodK8s1, err = kubectl.GetCiliumPodOnNodeWithLabel(helpers.K8s1)
			Expect(err).Should(BeNil(), "unable to find hubble-cli pod on %s", helpers.K8s1)

			ExpectHubbleRelayReady(kubectl, hubbleRelayNamespace)
			hubbleRelayIP, hubbleRelayPort, err := kubectl.GetServiceHostPort(hubbleRelayNamespace, hubbleRelayService)
			Expect(err).Should(BeNil(), "Cannot get service %s", hubbleRelayService)
			Expect(govalidator.IsIP(hubbleRelayIP)).Should(BeTrue(), "hubbleRelayIP is not an IP")
			hubbleRelayAddress = net.JoinHostPort(hubbleRelayIP, strconv.Itoa(hubbleRelayPort))

			namespaceForTest = helpers.GenerateNamespaceForTest("")
			kubectl.NamespaceDelete(namespaceForTest)
			res := kubectl.NamespaceCreate(namespaceForTest)
			res.ExpectSuccess("could not create namespace")

			res = kubectl.Apply(helpers.ApplyOptions{FilePath: demoPath, Namespace: namespaceForTest})
			res.ExpectSuccess("could not create resource")

			err = kubectl.WaitforPods(namespaceForTest, "-l zgroup=testapp", helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "test pods are not ready after timeout")

			appPods = helpers.GetAppPods(apps, namespaceForTest, kubectl, "id")
			app1ClusterIP, app1Port, err = kubectl.GetServiceHostPort(namespaceForTest, app1Service)
			Expect(err).To(BeNil(), "unable to find service in %q namespace", namespaceForTest)
		})

		AfterFailed(func() {
			kubectl.CiliumReport("cilium endpoint list")
		})

		JustAfterEach(func() {
			kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
		})

		AfterEach(func() {
			ExpectAllPodsTerminated(kubectl)
		})

		AfterAll(func() {
			kubectl.Delete(demoPath)
			kubectl.NamespaceDelete(namespaceForTest)

			kubectl.DeleteHubbleRelay(hubbleRelayNamespace)
			UninstallCiliumFromManifest(kubectl, ciliumFilename)
			kubectl.CloseSSHClient()
		})

		It("Test L3/L4 Flow", func() {
			ctx, cancel := context.WithTimeout(context.Background(), helpers.MidCommandTimeout)
			defer cancel()
			follow := kubectl.HubbleObserveFollow(ctx, ciliumPodK8s1, fmt.Sprintf(
				"--last 1 --type trace --from-pod %s/%s --to-namespace %s --to-label %s --to-port %d",
				namespaceForTest, appPods[helpers.App2], namespaceForTest, app1Labels, app1Port))

			res := kubectl.ExecPodCmd(namespaceForTest, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", app1ClusterIP)))
			res.ExpectSuccess("%q cannot curl clusterIP %q", appPods[helpers.App2], app1ClusterIP)

			err := follow.WaitUntilMatchFilterLineTimeout(`{$.Type}`, "L3_L4", helpers.ShortCommandTimeout)
			Expect(err).To(BeNil(), fmt.Sprintf("hubble observe query timed out on %q", follow.OutputPrettyPrint()))

			// Basic check for L4 Prometheus metrics.
			_, nodeIP := kubectl.GetNodeInfo(helpers.K8s1)
			metricsUrl := fmt.Sprintf("%s/metrics", net.JoinHostPort(nodeIP, prometheusPort))
			res = kubectl.ExecInHostNetNS(ctx, k8s1NodeName, helpers.CurlFail(metricsUrl))
			res.ExpectSuccess("%s/%s cannot curl metrics %q", helpers.CiliumNamespace, ciliumPodK8s1, app1ClusterIP)
			res.ExpectContains(`hubble_flows_processed_total{protocol="TCP",subtype="to-endpoint",type="Trace",verdict="FORWARDED"}`)
		})

		It("Test TLS certificate", func() {
			certpath := "/var/lib/cilium/tls/hubble/server.crt"
			res := kubectl.ExecPodCmd(helpers.CiliumNamespace, ciliumPodK8s1, helpers.ReadFile(certpath))
			res.ExpectSuccess("Cilium pod cannot read the hubble server TLS certificate")
			expected := string(res.GetStdOut().Bytes())

			serverName := fmt.Sprintf("%s.default.hubble-grpc.cilium.io", helpers.K8s1)
			cmd := helpers.OpenSSLShowCerts("localhost", defaults.ServerPort, serverName)
			res = kubectl.ExecPodCmd(helpers.CiliumNamespace, ciliumPodK8s1, cmd)
			res.ExpectSuccess("Cilium pod cannot initiate TLS handshake to Hubble")
			cert := string(res.GetStdOut().Bytes())

			Expect(cert).To(Equal(expected))
		})

		It("Test L3/L4 Flow with hubble-relay", func() {
			res := kubectl.ExecPodCmd(namespaceForTest, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", app1ClusterIP)))
			res.ExpectSuccess("%q cannot curl clusterIP %q", appPods[helpers.App2], app1ClusterIP)

			// In case a node was temporarily unavailable, hubble-relay will
			// reconnect once it receives a new request. Therefore we retry
			// in a 5 second interval.
			hubbleObserveUntilMatch(ciliumPodK8s1, fmt.Sprintf(
				"--server %s --last 1 --type trace --from-pod %s/%s --to-namespace %s --to-label %s --to-port %d",
				hubbleRelayAddress, namespaceForTest, appPods[helpers.App2], namespaceForTest, app1Labels, app1Port),
				`{$.Type}`, "L3_L4",
				helpers.MidCommandTimeout)
		})

		It("Test L7 Flow", func() {
			addVisibilityAnnotation(namespaceForTest, app1Labels, "Ingress", "80", "TCP", "HTTP")
			defer removeVisibilityAnnotation(namespaceForTest, app1Labels)

			ctx, cancel := context.WithTimeout(context.Background(), helpers.MidCommandTimeout)
			defer cancel()
			follow := kubectl.HubbleObserveFollow(ctx, ciliumPodK8s1, fmt.Sprintf(
				"--last 1 --type l7 --from-pod %s/%s --to-namespace %s --to-label %s --protocol http",
				namespaceForTest, appPods[helpers.App2], namespaceForTest, app1Labels))

			res := kubectl.ExecPodCmd(namespaceForTest, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", app1ClusterIP)))
			res.ExpectSuccess("%q cannot curl clusterIP %q", appPods[helpers.App2], app1ClusterIP)

			err := follow.WaitUntilMatchFilterLineTimeout(`{$.Type}`, "L7", helpers.ShortCommandTimeout)
			Expect(err).To(BeNil(), fmt.Sprintf("hubble observe query timed out on %q", follow.OutputPrettyPrint()))

			// Basic check for L7 Prometheus metrics.
			_, nodeIP := kubectl.GetNodeInfo(helpers.K8s1)
			metricsUrl := fmt.Sprintf("%s/metrics", net.JoinHostPort(nodeIP, prometheusPort))
			res = kubectl.ExecInHostNetNS(ctx, k8s1NodeName, helpers.CurlFail(metricsUrl))
			res.ExpectSuccess("%s/%s cannot curl metrics %q", helpers.CiliumNamespace, ciliumPodK8s1, app1ClusterIP)
			res.ExpectContains(`hubble_flows_processed_total{protocol="HTTP",subtype="HTTP",type="L7",verdict="FORWARDED"}`)
		})

		It("Test L7 Flow with hubble-relay", func() {
			addVisibilityAnnotation(namespaceForTest, app1Labels, "Ingress", "80", "TCP", "HTTP")
			defer removeVisibilityAnnotation(namespaceForTest, app1Labels)

			res := kubectl.ExecPodCmd(namespaceForTest, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", app1ClusterIP)))
			res.ExpectSuccess("%q cannot curl clusterIP %q", appPods[helpers.App2], app1ClusterIP)

			// In case a node was temporarily unavailable, hubble-relay will
			// reconnect once it receives a new request. Therefore we retry
			// in a 5 second interval.
			hubbleObserveUntilMatch(ciliumPodK8s1, fmt.Sprintf(
				"--server %s --last 1 --type l7 --from-pod %s/%s --to-namespace %s --to-label %s --protocol http",
				hubbleRelayAddress, namespaceForTest, appPods[helpers.App2], namespaceForTest, app1Labels),
				`{$.Type}`, "L7",
				helpers.MidCommandTimeout)
		})
	})
})
