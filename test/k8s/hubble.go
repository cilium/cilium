// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8sTest

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	. "github.com/onsi/gomega"
	"google.golang.org/protobuf/encoding/protojson"

	observerpb "github.com/cilium/cilium/api/v1/observer"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/hubble/defaults"
	"github.com/cilium/cilium/pkg/identity"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
)

var _ = Describe("K8sAgentHubbleTest", func() {
	// We want to run Hubble tests both with and without our kube-proxy
	// replacement, as the trace events depend on it. We thus run the tests
	// on GKE and our 4.19 pipeline.
	SkipContextIf(func() bool {
		return helpers.RunsOnNetNextKernel() || helpers.RunsOnAKS()
	}, "Hubble Observe", func() {
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
			prometheusPort = "9965"

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
				ciliumPod, err := kubectl.GetCiliumPodOnNodeByName(node)
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

		getFlowsFromRelay := func(args string) []*observerpb.GetFlowsResponse {
			args = fmt.Sprintf("--server %s %s", hubbleRelayAddress, args)

			var result []*observerpb.GetFlowsResponse
			hubbleObserve := func() error {
				res := kubectl.HubbleObserve(ciliumPodK8s1, args)
				res.ExpectSuccess("hubble observe invocation failed: %q", res.OutputPrettyPrint())

				lines := res.ByLines()
				flows := make([]*observerpb.GetFlowsResponse, 0, len(lines))
				for _, line := range lines {
					if len(line) == 0 {
						continue
					}

					f := &observerpb.GetFlowsResponse{}
					if err := protojson.Unmarshal([]byte(line), f); err != nil {
						return fmt.Errorf("failed to decode in %q: %w", lines, err)
					}
					flows = append(flows, f)
				}

				if len(flows) == 0 {
					return fmt.Errorf("no flows returned for query %q", args)
				}

				result = flows
				return nil
			}

			Eventually(hubbleObserve, helpers.MidCommandTimeout).Should(BeNil())
			return result
		}

		BeforeAll(func() {
			kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
			k8s1NodeName, _ = kubectl.GetNodeInfo(helpers.K8s1)

			demoPath = helpers.ManifestGet(kubectl.BasePath(), "demo.yaml")

			ciliumFilename = helpers.TimestampFilename("cilium.yaml")
			DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, map[string]string{
				"hubble.metrics.enabled": `"{dns:query;ignoreAAAA,drop,tcp,flow,port-distribution,icmp,http}"`,
				"hubble.relay.enabled":   "true",
				"bpf.monitorAggregation": "none",
			})

			var err error
			ciliumPodK8s1, err = kubectl.GetCiliumPodOnNode(helpers.K8s1)
			Expect(err).Should(BeNil(), "unable to find hubble-cli pod on %s", helpers.K8s1)

			ExpectHubbleRelayReady(kubectl, hubbleRelayNamespace)
			hubbleRelayIP, hubbleRelayPort, err := kubectl.GetServiceHostPort(hubbleRelayNamespace, hubbleRelayService)
			Expect(err).Should(BeNil(), "Cannot get service %s", hubbleRelayService)
			Expect(net.ParseIP(hubbleRelayIP) != nil).Should(BeTrue(), "hubbleRelayIP is not an IP")
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

		AfterAll(func() {
			kubectl.Delete(demoPath)
			kubectl.NamespaceDelete(namespaceForTest)
			ExpectAllPodsTerminated(kubectl)

			kubectl.DeleteHubbleRelay(hubbleRelayNamespace)
			UninstallCiliumFromManifest(kubectl, ciliumFilename)
			kubectl.CloseSSHClient()
		})

		It("Test L3/L4 Flow", func() {
			ctx, cancel := context.WithTimeout(context.Background(), helpers.MidCommandTimeout)
			defer cancel()
			follow, err := kubectl.HubbleObserveFollow(ctx, ciliumPodK8s1, fmt.Sprintf(
				"--last 1 --type trace --from-pod %s/%s --to-namespace %s --to-label %s --to-port %d",
				namespaceForTest, appPods[helpers.App2], namespaceForTest, app1Labels, app1Port))
			Expect(err).To(BeNil(), "Failed to start hubble observe")

			res := kubectl.ExecPodCmd(namespaceForTest, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", app1ClusterIP)))
			res.ExpectSuccess("%q cannot curl clusterIP %q", appPods[helpers.App2], app1ClusterIP)

			err = follow.WaitUntilMatchFilterLineTimeout(`{$.flow.Type}`, "L3_L4", helpers.ShortCommandTimeout)
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

			flows := getFlowsFromRelay(fmt.Sprintf(
				"--last 1 --type trace --from-pod %s/%s --to-namespace %s --to-label %s --to-port %d",
				namespaceForTest, appPods[helpers.App2], namespaceForTest, app1Labels, app1Port))
			Expect(flows).NotTo(BeEmpty())
		})

		It("Test L7 Flow", func() {
			defer removeVisibilityAnnotation(namespaceForTest, app1Labels)
			addVisibilityAnnotation(namespaceForTest, app1Labels, "Ingress", "80", "TCP", "HTTP")

			ctx, cancel := context.WithTimeout(context.Background(), helpers.MidCommandTimeout)
			defer cancel()
			follow, err := kubectl.HubbleObserveFollow(ctx, ciliumPodK8s1, fmt.Sprintf(
				"--last 1 --type l7 --from-pod %s/%s --to-namespace %s --to-label %s --protocol http",
				namespaceForTest, appPods[helpers.App2], namespaceForTest, app1Labels))
			Expect(err).To(BeNil(), "Failed to start hubble observe")

			res := kubectl.ExecPodCmd(namespaceForTest, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", app1ClusterIP)))
			res.ExpectSuccess("%q cannot curl clusterIP %q", appPods[helpers.App2], app1ClusterIP)

			err = follow.WaitUntilMatchFilterLineTimeout(`{$.flow.Type}`, "L7", helpers.ShortCommandTimeout)
			Expect(err).To(BeNil(), fmt.Sprintf("hubble observe query timed out on %q", follow.OutputPrettyPrint()))

			// Basic check for L7 Prometheus metrics.
			_, nodeIP := kubectl.GetNodeInfo(helpers.K8s1)
			metricsUrl := fmt.Sprintf("%s/metrics", net.JoinHostPort(nodeIP, prometheusPort))
			res = kubectl.ExecInHostNetNS(ctx, k8s1NodeName, helpers.CurlFail(metricsUrl))
			res.ExpectSuccess("%s/%s cannot curl metrics %q", helpers.CiliumNamespace, ciliumPodK8s1, app1ClusterIP)
			res.ExpectContains(`hubble_flows_processed_total{protocol="HTTP",subtype="HTTP",type="L7",verdict="FORWARDED"}`)
		})

		It("Test L7 Flow with hubble-relay", func() {
			defer removeVisibilityAnnotation(namespaceForTest, app1Labels)
			addVisibilityAnnotation(namespaceForTest, app1Labels, "Ingress", "80", "TCP", "HTTP")

			res := kubectl.ExecPodCmd(namespaceForTest, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", app1ClusterIP)))
			res.ExpectSuccess("%q cannot curl clusterIP %q", appPods[helpers.App2], app1ClusterIP)

			flows := getFlowsFromRelay(fmt.Sprintf(
				"--last 1 --type l7 --from-pod %s/%s --to-namespace %s --to-label %s --protocol http",
				namespaceForTest, appPods[helpers.App2], namespaceForTest, app1Labels))
			Expect(flows).NotTo(BeEmpty())
		})

		It("Test FQDN Policy with Relay", func() {
			fqdnProxyPolicy := helpers.ManifestGet(kubectl.BasePath(), "fqdn-proxy-policy.yaml")
			fqdnTarget := "vagrant-cache.ci.cilium.io"

			_, err := kubectl.CiliumPolicyAction(
				namespaceForTest, fqdnProxyPolicy,
				helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).To(BeNil(), "Cannot install fqdn proxy policy")
			defer kubectl.CiliumPolicyAction(namespaceForTest, fqdnProxyPolicy,
				helpers.KubectlDelete, helpers.HelperTimeout)

			res := kubectl.ExecPodCmd(namespaceForTest, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s", fqdnTarget)))
			res.ExpectSuccess("%q cannot curl fqdn target %q", appPods[helpers.App2], fqdnTarget)

			flows := getFlowsFromRelay(fmt.Sprintf(
				"--last 1 --type trace:from-endpoint --from-pod %s/%s --to-fqdn %s",
				namespaceForTest, appPods[helpers.App2], fqdnTarget))
			Expect(flows).To(HaveLen(1))
			Expect(flows[0].GetFlow().Destination.Identity).To(BeNumerically(">=", identity.MinimalNumericIdentity))
		})
	})
})
