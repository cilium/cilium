// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2020 Authors of Cilium

package k8sTest

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/policy"
	. "github.com/cilium/cilium/test/ginkgo-ext"
	"github.com/cilium/cilium/test/helpers"
)

var _ = SkipDescribeIf(func() bool {
	// We only need to run on 4.9 with kube-proxy and net-next with KPR
	// and the third node. Other CI jobs are not expected to increase
	// code coverage.
	//
	// For GKE coverage, see the K8sPolicyTestExtended Describe block below.
	return helpers.RunsOnGKE() || helpers.RunsOn419Kernel() || helpers.RunsOn54Kernel()
}, "K8sPolicyTest", func() {

	var (
		kubectl *helpers.Kubectl

		// these are set in BeforeAll()
		ciliumFilename           string
		demoPath                 string
		l3Policy                 string
		l3PolicyDeny             string
		l3NamedPortPolicy        string
		l3NamedPortPolicyDeny    string
		l7Policy                 string
		l7NamedPortPolicy        string
		l7PolicyKafka            string
		l7PolicyTLS              string
		TLSCaCerts               string
		TLSArtiiCrt              string
		TLSArtiiKey              string
		TLSLyftCrt               string
		TLSLyftKey               string
		TLSCa                    string
		serviceAccountPolicy     string
		serviceAccountPolicyDeny string
		knpDenyIngress           string
		knpDenyEgress            string
		knpDenyIngressEgress     string
		cnpDenyIngress           string
		cnpDenyEgress            string
		knpAllowIngress          string
		knpAllowEgress           string
		cnpMatchExpression       string
		cnpMatchExpressionDeny   string
		connectivityCheckYml     string

		app1Service = "app1-service"
		apps        = []string{helpers.App1, helpers.App2, helpers.App3}
		daemonCfg   map[string]string
	)

	BeforeAll(func() {
		kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)

		demoPath = helpers.ManifestGet(kubectl.BasePath(), "demo-named-port.yaml")
		l3Policy = helpers.ManifestGet(kubectl.BasePath(), "l3-l4-policy.yaml")
		l3PolicyDeny = helpers.ManifestGet(kubectl.BasePath(), "l3-l4-policy-deny.yaml")
		l3NamedPortPolicy = helpers.ManifestGet(kubectl.BasePath(), "l3-l4-policy-named-port.yaml")
		l3NamedPortPolicyDeny = helpers.ManifestGet(kubectl.BasePath(), "l3-l4-policy-named-port-deny.yaml")
		l7Policy = helpers.ManifestGet(kubectl.BasePath(), "l7-policy.yaml")
		l7NamedPortPolicy = helpers.ManifestGet(kubectl.BasePath(), "l7-policy-named-port.yaml")
		l7PolicyKafka = helpers.ManifestGet(kubectl.BasePath(), "l7-policy-kafka.yaml")
		l7PolicyTLS = helpers.ManifestGet(kubectl.BasePath(), "l7-policy-TLS.yaml")
		TLSCaCerts = helpers.ManifestGet(kubectl.BasePath(), "testCA.crt")
		TLSArtiiCrt = helpers.ManifestGet(kubectl.BasePath(), "internal-artii.crt")
		TLSArtiiKey = helpers.ManifestGet(kubectl.BasePath(), "internal-artii.key")
		TLSLyftCrt = helpers.ManifestGet(kubectl.BasePath(), "internal-lyft.crt")
		TLSLyftKey = helpers.ManifestGet(kubectl.BasePath(), "internal-lyft.key")
		TLSCa = helpers.ManifestGet(kubectl.BasePath(), "ca.crt")
		serviceAccountPolicy = helpers.ManifestGet(kubectl.BasePath(), "service-account.yaml")
		serviceAccountPolicyDeny = helpers.ManifestGet(kubectl.BasePath(), "service-account-deny.yaml")
		knpDenyIngress = helpers.ManifestGet(kubectl.BasePath(), "knp-default-deny-ingress.yaml")
		knpDenyEgress = helpers.ManifestGet(kubectl.BasePath(), "knp-default-deny-egress.yaml")
		knpDenyIngressEgress = helpers.ManifestGet(kubectl.BasePath(), "knp-default-deny-ingress-egress.yaml")
		cnpDenyIngress = helpers.ManifestGet(kubectl.BasePath(), "cnp-default-deny-ingress.yaml")
		cnpDenyEgress = helpers.ManifestGet(kubectl.BasePath(), "cnp-default-deny-egress.yaml")
		knpAllowIngress = helpers.ManifestGet(kubectl.BasePath(), "knp-default-allow-ingress.yaml")
		knpAllowEgress = helpers.ManifestGet(kubectl.BasePath(), "knp-default-allow-egress.yaml")
		cnpMatchExpression = helpers.ManifestGet(kubectl.BasePath(), "cnp-matchexpressions.yaml")
		cnpMatchExpressionDeny = helpers.ManifestGet(kubectl.BasePath(), "cnp-matchexpressions-deny.yaml")
		connectivityCheckYml = kubectl.GetFilePath("../examples/kubernetes/connectivity-check/connectivity-check-proxy.yaml")

		daemonCfg = map[string]string{
			"tls.secretsBackend": "k8s",
		}
		ciliumFilename = helpers.TimestampFilename("cilium.yaml")
		DeployCiliumOptionsAndDNS(kubectl, ciliumFilename, daemonCfg)
	})

	AfterFailed(func() {
		kubectl.CiliumReport("cilium service list", "cilium endpoint list")
	})

	AfterAll(func() {
		UninstallCiliumFromManifest(kubectl, ciliumFilename)
		kubectl.CloseSSHClient()
	})

	JustAfterEach(func() {
		kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
	})

	Context("Basic Test", func() {
		var (
			ciliumPod        string
			clusterIP        string
			appPods          map[string]string
			namespaceForTest string
		)

		validateConnectivity := func(expectWorldSuccess, expectClusterSuccess bool) {
			var wg sync.WaitGroup
			for _, appPod := range []string{appPods[helpers.App2], appPods[helpers.App3]} {
				wg.Add(1)
				go func(pod string) {
					defer GinkgoRecover()
					defer wg.Done()
					By("HTTP connectivity to 1.1.1.1")
					res := kubectl.ExecPodCmd(
						namespaceForTest, pod,
						helpers.CurlWithRetries("http://1.1.1.1/", 5, true))

					ExpectWithOffset(1, res).To(getMatcher(expectWorldSuccess),
						"HTTP egress connectivity to 1.1.1.1 from pod %q", pod)
				}(appPod)

				wg.Add(1)
				go func(pod string) {
					defer GinkgoRecover()
					defer wg.Done()
					By("ICMP connectivity to 8.8.8.8")
					res := kubectl.ExecPodCmd(
						namespaceForTest, pod,
						helpers.Ping("8.8.8.8"))

					ExpectWithOffset(1, res).To(getMatcher(expectWorldSuccess),
						"ICMP egress connectivity to 8.8.8.8 from pod %q", pod)
				}(appPod)

				wg.Add(1)
				go func(pod string) {
					defer GinkgoRecover()
					defer wg.Done()
					By("DNS lookup of kubernetes.default.svc.cluster.local")
					// -R3 retry 3 times, -N1 ndots set to 1, -t A only lookup A records
					res := kubectl.ExecPodCmd(
						namespaceForTest, pod,
						"host -v -R3 -N1 -t A kubernetes.default.svc.cluster.local.")

					// kube-dns is always whitelisted so this should always work
					ExpectWithOffset(1, res).To(getMatcher(expectWorldSuccess || expectClusterSuccess),
						"DNS connectivity of kubernetes.default.svc.cluster.local from pod %q", pod)
				}(appPod)

				wg.Add(1)
				go func(pod string) {
					defer GinkgoRecover()
					defer wg.Done()
					By("HTTP connectivity from pod to pod")
					res := kubectl.ExecPodCmd(
						namespaceForTest, pod,
						helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))

					ExpectWithOffset(1, res).To(getMatcher(expectClusterSuccess),
						"HTTP connectivity to clusterIP %q of app1 from pod %q", clusterIP, appPods[helpers.App2])
				}(appPod)
			}
			wg.Wait()
		}

		BeforeAll(func() {
			namespaceForTest = helpers.GenerateNamespaceForTest("")
			kubectl.NamespaceDelete(namespaceForTest)
			kubectl.NamespaceCreate(namespaceForTest).ExpectSuccess("could not create namespace")
			kubectl.Apply(helpers.ApplyOptions{FilePath: demoPath, Namespace: namespaceForTest}).ExpectSuccess("could not create resource")

			err := kubectl.WaitforPods(namespaceForTest, "-l zgroup=testapp", helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Test pods are not ready after timeout")

			ciliumPod, err = kubectl.GetCiliumPodOnNode(helpers.K8s1)
			Expect(err).Should(BeNil(), "cannot get CiliumPod")

			clusterIP, _, err = kubectl.GetServiceHostPort(namespaceForTest, app1Service)
			Expect(err).To(BeNil(), "Cannot get service in %q namespace", namespaceForTest)
			appPods = helpers.GetAppPods(apps, namespaceForTest, kubectl, "id")
			logger.WithFields(logrus.Fields{
				"ciliumPod": ciliumPod,
				"clusterIP": clusterIP}).Info("Initial data")

		})

		AfterAll(func() {
			kubectl.NamespaceDelete(namespaceForTest)
			kubectl.Delete(demoPath)
			ExpectAllPodsTerminated(kubectl)
		})

		BeforeEach(func() {
			kubectl.CiliumExecMustSucceed(context.TODO(),
				ciliumPod, fmt.Sprintf("cilium config %s=%s",
					helpers.PolicyEnforcement, helpers.PolicyEnforcementDefault))

			err := kubectl.CiliumEndpointWaitReady()
			Expect(err).To(BeNil(), "Endpoints are not ready after timeout")

			err = kubectl.WaitforPods(namespaceForTest, "-l zgroup=testapp", helpers.HelperTimeout)
			Expect(err).Should(BeNil())

		})

		AfterEach(func() {
			cmd := fmt.Sprintf("%s delete --all cnp,ccnp,netpol -n %s", helpers.KubectlCmd, namespaceForTest)
			_ = kubectl.Exec(cmd)
		})

		It("checks all kind of Kubernetes policies", func() {

			logger.Infof("PolicyRulesTest: cluster service ip '%s'", clusterIP)

			By("Testing L3/L4 rules")

			_, err := kubectl.CiliumPolicyAction(
				namespaceForTest, l3Policy, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil())

			for _, appName := range []string{helpers.App1, helpers.App2, helpers.App3} {
				err = kubectl.WaitForCEPIdentity(namespaceForTest, appPods[appName])
				Expect(err).Should(BeNil())
			}

			trace := kubectl.CiliumExecMustSucceed(context.TODO(), ciliumPod, fmt.Sprintf(
				"cilium policy trace --src-k8s-pod %s:%s --dst-k8s-pod %s:%s --dport 80/TCP",
				namespaceForTest, appPods[helpers.App2], namespaceForTest, appPods[helpers.App1]))
			trace.ExpectContains("Final verdict: ALLOWED", "Policy trace output mismatch")

			trace = kubectl.CiliumExecMustSucceed(context.TODO(), ciliumPod, fmt.Sprintf(
				"cilium policy trace --src-k8s-pod %s:%s --dst-k8s-pod %s:%s --dport 0/ANY",
				namespaceForTest, appPods[helpers.App3], namespaceForTest, appPods[helpers.App1]))
			trace.ExpectContains("Final verdict: DENIED", "Policy trace output mismatch")

			res := kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectSuccess("%q cannot curl clusterIP %q", appPods[helpers.App2], clusterIP)

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("%q can curl to %q", appPods[helpers.App3], clusterIP)

			By("Testing L3/L4 deny rules")

			_, err = kubectl.CiliumPolicyAction(
				namespaceForTest, l3PolicyDeny, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil())

			trace = kubectl.CiliumExecMustSucceed(context.TODO(), ciliumPod, fmt.Sprintf(
				"cilium policy trace --src-k8s-pod %s:%s --dst-k8s-pod %s:%s --dport 80/TCP",
				namespaceForTest, appPods[helpers.App2], namespaceForTest, appPods[helpers.App1]))
			trace.ExpectContains("Final verdict: DENIED", "Policy trace output mismatch")

			trace = kubectl.CiliumExecMustSucceed(context.TODO(), ciliumPod, fmt.Sprintf(
				"cilium policy trace --src-k8s-pod %s:%s --dst-k8s-pod %s:%s --dport 0/ANY",
				namespaceForTest, appPods[helpers.App3], namespaceForTest, appPods[helpers.App1]))
			trace.ExpectContains("Final verdict: DENIED", "Policy trace output mismatch")

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("%q can curl clusterIP %q", appPods[helpers.App2], clusterIP)

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("%q can curl to %q", appPods[helpers.App3], clusterIP)

			_, err = kubectl.CiliumPolicyAction(
				namespaceForTest, l3Policy,
				helpers.KubectlDelete, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Cannot delete L3 Policy")

			_, err = kubectl.CiliumPolicyAction(
				namespaceForTest, l3PolicyDeny,
				helpers.KubectlDelete, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Cannot delete L3 Policy Deny")

			By("Testing L7 Policy")

			_, err = kubectl.CiliumPolicyAction(
				namespaceForTest, l7Policy, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Cannot install %q policy", l7Policy)

			// Cilium launches Envoy with path normalization enabled by default, so '//public' will be seen as '/public'.
			// Note that 'hhtpd' performs slash merging and serves '/public' when '//public' is requested.
			// Policy enforcement will block this if path normalization is not done prior as policy only allows '/public'.
			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App2],
				helpers.CurlFail("http://%s//public", clusterIP))
			res.ExpectSuccess("Cannot connect from %q to 'http://%s//public'",
				appPods[helpers.App2], clusterIP)

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/private", clusterIP)))
			res.ExpectFail("Unexpected connection from %q to 'http://%s/private'",
				appPods[helpers.App2], clusterIP)

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("Unexpected connection from %q to 'http://%s/public'",
				appPods[helpers.App3], clusterIP)

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App3],
				helpers.CurlFail("http://%s/private", clusterIP))
			res.ExpectFail("Unexpected connection from %q to 'http://%s/private'",
				appPods[helpers.App3], clusterIP)

			By("Testing L7 Policy with L3/L4 deny rules")

			_, err = kubectl.CiliumPolicyAction(
				namespaceForTest, l3PolicyDeny, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil())

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App2],
				helpers.CurlFail("http://%s/public", clusterIP))
			res.ExpectFail("Unexpected connection from %q to 'http://%s/public'",
				appPods[helpers.App2], clusterIP)

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/private", clusterIP)))
			res.ExpectFail("Unexpected connection from %q to 'http://%s/private'",
				appPods[helpers.App2], clusterIP)

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("Unexpected connection from %q to 'http://%s/public'",
				appPods[helpers.App3], clusterIP)

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App3],
				helpers.CurlFail("http://%s/private", clusterIP))
			res.ExpectFail("Unexpected connection from %q to 'http://%s/private'",
				appPods[helpers.App3], clusterIP)
		}, 500)

		It("checks policies with named ports", func() {

			logger.Infof("PolicyRulesTest: cluster service ip '%s'", clusterIP)

			By("Testing L3/L4 rules with named ports")

			_, err := kubectl.CiliumPolicyAction(
				namespaceForTest, l3NamedPortPolicy, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil())

			for _, appName := range []string{helpers.App1, helpers.App2, helpers.App3} {
				err = kubectl.WaitForCEPIdentity(namespaceForTest, appPods[appName])
				Expect(err).Should(BeNil())
			}

			trace := kubectl.CiliumExecMustSucceed(context.TODO(), ciliumPod, fmt.Sprintf(
				"cilium policy trace --src-k8s-pod %s:%s --dst-k8s-pod %s:%s --dport http-80/TCP",
				namespaceForTest, appPods[helpers.App2], namespaceForTest, appPods[helpers.App1]))
			trace.ExpectContains("Final verdict: ALLOWED", "Policy trace output mismatch")

			trace = kubectl.CiliumExecMustSucceed(context.TODO(), ciliumPod, fmt.Sprintf(
				"cilium policy trace --src-k8s-pod %s:%s --dst-k8s-pod %s:%s --dport 0/ANY",
				namespaceForTest, appPods[helpers.App3], namespaceForTest, appPods[helpers.App1]))
			trace.ExpectContains("Final verdict: DENIED", "Policy trace output mismatch")

			res := kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectSuccess("%q cannot curl clusterIP %q", appPods[helpers.App2], clusterIP)

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("%q can curl to %q", appPods[helpers.App3], clusterIP)

			By("Testing L3/L4 deny rules with named ports")

			_, err = kubectl.CiliumPolicyAction(
				namespaceForTest, l3NamedPortPolicyDeny, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil())

			trace = kubectl.CiliumExecMustSucceed(context.TODO(), ciliumPod, fmt.Sprintf(
				"cilium policy trace --src-k8s-pod %s:%s --dst-k8s-pod %s:%s --dport http-80/TCP",
				namespaceForTest, appPods[helpers.App2], namespaceForTest, appPods[helpers.App1]))
			trace.ExpectContains("Final verdict: DENIED", "Policy trace output mismatch")

			trace = kubectl.CiliumExecMustSucceed(context.TODO(), ciliumPod, fmt.Sprintf(
				"cilium policy trace --src-k8s-pod %s:%s --dst-k8s-pod %s:%s --dport 0/ANY",
				namespaceForTest, appPods[helpers.App3], namespaceForTest, appPods[helpers.App1]))
			trace.ExpectContains("Final verdict: DENIED", "Policy trace output mismatch")

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("%q can curl clusterIP %q", appPods[helpers.App2], clusterIP)

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("%q can curl to %q", appPods[helpers.App3], clusterIP)

			_, err = kubectl.CiliumPolicyAction(
				namespaceForTest, l3NamedPortPolicy,
				helpers.KubectlDelete, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Cannot delete L3 Policy")

			_, err = kubectl.CiliumPolicyAction(
				namespaceForTest, l3NamedPortPolicyDeny,
				helpers.KubectlDelete, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Cannot delete L3 Policy Deny")

			By("Testing L7 Policy with named port")

			_, err = kubectl.CiliumPolicyAction(
				namespaceForTest, l7NamedPortPolicy, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Cannot install %q policy", l7NamedPortPolicy)

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App2],
				helpers.CurlFail("http://%s/public", clusterIP))
			res.ExpectSuccess("Cannot connect from %q to 'http://%s/public'",
				appPods[helpers.App2], clusterIP)

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/private", clusterIP)))
			res.ExpectFail("Unexpected connection from %q to 'http://%s/private'",
				appPods[helpers.App2], clusterIP)

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("Unexpected connection from %q to 'http://%s/public'",
				appPods[helpers.App3], clusterIP)

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App3],
				helpers.CurlFail("http://%s/private", clusterIP))
			res.ExpectFail("Unexpected connection from %q to 'http://%s/private'",
				appPods[helpers.App3], clusterIP)

			By("Testing L7 Policy with L3/L4 deny rules with named ports")

			_, err = kubectl.CiliumPolicyAction(
				namespaceForTest, l3NamedPortPolicyDeny, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil())

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App2],
				helpers.CurlFail("http://%s/public", clusterIP))
			res.ExpectFail("Unexpected connection from %q to 'http://%s/public'",
				appPods[helpers.App2], clusterIP)

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/private", clusterIP)))
			res.ExpectFail("Unexpected connection from %q to 'http://%s/private'",
				appPods[helpers.App2], clusterIP)

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("Unexpected connection from %q to 'http://%s/public'",
				appPods[helpers.App3], clusterIP)

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App3],
				helpers.CurlFail("http://%s/private", clusterIP))
			res.ExpectFail("Unexpected connection from %q to 'http://%s/private'",
				appPods[helpers.App3], clusterIP)
		}, 500)

		SkipItIf(helpers.SkipQuarantined, "TLS policy", func() {
			By("Testing L7 Policy with TLS")

			res := kubectl.CreateSecret("generic", "user-agent", "default", "--from-literal=user-agent=CURRL")
			res.ExpectSuccess("Cannot create secret %s", "user-agent")

			res = kubectl.CreateSecret("generic", "test-client", "default", "--from-file="+TLSCa)
			res.ExpectSuccess("Cannot create secret %s", "test-client")

			res = kubectl.CreateSecret("tls", "artii-server", "default", "--cert="+TLSArtiiCrt+" --key="+TLSArtiiKey)
			res.ExpectSuccess("Cannot create secret %s", "artii-server")

			res = kubectl.CreateSecret("tls", "lyft-server", "default", "--cert="+TLSLyftCrt+" --key="+TLSLyftKey)
			res.ExpectSuccess("Cannot create secret %s", "lyft-server")

			res = kubectl.CopyFileToPod(namespaceForTest, appPods[helpers.App2], TLSCaCerts, "/cacert.pem")
			res.ExpectSuccess("Cannot copy certs to %s", appPods[helpers.App2])

			_, err := kubectl.CiliumPolicyAction(
				namespaceForTest, l7PolicyTLS, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Cannot install %q policy", l7PolicyTLS)

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App2],
				helpers.CurlWithRetries("-4 --max-time 15 %s 'https://artii.herokuapp.com/make?text=cilium&font=univers'", 5, true, "-v --cacert /cacert.pem"))
			res.ExpectSuccess("Cannot connect from %q to 'https://artii.herokuapp.com/make?text=cilium&font=univers'",
				appPods[helpers.App2])

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App2],
				helpers.CurlWithRetries("-4 %s 'https://artii.herokuapp.com:443/fonts_list'", 5, true, "-v --cacert /cacert.pem"))
			res.ExpectFailWithError("403 Forbidden", "Unexpected connection from %q to 'https://artii.herokuapp.com:443/fonts_list'",
				appPods[helpers.App2])

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App2],
				helpers.CurlWithRetries("-4 %s https://www.lyft.com:443/privacy", 5, true, "-v --cacert /cacert.pem"))
			res.ExpectSuccess("Cannot connect from %q to 'https://www.lyft.com:443/privacy'",
				appPods[helpers.App2])

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App2],
				helpers.CurlWithRetries("-4 %s https://www.lyft.com:443/private", 5, true, "-v --cacert /cacert.pem"))
			res.ExpectFailWithError("403 Forbidden", "Unexpected connection from %q to 'https://www.lyft.com:443/private'",
				appPods[helpers.App2])
		}, 500)

		It("Invalid Policy report status correctly", func() {
			manifest := helpers.ManifestGet(kubectl.BasePath(), "invalid_cnp.yaml")
			cnpName := "foo"
			kubectl.Apply(helpers.ApplyOptions{FilePath: manifest, Namespace: namespaceForTest}).ExpectSuccess("Cannot apply policy manifest")

			body := func() bool {
				cnp := kubectl.GetCNP(namespaceForTest, cnpName)
				if cnp != nil && len(cnp.Status.Nodes) > 0 {
					for _, node := range cnp.Status.Nodes {
						if node.Error == "" {
							return false
						}
					}
					return true
				}
				return false
			}

			err := helpers.WithTimeout(
				body,
				fmt.Sprintf("CNP %q does not report the status correctly after timeout", cnpName),
				&helpers.TimeoutConfig{Timeout: 100 * time.Second})

			Expect(err).To(BeNil(), "CNP status for invalid policy did not update correctly")
		})

		It("ServiceAccount Based Enforcement", func() {
			// Load policy allowing serviceAccount of app2 to talk
			// to app1 on port 80 TCP
			_, err := kubectl.CiliumPolicyAction(
				namespaceForTest, serviceAccountPolicy, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil())

			for _, appName := range []string{helpers.App1, helpers.App2, helpers.App3} {
				err = kubectl.WaitForCEPIdentity(namespaceForTest, appPods[appName])
				Expect(err).Should(BeNil())
			}

			trace := kubectl.CiliumExecMustSucceed(context.TODO(), ciliumPod, fmt.Sprintf(
				"cilium policy trace --src-k8s-pod %s:%s --dst-k8s-pod %s:%s --dport 80/TCP",
				namespaceForTest, appPods[helpers.App2], namespaceForTest, appPods[helpers.App1]))
			trace.ExpectContains("Final verdict: ALLOWED", "Policy trace output mismatch")

			trace = kubectl.CiliumExecMustSucceed(context.TODO(), ciliumPod, fmt.Sprintf(
				"cilium policy trace --src-k8s-pod %s:%s --dst-k8s-pod %s:%s --dport 0/ANY",
				namespaceForTest, appPods[helpers.App3], namespaceForTest, appPods[helpers.App1]))
			trace.ExpectContains("Final verdict: DENIED", "Policy trace output mismatch")

			res := kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectSuccess("%q cannot curl clusterIP %q", appPods[helpers.App2], clusterIP)

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("%q can curl to %q", appPods[helpers.App3], clusterIP)

			By("Testing ServiceAccount Based Enforcement with Policy Denies")

			// Load policy denying serviceAccount of app2 to talk
			// to app1 on port 80 TCP
			_, err = kubectl.CiliumPolicyAction(
				namespaceForTest, serviceAccountPolicyDeny, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil())

			for _, appName := range []string{helpers.App1, helpers.App2, helpers.App3} {
				err = kubectl.WaitForCEPIdentity(namespaceForTest, appPods[appName])
				Expect(err).Should(BeNil())
			}

			trace = kubectl.CiliumExecMustSucceed(context.TODO(), ciliumPod, fmt.Sprintf(
				"cilium policy trace --src-k8s-pod %s:%s --dst-k8s-pod %s:%s --dport 80/TCP",
				namespaceForTest, appPods[helpers.App2], namespaceForTest, appPods[helpers.App1]))
			trace.ExpectContains("Final verdict: DENIED", "Policy trace output mismatch")

			trace = kubectl.CiliumExecMustSucceed(context.TODO(), ciliumPod, fmt.Sprintf(
				"cilium policy trace --src-k8s-pod %s:%s --dst-k8s-pod %s:%s --dport 0/ANY",
				namespaceForTest, appPods[helpers.App3], namespaceForTest, appPods[helpers.App1]))
			trace.ExpectContains("Final verdict: DENIED", "Policy trace output mismatch")

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("%q can curl clusterIP %q", appPods[helpers.App2], clusterIP)

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("%q can curl to %q", appPods[helpers.App3], clusterIP)

		}, 500)

		It("CNP test MatchExpressions key", func() {
			_, err := kubectl.CiliumPolicyAction(
				namespaceForTest, cnpMatchExpression, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "cannot install policy %s", cnpMatchExpression)

			res := kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectSuccess("%q cannot curl clusterIP %q", appPods[helpers.App2], clusterIP)

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("%q can curl to %q", appPods[helpers.App3], clusterIP)

			By("Testing CNP test MatchExpressions key with policy Denies")

			_, err = kubectl.CiliumPolicyAction(
				namespaceForTest, cnpMatchExpressionDeny, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "cannot install policy %s", cnpMatchExpression)

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("%q can curl clusterIP %q", appPods[helpers.App2], clusterIP)

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("%q can curl to %q", appPods[helpers.App3], clusterIP)

		})

		It("Denies traffic with k8s default-deny ingress policy", func() {

			res := kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectSuccess("%q cannot curl clusterIP %q", appPods[helpers.App2], clusterIP)

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectSuccess("%q cannot curl to %q", appPods[helpers.App3], clusterIP)

			By("Installing knp ingress default-deny")

			// Import the policy and wait for all required endpoints to enforce the policy
			_, err := kubectl.CiliumPolicyAction(
				namespaceForTest, knpDenyIngress, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(),
				"L3 deny-ingress Policy cannot be applied in %q namespace", namespaceForTest)

			By("Testing connectivity with ingress default-deny policy loaded")

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("Ingress connectivity should be denied by policy")

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("Ingress connectivity should be denied by policy")
		})

		It("Denies traffic with k8s default-deny egress policy", func() {
			By("Installing knp egress default-deny")

			_, err := kubectl.CiliumPolicyAction(
				namespaceForTest, knpDenyEgress, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(),
				"L3 deny-egress Policy cannot be applied in %q namespace", namespaceForTest)

			By("Testing if egress policy enforcement is enabled on the endpoint")
			for _, pod := range []string{appPods[helpers.App2], appPods[helpers.App3]} {
				res := kubectl.ExecPodCmd(
					namespaceForTest, pod,
					helpers.CurlFail("http://1.1.1.1/"))
				res.ExpectFail("Egress connectivity should be denied for pod %q", pod)

				res = kubectl.ExecPodCmd(
					namespaceForTest, pod,
					helpers.Ping("8.8.8.8"))
				res.ExpectFail("Egress ping connectivity should be denied for pod %q", pod)

				res = kubectl.ExecPodCmd(
					namespaceForTest, pod,
					"host kubernetes.default.svc.cluster.local")
				res.ExpectFail("Egress DNS connectivity should be denied for pod %q", pod)
			}
		})

		It("Denies traffic with k8s default-deny ingress-egress policy", func() {
			By("Installing knp ingress-egress default-deny")

			_, err := kubectl.CiliumPolicyAction(
				namespaceForTest, knpDenyIngressEgress, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(),
				"L3 deny-ingress-egress policy cannot be applied in %q namespace", namespaceForTest)

			By("Testing if egress and ingress policy enforcement is enabled on the endpoint")
			for _, pod := range []string{appPods[helpers.App2], appPods[helpers.App3]} {
				res := kubectl.ExecPodCmd(
					namespaceForTest, pod,
					helpers.CurlFail("http://1.1.1.1/"))
				res.ExpectFail("Egress connectivity should be denied for pod %q", pod)

				res = kubectl.ExecPodCmd(
					namespaceForTest, pod,
					helpers.Ping("8.8.8.8"))
				res.ExpectFail("Egress ping connectivity should be denied for pod %q", pod)

				res = kubectl.ExecPodCmd(
					namespaceForTest, pod,
					"host kubernetes.default.svc.cluster.local")
				res.ExpectFail("Egress DNS connectivity should be denied for pod %q", pod)
			}

			By("Testing ingress connectivity with default-deny policy loaded")
			res := kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("Ingress connectivity should be denied by policy")

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("Ingress connectivity should be denied by policy")
		})

		It("Denies traffic with cnp default-deny ingress policy", func() {

			By("Installing cnp ingress default-deny")

			_, err := kubectl.CiliumPolicyAction(
				namespaceForTest, cnpDenyIngress, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(),
				"L3 deny-ingress Policy cannot be applied in %q namespace", namespaceForTest)

			By("Testing connectivity with ingress default-deny policy loaded")

			res := kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("Ingress connectivity should be denied by policy")

			By("Testing egress connnectivity works correctly")
			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App2],
				helpers.PingWithCount("8.8.8.8", 25))
			res.ExpectSuccess("Egress ping connectivity should work")
		})

		It("Denies traffic with cnp default-deny egress policy", func() {

			By("Installing cnp egress default-deny")
			_, err := kubectl.CiliumPolicyAction(
				namespaceForTest, cnpDenyEgress, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(),
				"L3 deny-egress Policy cannot be applied in %q namespace", namespaceForTest)

			for _, pod := range apps {
				res := kubectl.ExecPodCmd(
					namespaceForTest, pod,
					helpers.CurlFail("http://1.1.1.1/"))
				res.ExpectFail("Egress connectivity should be denied for pod %q", pod)

				res = kubectl.ExecPodCmd(
					namespaceForTest, pod,
					helpers.Ping("8.8.8.8"))
				res.ExpectFail("Egress ping connectivity should be denied for pod %q", pod)

				res = kubectl.ExecPodCmd(
					namespaceForTest, pod,
					"host kubernetes.default.svc.cluster.local")
				res.ExpectFail("Egress DNS connectivity should be denied for pod %q", pod)
			}
		})

		It("Allows traffic with k8s default-allow ingress policy", func() {
			By("Installing ingress default-allow")
			_, err := kubectl.CiliumPolicyAction(
				namespaceForTest, knpAllowIngress, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(),
				"L3 allow-ingress Policy cannot be applied in %q namespace", namespaceForTest)

			By("Testing connectivity with ingress default-allow policy loaded")
			res := kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App2],
				helpers.CurlFail("http://%s/public", clusterIP))
			res.ExpectSuccess("Ingress connectivity should be allowed by policy")

			res = kubectl.ExecPodCmd(
				namespaceForTest, appPods[helpers.App3],
				helpers.CurlFail("http://%s/public", clusterIP))
			res.ExpectSuccess("Ingress connectivity should be allowed by policy")
		})

		It("Allows traffic with k8s default-allow egress policy", func() {
			By("Installing egress default-allow")
			_, err := kubectl.CiliumPolicyAction(
				namespaceForTest, knpAllowEgress, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(),
				"L3 allow-egress Policy cannot be applied in %q namespace", namespaceForTest)

			By("Checking connectivity between pods and external services after installing egress policy")

			for _, pod := range []string{appPods[helpers.App2], appPods[helpers.App3]} {
				res := kubectl.ExecPodCmd(
					namespaceForTest, pod,
					helpers.CurlWithRetries("http://1.1.1.1/", 5, true))
				res.ExpectSuccess("Egress connectivity should be allowed for pod %q", pod)

				res = kubectl.ExecPodCmd(
					namespaceForTest, pod,
					helpers.Ping("8.8.8.8"))
				res.ExpectSuccess("Egress ping connectivity should be allowed for pod %q", pod)

				// -R3 retry 3 times, -N1 ndots set to 1, -t A only lookup A records
				res = kubectl.ExecPodCmd(
					namespaceForTest, pod,
					"host -v -R3 -N1 -t A kubernetes.default.svc.cluster.local.")
				res.ExpectSuccess("Egress DNS connectivity should be allowed for pod %q", pod)
			}
		})

		Context("Validate to-entities policies", func() {
			const (
				WorldConnectivityDeny  = false
				WorldConnectivityAllow = true

				ClusterConnectivityDeny  = false
				ClusterConnectivityAllow = true
			)

			var (
				cnpToEntitiesAll      string
				ccnpToEntitiesAllDeny string
				cnpToEntitiesWorld    string
				cnpToEntitiesCluster  string
				cnpToEntitiesHost     string
			)

			BeforeAll(func() {
				cnpToEntitiesAll = helpers.ManifestGet(kubectl.BasePath(), "cnp-to-entities-all.yaml")
				ccnpToEntitiesAllDeny = helpers.ManifestGet(kubectl.BasePath(), "ccnp-to-entities-all-deny.yaml")
				cnpToEntitiesWorld = helpers.ManifestGet(kubectl.BasePath(), "cnp-to-entities-world.yaml")
				cnpToEntitiesCluster = helpers.ManifestGet(kubectl.BasePath(), "cnp-to-entities-cluster.yaml")
				cnpToEntitiesHost = helpers.ManifestGet(kubectl.BasePath(), "cnp-to-entities-host.yaml")
			})

			It("Validate toEntities All", func() {
				By("Installing toEntities All")
				importPolicy(kubectl, namespaceForTest, cnpToEntitiesAll, "to-entities-all")

				By("Verifying policy correctness")
				validateConnectivity(WorldConnectivityAllow, ClusterConnectivityAllow)

				By("Installing deny toEntities All")
				importPolicy(kubectl, namespaceForTest, ccnpToEntitiesAllDeny, "to-entities-all-deny")

				By("Verifying policy correctness")
				validateConnectivity(WorldConnectivityDeny, ClusterConnectivityDeny)
			})

			It("Validate toEntities World", func() {
				By("Installing toEntities World")
				importPolicy(kubectl, namespaceForTest, cnpToEntitiesWorld, "to-entities-world")

				By("Verifying policy correctness")
				validateConnectivity(WorldConnectivityAllow, ClusterConnectivityDeny)

			})

			It("Validate toEntities Cluster", func() {
				By("Installing toEntities Cluster")
				importPolicy(kubectl, namespaceForTest, cnpToEntitiesCluster, "to-entities-cluster")

				By("Verifying policy correctness")
				validateConnectivity(WorldConnectivityDeny, ClusterConnectivityAllow)
			})

			It("Validate toEntities Host", func() {
				By("Installing toEntities Host")
				importPolicy(kubectl, namespaceForTest, cnpToEntitiesHost, "to-entities-host")

				By("Verifying policy correctness")
				validateConnectivity(WorldConnectivityDeny, ClusterConnectivityDeny)
			})
		})

		Context("Validate CNP update", func() {
			const (
				allowAll = iota
				denyFromApp3
				denyAll
			)

			var (
				cnpUpdateAllow        string
				cnpUpdateDeny         string
				cnpUpdateDenyAll      string
				cnpUpdateNoSpecs      string
				cnpUpdateDenyLabelled string
			)

			BeforeAll(func() {
				cnpUpdateAllow = helpers.ManifestGet(kubectl.BasePath(), "cnp-update-allow-all.yaml")
				cnpUpdateDenyAll = helpers.ManifestGet(kubectl.BasePath(), "cnp-update-deny-all.yaml")
				cnpUpdateDeny = helpers.ManifestGet(kubectl.BasePath(), "cnp-update-deny-ingress.yaml")
				cnpUpdateNoSpecs = helpers.ManifestGet(kubectl.BasePath(), "cnp-update-no-specs.yaml")
				cnpUpdateDenyLabelled = helpers.ManifestGet(kubectl.BasePath(), "cnp-update-deny-ingress-labelled.yaml")
			})

			validateL3L4 := func(allow int) {
				var allowApp2, allowApp3 bool
				switch allow {
				case allowAll:
					allowApp2 = true
					allowApp3 = true
				case denyFromApp3:
					allowApp2 = true
				case denyAll:
				}

				res := kubectl.ExecPodCmd(
					namespaceForTest, appPods[helpers.App2],
					helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
				ExpectWithOffset(1, res).To(getMatcher(allowApp2),
					"%q curl clusterIP %q (expected to allow: %t)",
					appPods[helpers.App2], clusterIP, allowApp2)

				res = kubectl.ExecPodCmd(
					namespaceForTest, appPods[helpers.App3],
					helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
				ExpectWithOffset(1, res).To(getMatcher(allowApp3),
					"%q curl clusterIP %q (expected to allow: %t)",
					appPods[helpers.App3], clusterIP, allowApp3)
			}

			It("Enforces connectivity correctly when the same L3/L4 CNP is updated", func() {
				By("Applying default allow policy")
				_, err := kubectl.CiliumPolicyAction(
					namespaceForTest, cnpUpdateAllow, helpers.KubectlApply, helpers.HelperTimeout)
				Expect(err).Should(BeNil(), "%q Policy cannot be applied", cnpUpdateAllow)

				validateL3L4(allowAll)

				By("Applying l3-l4 policy")
				_, err = kubectl.CiliumPolicyAction(
					namespaceForTest, cnpUpdateDeny, helpers.KubectlApply, helpers.HelperTimeout)
				Expect(err).Should(BeNil(), "%q Policy cannot be applied", cnpUpdateDeny)

				validateL3L4(denyFromApp3)

				By("Applying no-specs policy")
				// We are intentionally not using helpers.CiliumPolicyAction
				// because we don't expect this policy to be applied; it will
				// be accepted by K8s apiserver, but it will be rejected by
				// Cilium agent, and therefore no revision bump.
				Expect(kubectl.Apply(helpers.ApplyOptions{
					Namespace: namespaceForTest,
					FilePath:  cnpUpdateNoSpecs,
				})).Should(helpers.CMDSuccess(), "%q Policy cannot be applied", cnpUpdateNoSpecs)
				validateL3L4(denyFromApp3)

				By("Applying l3-l4 policy with user-specified labels")
				_, err = kubectl.CiliumPolicyAction(
					namespaceForTest, cnpUpdateDenyLabelled, helpers.KubectlApply, helpers.HelperTimeout)
				Expect(err).Should(BeNil(), "%q Policy cannot be applied", cnpUpdateDenyLabelled)

				validateL3L4(denyFromApp3)

				By("Applying default allow policy (should remove policy with user labels)")
				_, err = kubectl.CiliumPolicyAction(
					namespaceForTest, cnpUpdateAllow, helpers.KubectlApply, helpers.HelperTimeout)
				Expect(err).Should(BeNil(), "%q Policy cannot be applied", cnpUpdateAllow)

				validateL3L4(allowAll)

				By("Applying a full deny policy on all endpoints")
				_, err = kubectl.CiliumPolicyAction(
					namespaceForTest, cnpUpdateDenyAll, helpers.KubectlApply, helpers.HelperTimeout)
				Expect(err).Should(BeNil(), "%q Policy cannot be applied", cnpUpdateDenyAll)

				validateL3L4(denyAll)
			})

			// Tests involving the L7 proxy do not work when built with -race, see issue #13757.
			SkipItIf(helpers.SkipRaceDetectorEnabled, "Verifies that a CNP with L7 HTTP rules can be replaced with L7 Kafka rules", func() {
				By("Installing L7 Policy")

				// This HTTP policy was already validated in the
				// test "checks all kind of Kubernetes policies".
				// Install it then move on.
				_, err := kubectl.CiliumPolicyAction(
					namespaceForTest, l7Policy, helpers.KubectlApply, helpers.HelperTimeout)
				Expect(err).Should(BeNil(), "Cannot install %q policy", l7Policy)

				// Update existing policy on port 80 from http to kafka
				// to test ability to change L7 parser type of a port.
				// Traffic cannot flow but policy must be able to be
				// imported and applied to the endpoints.
				_, err = kubectl.CiliumPolicyAction(
					namespaceForTest, l7PolicyKafka, helpers.KubectlApply, helpers.HelperTimeout)
				Expect(err).Should(BeNil(), "Cannot update L7 policy (%q) from parser http to kafka", l7PolicyKafka)

				res := kubectl.ExecPodCmd(
					namespaceForTest, appPods[helpers.App3],
					helpers.CurlFail("http://%s/public", clusterIP))
				res.ExpectFail("Unexpected connection from %q to 'http://%s/public'",
					appPods[helpers.App3], clusterIP)

				res = kubectl.ExecPodCmd(
					namespaceForTest, appPods[helpers.App2],
					helpers.CurlFail("http://%s/public", clusterIP))
				res.ExpectFail("Unexpected connection from %q to 'http://%s/public'",
					appPods[helpers.App2], clusterIP)
			})
		})

		// Tests involving the L7 proxy do not work when built with -race, see issue #13757.
		SkipContextIf(helpers.SkipRaceDetectorEnabled, "Traffic redirections to proxy", func() {
			var (
				// track which app1 pod we care about, and its corresponding
				// cilium pod.
				app1Pod     string
				app2Pod     string
				ciliumPod   string
				nodeName    string
				appPods     map[string]string
				app1PodIP   string
				worldTarget = "http://vagrant-cache.ci.cilium.io"
			)

			BeforeAll(func() {
				appPods = helpers.GetAppPods(apps, namespaceForTest, kubectl, "id")
				podsNodes, err := kubectl.GetPodsNodes(namespaceForTest, "id=app1")
				Expect(err).To(BeNil(), "error getting pod->node mapping")
				Expect(len(podsNodes)).To(Equal(2))
				// Just grab the first one.
				for k, v := range podsNodes {
					app1Pod = k
					nodeName = v
					break
				}

				podsNodes, err = kubectl.GetPodsNodes(namespaceForTest, "id=app2")
				Expect(err).To(BeNil(), "error getting pod->node mapping")
				Expect(len(podsNodes)).To(Equal(1))
				for k := range podsNodes {
					app2Pod = k
					break
				}

				Expect(kubectl.WaitforPods(namespaceForTest, "-l zgroup=testapp", helpers.HelperTimeout)).To(BeNil())
				var podList v1.PodList
				err = kubectl.GetPods(namespaceForTest, fmt.Sprintf("-n %s -l k8s-app=cilium --field-selector spec.nodeName=%s", helpers.CiliumNamespace, nodeName)).Unmarshal(&podList)
				Expect(err).To(BeNil())

				var app1PodModel v1.Pod
				Expect(kubectl.Exec(fmt.Sprintf("%s get pod -n %s %s -o json", helpers.KubectlCmd, namespaceForTest, app1Pod)).Unmarshal(&app1PodModel)).To(BeNil())
				Expect(app1PodModel).ToNot(BeNil())
				Expect(len(podList.Items)).To(Equal(1))
				ciliumPod = podList.Items[0].Name
				app1PodIP = app1PodModel.Status.PodIP
				//var app1Ep *models.Endpoint
				var endpoints []*models.Endpoint
				err = kubectl.ExecPodCmd(helpers.CiliumNamespace, ciliumPod, "cilium endpoint list -o json").Unmarshal(&endpoints)
				Expect(err).To(BeNil())
				for _, ep := range endpoints {
					if ep.Status.Networking.Addressing[0].IPV4 == app1PodIP {
						break
					}
				}
			})

			AfterEach(func() {
				// Remove the proxy visibility annotation - this is done by specifying the annotation followed by a '-'.
				kubectl.Exec(fmt.Sprintf("%s annotate pod %s -n %s %s-", helpers.KubectlCmd, appPods[helpers.App1], namespaceForTest, annotation.ProxyVisibility))
				kubectl.Exec(fmt.Sprintf("%s annotate pod %s -n %s %s-", helpers.KubectlCmd, appPods[helpers.App2], namespaceForTest, annotation.ProxyVisibility))
				cmd := fmt.Sprintf("%s delete --all cnp,ccnp,netpol -n %s", helpers.KubectlCmd, namespaceForTest)
				_ = kubectl.Exec(cmd)
			})

			checkProxyRedirection := func(resource string, redirected bool, parser policy.L7ParserType, retryCurl bool) {
				var (
					not           = " "
					filter        string // jsonpath filter
					expect        string // expected result
					curlCmd       string
					hubbleTimeout = 10 * time.Second
				)

				if !redirected {
					not = " not "
				}

				switch parser {
				case policy.ParserTypeDNS:
					// response DNS L7 flow
					filter = "{.destination.namespace} {.l7.type} {.l7.dns.query}"
					expect = fmt.Sprintf(
						"%s RESPONSE %s",
						namespaceForTest,
						"vagrant-cache.ci.cilium.io.",
					)
					if retryCurl {
						curlCmd = helpers.CurlWithRetries(resource, 5, true)
					} else {
						curlCmd = helpers.CurlFail(resource)
					}
				case policy.ParserTypeHTTP:
					filter = "{.destination.namespace} {.l7.type} {.l7.http.url} {.l7.http.code} {.l7.http.method}"
					expect = fmt.Sprintf(
						"%s RESPONSE %s 200 GET",
						namespaceForTest,
						fmt.Sprintf("http://%s/public", resource),
					)

					if retryCurl {
						curlCmd = helpers.CurlWithRetries(fmt.Sprintf("http://%s/public", resource), 5, true)
					} else {
						curlCmd = helpers.CurlFail(fmt.Sprintf("http://%s/public", resource))
					}
				default:
					Fail(fmt.Sprintf("invalid parser type for proxy visibility: %s", parser))
				}

				observeFile := fmt.Sprintf("hubble-observe-%s", uuid.New().String())

				// curl commands are issued from the first k8s worker where all
				// the app instances are running
				By("Starting hubble observe and generating traffic which should%s redirect to proxy", not)
				ctx, cancel := context.WithCancel(context.Background())
				hubbleRes := kubectl.HubbleObserveFollow(
					ctx, ciliumPod,
					// since 0s is important here so no historic events from the
					// buffer are shown, only follow from the current time
					"--type l7 --since 0s",
				)

				// clean up at the end of the test
				defer func() {
					cancel()
					hubbleRes.WaitUntilFinish()
					helpers.WriteToReportFile(hubbleRes.CombineOutput().Bytes(), observeFile)
				}()

				// Let the monitor get started since it is started in the background.
				time.Sleep(2 * time.Second)
				res := kubectl.ExecPodCmd(
					namespaceForTest, appPods[helpers.App2],
					curlCmd)
				// Give time for the monitor to be notified of the proxy flow.
				time.Sleep(2 * time.Second)
				res.ExpectSuccess("%q cannot curl %q", appPods[helpers.App2], resource)

				By("Checking that aforementioned traffic was%sredirected to the proxy", not)
				err := hubbleRes.WaitUntilMatchFilterLineTimeout(filter, expect, hubbleTimeout)
				if redirected {
					ExpectWithOffset(1, err).To(BeNil(), "traffic was not redirected to the proxy when it should have been")
				} else {
					ExpectWithOffset(1, err).ToNot(BeNil(), "traffic was redirected to the proxy when it should have not been redirected")
				}

				if parser == policy.ParserTypeDNS && redirected {
					By("Checking that Hubble is correctly annotating the DNS names")
					res := kubectl.HubbleObserve(ciliumPod,
						fmt.Sprintf("--last 1 --from-pod %s/%s --to-fqdn %q",
							namespaceForTest, appPods[helpers.App2], "*.cilium.io"))
					res.ExpectContainsFilterLine("{.destination_names[0]}", "vagrant-cache.ci.cilium.io")
				}
			}

			proxyVisibilityTest := func(resource, podToAnnotate, anno string, parserType policy.L7ParserType, retryCurl bool) {
				checkProxyRedirection(resource, false, parserType, retryCurl)

				By("Annotating %s with %s", podToAnnotate, anno)
				res := kubectl.Exec(fmt.Sprintf("%s annotate pod %s -n %s %s=\"%s\"", helpers.KubectlCmd, podToAnnotate, namespaceForTest, annotation.ProxyVisibility, anno))
				res.ExpectSuccess("annotating pod with proxy visibility annotation failed")
				Expect(kubectl.CiliumEndpointWaitReady()).To(BeNil())

				checkProxyRedirection(resource, true, parserType, retryCurl)

				By("Removing proxy visibility annotation on %s", podToAnnotate)
				kubectl.Exec(fmt.Sprintf("%s annotate pod %s -n %s %s-", helpers.KubectlCmd, podToAnnotate, namespaceForTest, annotation.ProxyVisibility)).ExpectSuccess()
				Expect(kubectl.CiliumEndpointWaitReady()).To(BeNil())

				checkProxyRedirection(resource, false, parserType, retryCurl)
			}

			It("Tests HTTP proxy visibility without policy", func() {
				proxyVisibilityTest(app1PodIP, app1Pod, "<Ingress/80/TCP/HTTP>", policy.ParserTypeHTTP, false)
			})

			It("Tests DNS proxy visibility without policy", func() {
				proxyVisibilityTest(worldTarget, app2Pod, "<Egress/53/UDP/DNS>", policy.ParserTypeDNS, true)
			})

			It("Tests proxy visibility interactions with policy lifecycle operations", func() {
				checkProxyRedirection(app1PodIP, false, policy.ParserTypeHTTP, false)

				By("Annotating %s with <Ingress/80/TCP/HTTP>", app1Pod)
				res := kubectl.Exec(fmt.Sprintf("%s annotate pod %s -n %s %s=\"<Ingress/80/TCP/HTTP>\"", helpers.KubectlCmd, app1Pod, namespaceForTest, annotation.ProxyVisibility))
				res.ExpectSuccess("annotating pod with proxy visibility annotation failed")
				Expect(kubectl.CiliumEndpointWaitReady()).To(BeNil())

				checkProxyRedirection(app1PodIP, true, policy.ParserTypeHTTP, false)

				By("Importing policy which selects app1")

				_, err := kubectl.CiliumPolicyAction(
					namespaceForTest, l3Policy, helpers.KubectlApply, helpers.HelperTimeout)
				Expect(err).Should(BeNil(),
					"policy %s cannot be applied in %q namespace", l3Policy, namespaceForTest)

				By("Checking that proxy visibility annotation is still applied even while a policy was imported")
				checkProxyRedirection(app1PodIP, true, policy.ParserTypeHTTP, false)

				_, err = kubectl.CiliumPolicyAction(
					namespaceForTest, l3Policy, helpers.KubectlDelete, helpers.HelperTimeout)
				Expect(err).Should(BeNil(),
					"policy %s cannot be deleted in %q namespace", l3Policy, namespaceForTest)

				By("Checking that proxy visibility annotation is still applied after policy is removed")
				checkProxyRedirection(app1PodIP, true, policy.ParserTypeHTTP, false)

				By("Importing policy using named ports which selects app1; proxy-visibility annotation should remain")

				_, err = kubectl.CiliumPolicyAction(
					namespaceForTest, l3NamedPortPolicy, helpers.KubectlApply, helpers.HelperTimeout)
				Expect(err).Should(BeNil(),
					"policy %s cannot be applied in %q namespace", l3NamedPortPolicy, namespaceForTest)

				By("Checking that proxy visibility annotation is still applied to policy being added")
				checkProxyRedirection(app1PodIP, true, policy.ParserTypeHTTP, false)

				_, err = kubectl.CiliumPolicyAction(
					namespaceForTest, l3NamedPortPolicy, helpers.KubectlDelete, helpers.HelperTimeout)
				Expect(err).Should(BeNil(),
					"policy %s cannot be deleted in %q namespace", l3NamedPortPolicy, namespaceForTest)

				By("Checking that proxy visibility annotation is still applied after policy is removed")
				checkProxyRedirection(app1PodIP, true, policy.ParserTypeHTTP, false)
			})
		})
	})

	Context("Multi-node policy test", func() {
		const (
			testDS = "zgroup=testDS"

			// This currently matches GetPodOnNodeWithOffset().
			testNamespace = helpers.DefaultNamespace
		)
		var demoYAML string

		BeforeAll(func() {
			By("Deploying demo daemonset")
			demoYAML = helpers.ManifestGet(kubectl.BasePath(), "demo_ds.yaml")
			res := kubectl.ApplyDefault(demoYAML)
			res.ExpectSuccess("Unable to apply %s", demoYAML)

			err := kubectl.WaitforPods(testNamespace, fmt.Sprintf("-l %s", testDS), helpers.HelperTimeout)
			Expect(err).Should(BeNil())
		})

		AfterAll(func() {
			// Explicitly ignore result of deletion of resources to
			// avoid incomplete teardown if any step fails.
			_ = kubectl.Delete(demoYAML)
			ExpectAllPodsTerminated(kubectl)
		})

		AfterEach(func() {
			By("Cleaning up after the test")
			cmd := fmt.Sprintf("%s delete --all cnp,ccnp,netpol -n %s", helpers.KubectlCmd, testNamespace)
			_ = kubectl.Exec(cmd)
		})

		SkipContextIf(helpers.DoesNotExistNodeWithoutCilium, "validates ingress CIDR-dependent L4", func() {
			var (
				outsideNodeName, outsideIP string // k8s3 node (doesn't have agent running)

				backendPod   v1.Pod // The pod that k8s3 node is hitting
				backendPodIP string

				hostNodeName       string // Node that backendPod ends up on
				hostIPOfBackendPod string

				policyVerdictAllowRegex, policyVerdictDenyRegex *regexp.Regexp
			)

			BeforeAll(func() {
				RedeployCiliumWithMerge(kubectl, ciliumFilename, daemonCfg,
					map[string]string{
						"tunnel":               "disabled",
						"autoDirectNodeRoutes": "true",

						"hostFirewall.enabled": "true",
					})

				By("Retrieving backend pod and outside node IP addresses")
				outsideNodeName, outsideIP = kubectl.GetNodeInfo(helpers.GetFirstNodeWithoutCilium())

				var demoPods v1.PodList
				kubectl.GetPods(testNamespace, fmt.Sprintf("-l %s", testDS)).Unmarshal(&demoPods)
				Expect(demoPods.Items).To(HaveLen(2))

				backendPod = demoPods.Items[0] // We'll take the first one; doesn't matter
				backendPodIP = backendPod.Status.PodIP
				hostIPOfBackendPod = backendPod.Status.HostIP
				hostNodeName = backendPod.Spec.NodeName // Save the name of node backend pod is on

				By("Adding a static route to %s on the %s node (outside)",
					backendPodIP, outsideNodeName)
				// Add the route on the outside node to the backend pod IP
				// directly. The reason for this is to avoid NATing when using
				// K8s Services, for the sake of simplicity. Making the backend
				// pod IP directly routable on the "outside" node is sufficient
				// to validate the policy under test.
				res := kubectl.AddIPRoute(outsideNodeName, backendPodIP, hostIPOfBackendPod, true)
				Expect(res).To(getMatcher(true))

				policyVerdictAllowRegex = regexp.MustCompile(
					fmt.Sprintf("Policy verdict log: .+action allow.+%s:[0-9]+ -> %s:80 tcp SYN",
						outsideIP, backendPodIP))
				policyVerdictDenyRegex = regexp.MustCompile(
					fmt.Sprintf("Policy verdict log: .+action deny.+%s:[0-9]+ -> %s:80 tcp SYN",
						outsideIP, backendPodIP))
			})

			AfterAll(func() {
				// Remove the route on the outside node.
				kubectl.DelIPRoute(outsideNodeName, backendPodIP, hostIPOfBackendPod)

				// Revert Cilium installation back to before this Context.
				By("Redeploying Cilium with default configuration")
				RedeployCilium(kubectl, ciliumFilename, daemonCfg)
			})

			testConnectivity := func(dstIP string, expectSuccess bool) int {
				action := "allowed"
				if !expectSuccess {
					action = "denied"
				}
				By("Testing that connectivity from outside node is %s", action)

				var count int
				ConsistentlyWithOffset(1, func() bool {
					res := kubectl.ExecInHostNetNS(
						context.TODO(),
						outsideNodeName,
						helpers.CurlFail("http://%s:%d", dstIP, 80),
					)
					// We want to count the number of attempts that achieved
					// their expected result, so we can assert on how many
					// policy verdict logs we should expect from `cilium
					// monitor`.
					if res.WasSuccessful() == expectSuccess {
						count++
					}
					return res.WasSuccessful()
				}, helpers.ShortCommandTimeout).Should(Equal(expectSuccess),
					"Connectivity was expected to be %s consistently", action)

				return count
			}

			It("connectivity works from the outside before any policies", func() {
				// Ignore the return because we don't care about `cilium
				// monitor` output in this test.
				_ = testConnectivity(backendPodIP, true)
			})

			It("connectivity is blocked after denying ingress", func() {
				By("Running cilium monitor in the background")
				ciliumPod, err := kubectl.GetCiliumPodOnNode(hostNodeName)
				Expect(ciliumPod).ToNot(BeEmpty())
				Expect(err).ToNot(HaveOccurred())

				ep, err := kubectl.GetCiliumEndpoint(testNamespace, backendPod.GetName())
				Expect(ep).ToNot(BeNil())
				Expect(err).ToNot(HaveOccurred())

				monitor, monitorCancel := kubectl.MonitorEndpointStart(ciliumPod, ep.ID)

				By("Importing a default deny policy on ingress")
				cnpDenyIngress := helpers.ManifestGet(kubectl.BasePath(),
					"cnp-default-deny-ingress.yaml")
				importPolicy(kubectl, testNamespace, cnpDenyIngress, "default-deny-ingress")

				count := testConnectivity(backendPodIP, false)
				defer monitorCancel()

				By("Asserting that the expected policy verdict logs are in the monitor output")
				Eventually(func() int {
					return len(policyVerdictDenyRegex.FindAll(monitor.CombineOutput().Bytes(), -1))
				}).Should(BeNumerically(">=", count), "Monitor output is missing verdicts: %s\n%s",
					policyVerdictDenyRegex, monitor.CombineOutput().Bytes())
			})

			It("connectivity is restored after importing ingress policy", func() {
				By("Importing a default deny policy on ingress")
				cnpDenyIngress := helpers.ManifestGet(kubectl.BasePath(),
					"cnp-default-deny-ingress.yaml")
				importPolicy(kubectl, testNamespace, cnpDenyIngress, "default-deny-ingress")

				By("Running cilium monitor in the background")
				ciliumPod, err := kubectl.GetCiliumPodOnNode(hostNodeName)
				Expect(ciliumPod).ToNot(BeEmpty())
				Expect(err).ToNot(HaveOccurred())

				ep, err := kubectl.GetCiliumEndpoint(testNamespace, backendPod.GetName())
				Expect(ep).ToNot(BeNil())
				Expect(err).ToNot(HaveOccurred())

				monitor, monitorCancel := kubectl.MonitorEndpointStart(ciliumPod, ep.ID)

				By("Importing fromCIDR+toPorts policy on ingress")
				cnpAllowIngress := helpers.ManifestGet(kubectl.BasePath(),
					"cnp-ingress-from-cidr-to-ports.yaml")
				importPolicy(kubectl, testNamespace, cnpAllowIngress, "ingress-from-cidr-to-ports")
				count := testConnectivity(backendPodIP, true)
				defer monitorCancel()

				By("Asserting that the expected policy verdict logs are in the monitor output")
				Eventually(func() int {
					return len(policyVerdictAllowRegex.FindAll(monitor.CombineOutput().Bytes(), -1))
				}).Should(BeNumerically(">=", count), "Monitor output is missing verdicts: %s\n%s",
					policyVerdictAllowRegex, monitor.CombineOutput().Bytes())
			})

			Context("With host policy", func() {
				BeforeAll(func() {
					// Deploy echoserver pods in host namespace.
					echoPodPath := helpers.ManifestGet(kubectl.BasePath(), "echoserver-cilium-hostnetns.yaml")
					kubectl.ApplyDefault(echoPodPath).ExpectSuccess("Cannot install echoserver application")
					Expect(kubectl.WaitforPods(helpers.DefaultNamespace, "-l name=echoserver-hostnetns",
						helpers.HelperTimeout)).Should(BeNil())

					policyVerdictAllowRegex = regexp.MustCompile(
						fmt.Sprintf("Policy verdict log: .+action allow.+%s:[0-9]+ -> %s:80 tcp SYN",
							outsideIP, hostIPOfBackendPod))
					policyVerdictDenyRegex = regexp.MustCompile(
						fmt.Sprintf("Policy verdict log: .+action deny.+%s:[0-9]+ -> %s:80 tcp SYN",
							outsideIP, hostIPOfBackendPod))
				})

				AfterAll(func() {
					// Remove echoserver pods from host namespace.
					echoPodPath := helpers.ManifestGet(kubectl.BasePath(), "echoserver-cilium-hostnetns.yaml")
					kubectl.Delete(echoPodPath).ExpectSuccess("Cannot remove echoserver application")
					ExpectAllPodsTerminated(kubectl)
				})

				It("Connectivity to hostns is blocked after denying ingress", func() {
					By("Running cilium monitor in the background")
					ciliumPod, err := kubectl.GetCiliumPodOnNode(hostNodeName)
					Expect(ciliumPod).ToNot(BeEmpty())
					Expect(err).ToNot(HaveOccurred())

					hostEpID, err := kubectl.GetCiliumHostEndpointID(ciliumPod)
					Expect(err).ToNot(HaveOccurred())

					monitor, monitorCancel := kubectl.MonitorEndpointStart(ciliumPod, hostEpID)

					By("Importing a default-deny host policy on ingress")
					ccnpDenyHostIngress := helpers.ManifestGet(kubectl.BasePath(), "ccnp-default-deny-host-ingress.yaml")
					importPolicy(kubectl, testNamespace, ccnpDenyHostIngress, "default-deny-host-ingress")

					testConnectivity(backendPodIP, true)
					count := testConnectivity(hostIPOfBackendPod, false)
					defer monitorCancel()

					By("Asserting that the expected policy verdict logs are in the monitor output")
					Eventually(func() int {
						return len(policyVerdictDenyRegex.FindAll(monitor.CombineOutput().Bytes(), -1))
					}).Should(BeNumerically(">=", count), "Monitor output is missing verdicts: %s\n%s",
						policyVerdictDenyRegex, monitor.CombineOutput().Bytes())
				})

				It("Connectivity is restored after importing ingress policy", func() {
					By("Importing a default-deny host policy on ingress")
					ccnpDenyHostIngress := helpers.ManifestGet(kubectl.BasePath(), "ccnp-default-deny-host-ingress.yaml")
					importPolicy(kubectl, testNamespace, ccnpDenyHostIngress, "default-deny-host-ingress")

					By("Running cilium monitor in the background")
					ciliumPod, err := kubectl.GetCiliumPodOnNode(hostNodeName)
					Expect(ciliumPod).ToNot(BeEmpty())
					Expect(err).ToNot(HaveOccurred())

					hostEpID, err := kubectl.GetCiliumHostEndpointID(ciliumPod)
					Expect(err).ToNot(HaveOccurred())

					monitor, monitorCancel := kubectl.MonitorEndpointStart(ciliumPod, hostEpID)

					By("Importing fromCIDR+toPorts host policy on ingress")
					ccnpAllowHostIngress := helpers.ManifestGet(kubectl.BasePath(),
						"ccnp-host-ingress-from-cidr-to-ports.yaml")
					importPolicy(kubectl, testNamespace, ccnpAllowHostIngress, "host-ingress-from-cidr-to-ports")

					testConnectivity(backendPodIP, true)
					count := testConnectivity(hostIPOfBackendPod, true)
					defer monitorCancel()

					By("Asserting that the expected policy verdict logs are in the monitor output")
					Eventually(func() int {
						return len(policyVerdictAllowRegex.FindAll(monitor.CombineOutput().Bytes(), -1))
					}).Should(BeNumerically(">=", count), "Monitor output is missing verdicts: %s\n%s",
						policyVerdictAllowRegex, monitor.CombineOutput().Bytes())

					By("Removing the fromCIDR+toPorts ingress host policy")
					// This is to ensure this policy is always removed before the default-deny one.
					// Otherwise, connection to the nodes may be disrupted.
					cmd := fmt.Sprintf("%s -n %s delete ccnp host-ingress-from-cidr-to-ports", helpers.KubectlCmd, testNamespace)
					kubectl.Exec(cmd).ExpectSuccess("Failed to delete ccnp/host-ingress-from-cidr-to-ports")
				})
			})
		})

		Context("validates fromEntities policies", func() {
			const (
				HostConnectivityDeny        = false
				HostConnectivityAllow       = true
				RemoteNodeConnectivityDeny  = false
				RemoteNodeConnectivityAllow = true
				PodConnectivityDeny         = false
				PodConnectivityAllow        = true
				WorldConnectivityDeny       = false
				WorldConnectivityAllow      = true
			)

			var (
				cnpFromEntitiesHost       string
				cnpFromEntitiesRemoteNode string
				cnpFromEntitiesCluster    string
				cnpFromEntitiesAll        string

				k8s1Name             string
				k8s1IP               string
				k8s1PodName          string
				k8s1PodIP, k8s2PodIP string

				outsideNodeName string
			)

			BeforeAll(func() {
				cnpFromEntitiesHost = helpers.ManifestGet(kubectl.BasePath(), "cnp-from-entities-host.yaml")
				cnpFromEntitiesRemoteNode = helpers.ManifestGet(kubectl.BasePath(), "cnp-from-entities-remote-node.yaml")
				cnpFromEntitiesCluster = helpers.ManifestGet(kubectl.BasePath(), "cnp-from-entities-cluster.yaml")
				cnpFromEntitiesAll = helpers.ManifestGet(kubectl.BasePath(), "cnp-from-entities-all.yaml")

				k8s1Name, k8s1IP = kubectl.GetNodeInfo(helpers.K8s1)
				k8s1PodName, k8s1PodIP = kubectl.GetPodOnNodeLabeledWithOffset(helpers.K8s1, testDS, 0)
				_, k8s2PodIP = kubectl.GetPodOnNodeLabeledWithOffset(helpers.K8s2, testDS, 0)

				if helpers.ExistNodeWithoutCilium() {
					outsideNodeName, _ = kubectl.GetNodeInfo(helpers.GetFirstNodeWithoutCilium())
				}

				// Masquerade function should be disabled
				// because the request will fail if the reply packet's source address is rewritten
				// when sending a request directly to the Pod from outside the cluster.
				By("Reconfiguring Cilium to disable ipv4 masquerade")
				RedeployCiliumWithMerge(kubectl, ciliumFilename, daemonCfg,
					map[string]string{
						"enableIPv4Masquerade": "false",
					})

			})

			AfterAll(func() {
				By("Redeploying Cilium with default configuration")
				RedeployCilium(kubectl, ciliumFilename, daemonCfg)
			})

			validateConnectivity := func(expectHostSuccess, expectRemoteNodeSuccess, expectPodSuccess, expectWorldSuccess bool) {
				var wg sync.WaitGroup
				wg.Add(1)
				go func() {
					defer GinkgoRecover()
					defer wg.Done()
					By("Checking ingress connectivity from k8s1 node to k8s1 pod (host)")
					res := kubectl.ExecInHostNetNS(context.TODO(), k8s1Name,
						helpers.CurlFail(k8s1PodIP))
					ExpectWithOffset(1, res).To(getMatcher(expectHostSuccess),
						"HTTP ingress connectivity to pod %q from local host", k8s1PodIP)
				}()

				wg.Add(1)
				go func() {
					defer GinkgoRecover()
					defer wg.Done()
					By("Checking ingress connectivity from k8s1 node to k8s2 pod (remote-node)")
					res := kubectl.ExecInHostNetNS(context.TODO(), k8s1Name,
						helpers.CurlFail(k8s2PodIP))
					ExpectWithOffset(1, res).To(getMatcher(expectRemoteNodeSuccess),
						"HTTP ingress connectivity to pod %q from remote node", k8s2PodIP)
				}()

				wg.Add(1)
				go func() {
					defer GinkgoRecover()
					defer wg.Done()
					By("Checking ingress connectivity from k8s1 pod to k8s2 pod")
					res := kubectl.ExecPodCmd(testNamespace, k8s1PodName, helpers.CurlFail(k8s2PodIP))
					ExpectWithOffset(1, res).To(getMatcher(expectPodSuccess),
						"HTTP ingress connectivity to pod %q from pod %q", k8s2PodIP, k8s1PodIP)
				}()

				if helpers.ExistNodeWithoutCilium() {
					wg.Add(1)
					go func() {
						defer GinkgoRecover()
						defer wg.Done()
						By("Checking ingress connectivity from world to k8s1 pod")
						By("Adding a static route to %s on the %s node (outside)", k8s1PodIP, outsideNodeName)
						res := kubectl.AddIPRoute(outsideNodeName, k8s1PodIP, k8s1IP, true)
						Expect(res).To(getMatcher(true))

						if expectWorldSuccess {
							testCurlFromOutside(kubectl, &helpers.NodesInfo{
								OutsideNodeName: outsideNodeName,
							}, k8s1PodIP, 1, false)
						} else {
							testCurlFailFromOutside(kubectl, &helpers.NodesInfo{
								OutsideNodeName: outsideNodeName,
							}, k8s1PodIP, 1)
						}
					}()
				}
				wg.Wait()
			}

			Context("with remote-node identity disabled", func() {
				BeforeAll(func() {
					By("Reconfiguring Cilium to disable remote-node identity")
					RedeployCiliumWithMerge(kubectl, ciliumFilename, daemonCfg,
						map[string]string{
							"remoteNodeIdentity":   "false",
							"enableIPv4Masquerade": "false",
						})
				})

				It("Allows from all hosts with cnp fromEntities host policy", func() {

					By("Installing fromEntities host policy")
					importPolicy(kubectl, testNamespace, cnpFromEntitiesHost, "from-entities-host")

					By("Checking policy correctness")
					validateConnectivity(HostConnectivityAllow, RemoteNodeConnectivityAllow, PodConnectivityDeny, WorldConnectivityDeny)
				})
			})

			Context("with remote-node identity enabled", func() {
				BeforeAll(func() {
					By("Reconfiguring Cilium to enable remote-node identity")
					RedeployCiliumWithMerge(kubectl, ciliumFilename, daemonCfg,
						map[string]string{
							"remoteNodeIdentity":   "true",
							"enableIPv4Masquerade": "false",
						})
				})

				It("Validates fromEntities remote-node policy", func() {
					installDefaultDenyIngressPolicy(kubectl, testNamespace, validateConnectivity)

					By("Installing fromEntities remote-node policy")
					importPolicy(kubectl, testNamespace, cnpFromEntitiesRemoteNode, "from-entities-remote-node")

					By("Checking policy correctness")
					validateConnectivity(HostConnectivityAllow, RemoteNodeConnectivityAllow, PodConnectivityDeny, WorldConnectivityDeny)
				})
			})

			It("Validates fromEntities cluster policy", func() {
				installDefaultDenyIngressPolicy(kubectl, testNamespace, validateConnectivity)

				By("Installing fromEntities cluster policy")
				importPolicy(kubectl, testNamespace, cnpFromEntitiesCluster, "from-entities-cluster")

				By("Checking policy correctness")
				validateConnectivity(HostConnectivityAllow, RemoteNodeConnectivityAllow, PodConnectivityAllow, WorldConnectivityDeny)
			})

			// Quarantined on net-next until #18520 is fixed
			SkipItIf(func() bool {
				return helpers.RunsOnNetNextKernel() && helpers.SkipQuarantined()
			}, "Validates fromEntities all policy", func() {
				installDefaultDenyIngressPolicy(kubectl, testNamespace, validateConnectivity)

				By("Installing fromEntities all policy")
				importPolicy(kubectl, testNamespace, cnpFromEntitiesAll, "from-entities-all")

				By("Checking policy correctness")
				validateConnectivity(HostConnectivityAllow, RemoteNodeConnectivityAllow, PodConnectivityAllow, WorldConnectivityAllow)
			})
		})

		Context("with L7 policy", func() {
			BeforeAll(func() {
				if helpers.RunsOnNetNextKernel() {
					By("Reconfiguring Cilium to enable BPF TProxy")
					RedeployCiliumWithMerge(kubectl, ciliumFilename, daemonCfg,
						map[string]string{
							"bpf.tproxy": "true",
						})
				}
			})

			AfterEach(func() {
				kubectl.Delete(connectivityCheckYml)
				ExpectAllPodsTerminated(kubectl)
			})

			It("using connectivity-check to check datapath", func() {
				kubectl.ApplyDefault(connectivityCheckYml).ExpectSuccess("cannot install connectivity-check")

				err := kubectl.WaitforPods(helpers.DefaultNamespace, "", helpers.HelperTimeout)
				Expect(err).Should(BeNil(), "connectivity-check pods are not ready after timeout")
			})
		})
	})

	Context("GuestBook Examples", func() {
		var (
			deployment      = "guestbook_deployment.yaml"
			redisPolicy     = "guestbook-policy-redis.json"
			redisPolicyName = "guestbook-policy-redis"
			webPolicy       = "guestbook-policy-web.yaml"
			webPolicyName   = "guestbook-policy-web"
		)

		var ciliumPods []string
		var err error

		BeforeEach(func() {
			kubectl.ApplyDefault(helpers.ManifestGet(kubectl.BasePath(), deployment))
			ciliumPods, err := kubectl.GetCiliumPods()
			Expect(err).To(BeNil(), "cannot retrieve Cilium Pods")
			Expect(ciliumPods).ShouldNot(BeEmpty(), "cannot retrieve Cilium pods")
		})

		getPolicyCmd := func(policy string) string {
			return fmt.Sprintf("%s=%s %s=%s",
				helpers.KubectlPolicyNameLabel, policy,
				helpers.KubectlPolicyNameSpaceLabel, helpers.DefaultNamespace)
		}

		AfterEach(func() {

			kubectl.Delete(helpers.ManifestGet(kubectl.BasePath(), webPolicy)).ExpectSuccess(
				"Web policy cannot be deleted")
			kubectl.Delete(helpers.ManifestGet(kubectl.BasePath(), deployment)).ExpectSuccess(
				"Guestbook deployment cannot be deleted")

			// This policy shouldn't be there, but test can fail before delete
			// the policy and we want to make sure that it's deleted
			kubectl.Delete(helpers.ManifestGet(kubectl.BasePath(), redisPolicy))
			for _, ciliumPod := range ciliumPods {
				err := kubectl.WaitPolicyDeleted(ciliumPod, getPolicyCmd(webPolicyName))
				Expect(err).To(
					BeNil(), "WebPolicy is not deleted")

				err = kubectl.WaitPolicyDeleted(ciliumPod, getPolicyCmd(redisPolicyName))
				Expect(err).To(
					BeNil(), "RedisPolicy is not deleted")
			}
			ExpectAllPodsTerminated(kubectl)
		})

		waitforPods := func() {
			err := kubectl.WaitforPods(helpers.DefaultNamespace, "-l tier=backend", helpers.HelperTimeout)
			ExpectWithOffset(1, err).Should(BeNil(), "Backend pods are not ready after timeout")

			err = kubectl.WaitforPods(helpers.DefaultNamespace, "-l tier=frontend", helpers.HelperTimeout)
			ExpectWithOffset(1, err).Should(BeNil(), "Frontend pods are not ready after timeout")

			err = kubectl.WaitForServiceEndpoints(helpers.DefaultNamespace, "", "redis-master", helpers.HelperTimeout)
			ExpectWithOffset(1, err).Should(BeNil(), "error waiting for redis-master service to be ready")

			err = kubectl.WaitForServiceEndpoints(helpers.DefaultNamespace, "", "redis-follower", helpers.HelperTimeout)
			ExpectWithOffset(1, err).Should(BeNil(), "error waiting for redis-follower service to be ready")
		}

		policyCheckStatus := func(policyCheck string) {
			for _, ciliumPod := range ciliumPods {
				ExpectWithOffset(1, kubectl.CiliumIsPolicyLoaded(ciliumPod, policyCheck)).To(BeTrue(),
					"Policy %q is not in cilium pod %s", policyCheck, ciliumPod)
			}
		}

		testConnectivitytoRedis := func() {
			webPods, err := kubectl.GetPodsNodes(helpers.DefaultNamespace, "app=guestbook")
			ExpectWithOffset(1, err).To(BeNil(), "Error retrieving web pods")
			ExpectWithOffset(1, webPods).ShouldNot(BeEmpty(), "Cannot retrieve web pods")

			cmd := helpers.CurlFailNoStats(`"127.0.0.1/guestbook.php?cmd=set&key=messages&value=Hello"`)
			for pod := range webPods {
				res := kubectl.ExecPodCmd(helpers.DefaultNamespace, pod, cmd)
				ExpectWithOffset(1, res).Should(helpers.CMDSuccess(), "Cannot curl webhook frontend of pod %q", pod)

				var response map[string]interface{}
				err := json.Unmarshal([]byte(res.Stdout()), &response)
				ExpectWithOffset(1, err).To(BeNil(), fmt.Sprintf("Error parsing JSON response: %s", res.Stdout()))
			}
		}
		It("checks policy example", func() {

			waitforPods()

			By("Apply policy to web")
			_, err = kubectl.CiliumPolicyAction(
				helpers.DefaultNamespace, helpers.ManifestGet(kubectl.BasePath(), webPolicy),
				helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Cannot apply web-policy")

			policyCheck := fmt.Sprintf("%s=%s %s=%s",
				helpers.KubectlPolicyNameLabel, webPolicyName,
				helpers.KubectlPolicyNameSpaceLabel, helpers.DefaultNamespace)
			policyCheckStatus(policyCheck)

			By("Apply policy to Redis")
			_, err = kubectl.CiliumPolicyAction(
				helpers.DefaultNamespace, helpers.ManifestGet(kubectl.BasePath(), redisPolicy),
				helpers.KubectlApply, helpers.HelperTimeout)

			Expect(err).Should(BeNil(), "Cannot apply redis policy")

			policyCheck = fmt.Sprintf("%s=%s %s=%s",
				helpers.KubectlPolicyNameLabel, redisPolicyName,
				helpers.KubectlPolicyNameSpaceLabel, helpers.DefaultNamespace)
			policyCheckStatus(policyCheck)

			testConnectivitytoRedis()

			_, err = kubectl.CiliumPolicyAction(
				helpers.DefaultNamespace, helpers.ManifestGet(kubectl.BasePath(), redisPolicy),
				helpers.KubectlDelete, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Cannot apply redis policy")
		})
	})

	Context("Namespaces policies", func() {

		var (
			err               error
			secondNS          string
			appPods           map[string]string
			appPodsNS         map[string]string
			clusterIP         string
			secondNSclusterIP string
			nsLabel           = "second"

			demoPath           string
			l3L4Policy         string
			cnpSecondNS        string
			netpolNsSelector   string
			l3l4PolicySecondNS string
			demoManifest       string
		)

		BeforeAll(func() {
			secondNS = helpers.GenerateNamespaceForTest("2")

			cnpSecondNSChart := helpers.ManifestGet(kubectl.BasePath(), "cnp-second-namespaces")
			cnpSecondNS = helpers.ManifestGet(kubectl.BasePath(), "cnp-second-namespaces.yaml")
			res := kubectl.HelmTemplate(cnpSecondNSChart, "", cnpSecondNS, map[string]string{
				"Namespace": secondNS,
			})
			res.ExpectSuccess("Unable to render cnp-second-namespace chart")

			demoPath = helpers.ManifestGet(kubectl.BasePath(), "demo.yaml")
			l3L4Policy = helpers.ManifestGet(kubectl.BasePath(), "l3-l4-policy.yaml")
			netpolNsSelector = fmt.Sprintf("%s -n %s", helpers.ManifestGet(kubectl.BasePath(), "netpol-namespace-selector.yaml"), secondNS)
			l3l4PolicySecondNS = fmt.Sprintf("%s -n %s", l3L4Policy, secondNS)
			demoManifest = fmt.Sprintf("%s -n %s", demoPath, secondNS)

			kubectl.NamespaceDelete(secondNS)
			res = kubectl.NamespaceCreate(secondNS)
			res.ExpectSuccess("unable to create namespace %q", secondNS)

			res = kubectl.Exec(fmt.Sprintf("kubectl label namespaces/%s nslabel=%s", secondNS, nsLabel))
			res.ExpectSuccess("cannot create namespace labels")

			res = kubectl.ApplyDefault(demoManifest)
			res.ExpectSuccess("unable to apply manifest")

			res = kubectl.ApplyDefault(demoPath)
			res.ExpectSuccess("unable to apply manifest")

			err := kubectl.WaitforPods(secondNS, "-l zgroup=testapp", helpers.HelperTimeout)
			Expect(err).To(BeNil(),
				"testapp pods are not ready after timeout in namspace %q", secondNS)

			err = kubectl.WaitforPods(helpers.DefaultNamespace, "-l zgroup=testapp", helpers.HelperTimeout)
			Expect(err).To(BeNil(),
				"testapp pods are not ready after timeout in %q namespace", helpers.DefaultNamespace)

			appPods = helpers.GetAppPods(apps, helpers.DefaultNamespace, kubectl, "id")
			appPodsNS = helpers.GetAppPods(apps, secondNS, kubectl, "id")

			clusterIP, _, err = kubectl.GetServiceHostPort(helpers.DefaultNamespace, app1Service)
			Expect(err).To(BeNil(), "Cannot get service on %q namespace", helpers.DefaultNamespace)

			secondNSclusterIP, _, err = kubectl.GetServiceHostPort(secondNS, app1Service)
			Expect(err).To(BeNil(), "Cannot get service on %q namespace", secondNS)

		})

		AfterEach(func() {
			// Explicitly do not check results to avoid incomplete teardown of test.
			_ = kubectl.Delete(l3l4PolicySecondNS)
			_ = kubectl.Delete(l3L4Policy)
			_ = kubectl.Delete(netpolNsSelector)

		})

		AfterAll(func() {
			_ = kubectl.Delete(demoPath)
			_ = kubectl.Delete(demoManifest)
			_ = kubectl.Delete(cnpSecondNS)
			_ = kubectl.NamespaceDelete(secondNS)
			ExpectAllPodsTerminated(kubectl)
		})

		It("Tests the same Policy in different namespaces", func() {
			// Tests that the same policy(name,labels) can enforce based on the
			// namespace and all works as expected.
			By("Applying Policy in %q namespace", secondNS)
			_, err = kubectl.CiliumPolicyAction(
				secondNS, l3l4PolicySecondNS, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(),
				"%q Policy cannot be applied in %q namespace", l3l4PolicySecondNS, secondNS)

			By("Applying Policy in default namespace")
			_, err = kubectl.CiliumPolicyAction(
				helpers.DefaultNamespace, l3L4Policy, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(),
				"%q Policy cannot be applied in %q namespace", l3L4Policy, helpers.DefaultNamespace)

			By("Testing connectivity in %q namespace", secondNS)

			res := kubectl.ExecPodCmd(
				secondNS, appPodsNS[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", secondNSclusterIP)))
			res.ExpectSuccess("%q cannot curl service", appPods[helpers.App2])

			res = kubectl.ExecPodCmd(
				secondNS, appPodsNS[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", secondNSclusterIP)))
			res.ExpectFail("%q can curl to service", appPods[helpers.App3])

			By("Testing connectivity in 'default' namespace")

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectSuccess("%q cannot curl clusterIP %q", appPods[helpers.App2], clusterIP)

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("%q can curl to %q", appPods[helpers.App3], clusterIP)
		})

		It("Kubernetes Network Policy by namespace selector", func() {
			// Use namespace selector using Kubernetes Network Policy to make
			// sure that it is translated correctly to Cilium and applies the
			// policies to the right endpoints.
			// KNP reference:
			// https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.10/#networkpolicyspec-v1-networking-k8s-io
			By("Testing connectivity across Namespaces without policy")
			for _, pod := range []string{helpers.App2, helpers.App3} {
				res := kubectl.ExecPodCmd(
					helpers.DefaultNamespace, appPods[pod],
					helpers.CurlFail(fmt.Sprintf("http://%s/public", secondNSclusterIP)))
				res.ExpectSuccess("%q cannot curl service", appPods[pod])

				res = kubectl.ExecPodCmd(
					secondNS, appPodsNS[pod],
					helpers.CurlFail(fmt.Sprintf("http://%s/public", secondNSclusterIP)))
				res.ExpectSuccess("%q cannot curl service", appPodsNS[pod])
			}

			By("Applying Policy in %q namespace", secondNS)
			_, err = kubectl.CiliumPolicyAction(
				secondNS, netpolNsSelector, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Policy cannot be applied")

			for _, pod := range []string{helpers.App2, helpers.App3} {
				// Make sure that the Default namespace can NOT connect to
				// second namespace.
				res := kubectl.ExecPodCmd(
					helpers.DefaultNamespace, appPods[pod],
					helpers.CurlFail(fmt.Sprintf("http://%s/public", secondNSclusterIP)))
				res.ExpectFail("%q can curl to service, policy is not blocking"+
					"communication to %q namespace", appPods[pod], secondNS)

				// Second namespace pods can connect to the same namespace based on policy.
				res = kubectl.ExecPodCmd(
					secondNS, appPodsNS[pod],
					helpers.CurlFail(fmt.Sprintf("http://%s/public", secondNSclusterIP)))
				res.ExpectSuccess("%q cannot curl service", appPodsNS[pod])
			}

			By("Delete Kubernetes Network Policies in %q namespace", secondNS)
			_, err = kubectl.CiliumPolicyAction(
				secondNS, netpolNsSelector, helpers.KubectlDelete, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "Policy %q cannot be deleted", netpolNsSelector)

			for _, pod := range []string{helpers.App2, helpers.App3} {
				res := kubectl.ExecPodCmd(
					helpers.DefaultNamespace, appPods[pod],
					helpers.CurlFail(fmt.Sprintf("http://%s/public", secondNSclusterIP)))
				res.ExpectSuccess("%q cannot curl service", appPods[pod])

				res = kubectl.ExecPodCmd(
					secondNS, appPodsNS[pod],
					helpers.CurlFail(fmt.Sprintf("http://%s/public", secondNSclusterIP)))
				res.ExpectSuccess("%q cannot curl service", appPodsNS[pod])
			}
		})

		It("Cilium Network policy using namespace label and L7", func() {

			_, err := kubectl.CiliumPolicyAction(
				helpers.DefaultNamespace, cnpSecondNS, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(), "%q Policy cannot be applied", cnpSecondNS)

			By("Testing connectivity in %q namespace", secondNS)
			res := kubectl.ExecPodCmd(
				secondNS, appPodsNS[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectSuccess("Cannot curl service in %s ns", helpers.DefaultNamespace)

			res = kubectl.ExecPodCmd(
				secondNS, appPodsNS[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectSuccess("Cannot curl service in %s ns", helpers.DefaultNamespace)

			By("Testing connectivity from 'default' namespace")

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("Can connect when it should not")

			res = kubectl.ExecPodCmd(
				helpers.DefaultNamespace, appPods[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", clusterIP)))
			res.ExpectFail("Can connect when it should not")
		})

	})

	Context("Clusterwide policies", func() {
		var (
			demoPath        string
			demoManifestNS1 string
			demoManifestNS2 string
			firstNS         string
			secondNS        string

			appPodsFirstNS  map[string]string
			appPodsSecondNS map[string]string

			firstNSclusterIP  string
			secondNSclusterIP string

			ingressDenyAllPolicy string
			egressDenyAllPolicy  string
			allowIngressPolicy   string
			allowAllPolicy       string
		)

		BeforeAll(func() {
			firstNS = helpers.GenerateNamespaceForTest("1")
			secondNS = helpers.GenerateNamespaceForTest("2")
			demoPath = helpers.ManifestGet(kubectl.BasePath(), "demo.yaml")
			egressDenyAllPolicy = helpers.ManifestGet(kubectl.BasePath(), "ccnp-default-deny-egress.yaml")
			ingressDenyAllPolicy = helpers.ManifestGet(kubectl.BasePath(), "ccnp-default-deny-ingress.yaml")
			allowIngressPolicy = helpers.ManifestGet(kubectl.BasePath(), "ccnp-update-allow-ingress.yaml")
			allowAllPolicy = helpers.ManifestGet(kubectl.BasePath(), "ccnp-update-allow-all.yaml")

			demoManifestNS1 = fmt.Sprintf("%s -n %s", demoPath, firstNS)
			demoManifestNS2 = fmt.Sprintf("%s -n %s", demoPath, secondNS)

			kubectl.NamespaceDelete(firstNS)
			res := kubectl.NamespaceCreate(firstNS)
			res.ExpectSuccess("unable to create namespace %q", firstNS)

			res = kubectl.Exec(fmt.Sprintf("kubectl label namespaces/%[1]s nslabel=%[1]s", firstNS))
			res.ExpectSuccess("cannot create namespace labels")

			kubectl.NamespaceDelete(secondNS)
			res = kubectl.NamespaceCreate(secondNS)
			res.ExpectSuccess("unable to create namespace %q", secondNS)

			res = kubectl.Exec(fmt.Sprintf("kubectl label namespaces/%[1]s nslabel=%[1]s", secondNS))
			res.ExpectSuccess("cannot create namespace labels")

			res = kubectl.ApplyDefault(demoManifestNS1)
			res.ExpectSuccess("unable to apply demo manifest")

			// Check if the Pods are ready in each namespace before the default configured
			// timeout.
			err := kubectl.WaitforPods(firstNS, "-l zgroup=testapp", helpers.HelperTimeout)
			Expect(err).To(BeNil(),
				"testapp pods are not ready after timeout in namspace %q", firstNS)

			res = kubectl.ApplyDefault(demoManifestNS2)
			res.ExpectSuccess("unable to apply demo manifest")

			err = kubectl.WaitforPods(secondNS, "-l zgroup=testapp", helpers.HelperTimeout)
			Expect(err).To(BeNil(),
				"testapp pods are not ready after timeout in namspace %q", secondNS)

			appPodsFirstNS = helpers.GetAppPods(apps, firstNS, kubectl, "id")
			appPodsSecondNS = helpers.GetAppPods(apps, secondNS, kubectl, "id")

			firstNSclusterIP, _, err = kubectl.GetServiceHostPort(firstNS, app1Service)
			Expect(err).To(BeNil(), "Cannot get service on %q namespace", helpers.DefaultNamespace)

			secondNSclusterIP, _, err = kubectl.GetServiceHostPort(secondNS, app1Service)
			Expect(err).To(BeNil(), "Cannot get service on %q namespace", secondNS)

		})

		AfterAll(func() {
			_ = kubectl.Delete(demoManifestNS1)
			_ = kubectl.Delete(demoManifestNS2)
			_ = kubectl.NamespaceDelete(firstNS)
			_ = kubectl.NamespaceDelete(secondNS)
			ExpectAllPodsTerminated(kubectl)
		})

		It("Test clusterwide connectivity with policies", func() {
			By("Applying Egress deny all clusterwide policy")
			_, err := kubectl.CiliumClusterwidePolicyAction(
				egressDenyAllPolicy, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(),
				"%q Clusterwide Policy cannot be applied", egressDenyAllPolicy)

			res := kubectl.ExecPodCmd(
				firstNS, appPodsFirstNS[helpers.App2],
				helpers.CurlFail("http://1.1.1.1/"))
			res.ExpectFail("Egress connectivity should be denied for pod %q", helpers.App2)

			res = kubectl.ExecPodCmd(
				secondNS, appPodsSecondNS[helpers.App2],
				helpers.CurlFail("http://1.1.1.1/"))
			res.ExpectFail("Egress connectivity should be denied for pod %q in %q namespace", helpers.App2, secondNS)

			res = kubectl.ExecPodCmd(
				firstNS, appPodsFirstNS[helpers.App3],
				helpers.Ping("8.8.8.8"))
			res.ExpectFail("Egress ping connectivity should be denied for pod %q", helpers.App3)

			res = kubectl.ExecPodCmd(
				secondNS, appPodsSecondNS[helpers.App3],
				"host kubernetes.default.svc.cluster.local")
			res.ExpectFail("Egress DNS connectivity should be denied for pod %q", helpers.App3)

			By("Deleting Egress deny all clusterwide policy")
			_, err = kubectl.CiliumClusterwidePolicyAction(
				egressDenyAllPolicy, helpers.KubectlDelete, helpers.HelperTimeout)
			Expect(err).Should(BeNil(),
				"%q Clusterwide Policy cannot be deleted", egressDenyAllPolicy)

			By("Applying Ingress deny all clusterwide policy")
			_, err = kubectl.CiliumClusterwidePolicyAction(
				ingressDenyAllPolicy, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(),
				"%q Clusterwide Policy cannot be applied", egressDenyAllPolicy)

			// Validate ingress Deny All policy.
			By("Testing ingress connectivity from %q namespace", firstNS)
			res = kubectl.ExecPodCmd(
				firstNS, appPodsFirstNS[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", firstNSclusterIP)))
			res.ExpectFail("Ingress connectivity should be denied for service in %s namespace", firstNS)

			By("Testing ingress connectivity from %q namespace", secondNS)
			res = kubectl.ExecPodCmd(
				secondNS, appPodsSecondNS[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", secondNSclusterIP)))
			res.ExpectFail("Ingress connectivity should be denied for service in %s namespace", secondNS)

			By("Testing cross namespace connectivity from %q to %q namespace", firstNS, secondNS)
			res = kubectl.ExecPodCmd(
				firstNS, appPodsFirstNS[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", secondNSclusterIP)))
			res.ExpectFail("Ingress connectivity should be denied for service in %s namespace", secondNS)

			By("Testing cross namespace connectivity from %q to %q namespace", secondNS, firstNS)
			res = kubectl.ExecPodCmd(
				secondNS, appPodsSecondNS[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", firstNSclusterIP)))
			res.ExpectFail("Ingress connectivity should be denied for service in %s namespace", firstNS)

			// Apply both ingress deny and egress deny all policies and override the policies with
			// global allow all policy.
			By("Applying Egress deny all clusterwide policy")
			_, err = kubectl.CiliumClusterwidePolicyAction(
				egressDenyAllPolicy, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(),
				"%q Clusterwide Policy cannot be applied", egressDenyAllPolicy)

			By("Applying Allow all clusterwide policy over ingress deny all and egress deny all")
			_, err = kubectl.CiliumClusterwidePolicyAction(
				allowAllPolicy, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(),
				"%q Clusterwide Policy cannot be applied", allowAllPolicy)

			By("Testing ingress connectivity from %q namespace", firstNS)
			res = kubectl.ExecPodCmd(
				firstNS, appPodsFirstNS[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", firstNSclusterIP)))
			res.ExpectSuccess("Ingress connectivity should be allowed for service in %s namespace", firstNS)

			By("Testing ingress connectivity from %q namespace", secondNS)
			res = kubectl.ExecPodCmd(
				secondNS, appPodsSecondNS[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", secondNSclusterIP)))
			res.ExpectSuccess("Ingress connectivity should be allowed for service in %s namespace", secondNS)

			By("Testing cross namespace connectivity from %q to %q namespace", firstNS, secondNS)
			res = kubectl.ExecPodCmd(
				firstNS, appPodsFirstNS[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", secondNSclusterIP)))
			res.ExpectSuccess("Ingress connectivity should be allowed for service in %s namespace", secondNS)

			By("Testing cross namespace connectivity from %q to %q namespace", secondNS, firstNS)
			res = kubectl.ExecPodCmd(
				secondNS, appPodsSecondNS[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", firstNSclusterIP)))
			res.ExpectSuccess("Ingress connectivity should be allowed for service in %s namespace", firstNS)

			// Update the ccnp-update policy from allow-all to allow-ingress from app2 to app1.
			// Checks in this ingress allow policy are
			// 1. Check allowed ingress from app2.firstNS to app1.firstNS
			// 2. Check allowed ingress from app2.secondNS to app1.firstNS
			// 3. Check denied ingress from app3.firstNS to app1.firstNS
			// 4. Check denied ingress from app3.secondNS to app1.firstNS
			By("Update allow all policy to allow ingress from a particular app only.")
			_, err = kubectl.CiliumClusterwidePolicyAction(
				allowIngressPolicy, helpers.KubectlApply, helpers.HelperTimeout)
			Expect(err).Should(BeNil(),
				"%q Clusterwide Policy cannot be applied", allowIngressPolicy)

			By("Deleting Egress deny all clusterwide policy")
			_, err = kubectl.CiliumClusterwidePolicyAction(
				egressDenyAllPolicy, helpers.KubectlDelete, helpers.HelperTimeout)
			Expect(err).Should(BeNil(),
				"%q Clusterwide Policy cannot be deleted", egressDenyAllPolicy)

			By("Testing ingress connectivity from %q to %q in %q namespace", helpers.App2, helpers.App1, firstNS)
			res = kubectl.ExecPodCmd(
				firstNS, appPodsFirstNS[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", firstNSclusterIP)))
			res.ExpectSuccess("Ingress connectivity should be allowed for service in %s namespace", firstNS)

			By("Testing ingress connectivity from %q to %q across two namespaces", helpers.App2, helpers.App1)
			res = kubectl.ExecPodCmd(
				secondNS, appPodsSecondNS[helpers.App2],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", firstNSclusterIP)))
			res.ExpectSuccess("Ingress connectivity should be allowed for service in %s namespace", firstNS)

			By("Testing ingress connectivity from %q to %q in %q namespace", helpers.App3, helpers.App1, firstNS)
			res = kubectl.ExecPodCmd(
				firstNS, appPodsFirstNS[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", firstNSclusterIP)))
			res.ExpectFail("Ingress connectivity should be denied for service in %s namespace", firstNS)

			By("Testing ingress connectivity from %q to %q across two namespacess", helpers.App3, helpers.App1)
			res = kubectl.ExecPodCmd(
				secondNS, appPodsSecondNS[helpers.App3],
				helpers.CurlFail(fmt.Sprintf("http://%s/public", firstNSclusterIP)))
			res.ExpectFail("Ingress connectivity should be denied for service in %s namespace", firstNS)

			// Cleanup all tested policies
			By("Delete allow ingress from particular app policy")
			_, err = kubectl.CiliumClusterwidePolicyAction(
				allowIngressPolicy, helpers.KubectlDelete, helpers.HelperTimeout)
			Expect(err).Should(BeNil(),
				"%q Clusterwide Policy cannot be deleted", allowIngressPolicy)

			By("Deleting Ingress deny all clusterwide policy")
			_, err = kubectl.CiliumClusterwidePolicyAction(
				ingressDenyAllPolicy, helpers.KubectlDelete, helpers.HelperTimeout)
			Expect(err).Should(BeNil(),
				"%q Clusterwide Policy cannot be deleted", ingressDenyAllPolicy)
		})
	})
})

// This Describe block is needed to run some tests in GKE. For example, the
// kube-apiserver policy matching feature needs coverage on GKE as there are
// two cases for that feature:
//   * kube-apiserver running within the cluster (Vagrant VMs)
//   * kube-apiserver running outside of the cluster (GKE)
var _ = SkipDescribeIf(helpers.DoesNotRunOn419OrLaterKernel,
	"K8sPolicyTestExtended", func() {
		var (
			kubectl *helpers.Kubectl

			// these are set in BeforeAll()
			ciliumFilename string
			daemonCfg      map[string]string
		)

		BeforeAll(func() {
			kubectl = helpers.CreateKubectl(helpers.K8s1VMName(), logger)
			daemonCfg = map[string]string{
				"tls.secretsBackend": "k8s",
			}
			ciliumFilename = helpers.TimestampFilename("cilium.yaml")
		})

		AfterAll(func() {
			UninstallCiliumFromManifest(kubectl, ciliumFilename)
			kubectl.CloseSSHClient()
		})

		AfterFailed(func() {
			kubectl.CiliumReport("cilium service list", "cilium endpoint list")
		})

		AfterEach(func() {
			ExpectAllPodsTerminated(kubectl)
		})

		JustAfterEach(func() {
			kubectl.ValidateNoErrorsInLogs(CurrentGinkgoTestDescription().Duration)
		})

		// Test must run with KPR enabled, see below comments.
		Context("Validate toEntities KubeAPIServer", func() {
			var (
				k8s1Name, k8s1IP         string
				k8s1PodName, k8s2PodName string
				k8s1PodIP, k8s2PodIP     string
				outsideNodeName          string

				demoLocalYAML                  string
				cnpToEntitiesKubeAPIServer     string
				cnpToEntitiesKubeAPIServerDeny string

				kubeAPIServerService *v1.Service

				testNamespace = helpers.DefaultNamespace
			)

			BeforeAll(func() {
				cnpToEntitiesKubeAPIServer = helpers.ManifestGet(
					kubectl.BasePath(), "cnp-to-entities-kube-apiserver.yaml",
				)
				cnpToEntitiesKubeAPIServerDeny = helpers.ManifestGet(
					kubectl.BasePath(), "cnp-to-entities-kube-apiserver-deny.yaml",
				)

				By("Redeploying Cilium with tunnel disabled and KPR enabled")
				RedeployCiliumWithMerge(kubectl, ciliumFilename, daemonCfg, map[string]string{
					// The following are needed because of
					// https://github.com/cilium/cilium/issues/17962 &&
					// https://github.com/cilium/cilium/issues/16197.
					"tunnel":               "disabled",
					"autoDirectNodeRoutes": "true",
					"kubeProxyReplacement": "strict",
				})

				By("Deploying demo local daemonset")
				demoLocalYAML = helpers.ManifestGet(kubectl.BasePath(), "demo_ds_local.yaml")
				kubectl.ApplyDefault(demoLocalYAML).ExpectSuccess("Unable to apply %s", demoLocalYAML)
				Expect(kubectl.WaitforPods(
					testNamespace,
					fmt.Sprintf("-l %s", testDS), helpers.HelperTimeout),
				).Should(BeNil())
				k8s1Name, k8s1IP = kubectl.GetNodeInfo(helpers.K8s1)
				k8s1PodName, k8s1PodIP = kubectl.GetPodOnNodeLabeledWithOffset(helpers.K8s1, testDS, 0)
				k8s2PodName, k8s2PodIP = kubectl.GetPodOnNodeLabeledWithOffset(helpers.K8s2, testDS, 0)
				if helpers.ExistNodeWithoutCilium() {
					outsideNodeName, _ = kubectl.GetNodeInfo(helpers.GetFirstNodeWithoutCilium())
				}

				var err error
				kubeAPIServerService, err = kubectl.GetService(helpers.DefaultNamespace, "kubernetes")
				Expect(err).ToNot(HaveOccurred())
				Expect(kubeAPIServerService).ToNot(BeNil())
			})

			AfterAll(func() {
				// Explicitly ignore result of deletion of resources to
				// avoid incomplete teardown if any step fails.
				_ = kubectl.Delete(demoLocalYAML)
				ExpectAllPodsTerminated(kubectl)
			})

			AfterEach(func() {
				cmd := fmt.Sprintf("%s delete --all cnp,ccnp,netpol -n %s", helpers.KubectlCmd, testNamespace)
				_ = kubectl.Exec(cmd)
			})

			validateConnectivity := func(
				expectHostSuccess, expectRemoteNodeSuccess, expectPodSuccess, expectWorldSuccess bool,
			) {
				var wg sync.WaitGroup
				wg.Add(1)
				go func() {
					defer GinkgoRecover()
					defer wg.Done()
					switch helpers.GetCurrentIntegration() {
					case helpers.CIIntegrationEKS, helpers.CIIntegrationEKSChaining, helpers.CIIntegrationGKE:
						By("Checking ingress connectivity from k8s1 node to k8s1 pod (host)")
					default:
						// We need to bypass this check as in a non-managed
						// environment like Vagrant, the kube-apiserver is
						// running locally on K8s1. This means that local host
						// traffic cannot be disambiguated from kube-apiserver
						// traffic.
						By("Bypassing check for ingress connectivity for host, which cannot be done in non-managed environments")
						return
					}
					res := kubectl.ExecInHostNetNS(context.TODO(), k8s1Name,
						helpers.CurlFail(k8s1PodIP))
					ExpectWithOffset(1, res).To(getMatcher(expectHostSuccess),
						"HTTP ingress connectivity to pod %q from local host", k8s1PodIP)
				}()

				wg.Add(1)
				go func() {
					defer GinkgoRecover()
					defer wg.Done()
					switch helpers.GetCurrentIntegration() {
					case helpers.CIIntegrationEKS, helpers.CIIntegrationEKSChaining, helpers.CIIntegrationGKE:
						By("Checking ingress connectivity from k8s1 node to k8s2 pod (remote-node)")
					default:
						// We need to bypass this check as in a two node
						// cluster, the kube-apiserver will be running on at
						// least one of the two nodes, which means that any
						// traffic to or from will be considered to / from
						// kube-apiserver, and not remote-node. If we had a
						// third node with Cilium installed, then we wouldn't
						// need to bypass this check.
						By("Bypassing check for ingress connectivity for remote-node, which cannot be done in a two-node cluster")
						return
					}
					res := kubectl.ExecInHostNetNS(context.TODO(), k8s1Name,
						helpers.CurlFail(k8s2PodIP))
					ExpectWithOffset(1, res).To(getMatcher(expectRemoteNodeSuccess),
						"HTTP ingress connectivity to pod %q from remote node", k8s2PodIP)
				}()

				wg.Add(1)
				go func() {
					defer GinkgoRecover()
					defer wg.Done()
					By("Checking ingress connectivity from k8s1 pod to k8s2 pod")
					res := kubectl.ExecPodCmd(testNamespace, k8s1PodName, helpers.CurlFail(k8s2PodIP))
					ExpectWithOffset(1, res).To(getMatcher(expectPodSuccess),
						"HTTP ingress connectivity to pod %q from pod %q", k8s2PodIP, k8s1PodIP)
				}()

				if helpers.ExistNodeWithoutCilium() {
					wg.Add(1)
					go func() {
						defer GinkgoRecover()
						defer wg.Done()
						By("Checking ingress connectivity from world to k8s1 pod")
						By("Adding a static route to %s on the %s node (outside)", k8s1PodIP, outsideNodeName)
						res := kubectl.AddIPRoute(outsideNodeName, k8s1PodIP, k8s1IP, true)
						Expect(res).To(getMatcher(true))

						if expectWorldSuccess {
							testCurlFromOutside(kubectl, &helpers.NodesInfo{
								OutsideNodeName: outsideNodeName,
							}, k8s1PodIP, 1, false)
						} else {
							testCurlFailFromOutside(kubectl, &helpers.NodesInfo{
								OutsideNodeName: outsideNodeName,
							}, k8s1PodIP, 1)
						}
					}()
				}
				wg.Wait()
			}

			It("Allows connection to KubeAPIServer", func() {
				installDefaultDenyIngressPolicy(
					kubectl,
					testNamespace,
					validateConnectivity,
				)
				installDefaultDenyEgressPolicy(
					kubectl,
					testNamespace,
					validateConnectivity,
				)

				By("Verifying KubeAPIServer connectivity is not yet allowed")
				Expect(
					kubectl.ExecPodCmd(
						testNamespace, k8s2PodName, helpers.CurlWithHTTPCode(
							"https://%s %s",
							kubeAPIServerService.Spec.ClusterIP,
							"--insecure", // kube-apiserver needs cert, skip verification
						),
					),
				).To(getMatcher(false),
					"HTTP egress connectivity should have been denied to pod %q to kube-apiserver %q",
					k8s2PodName, kubeAPIServerService.Spec.ClusterIP,
				)

				By("Installing toEntities KubeAPIServer")
				importPolicy(
					kubectl,
					testNamespace,
					cnpToEntitiesKubeAPIServer,
					"to-entities-kube-apiserver",
				)

				By("Verifying policy correctness")
				validateConnectivity(
					true,  /*HostConnectivityAllow*/
					false, /*RemoteNodeConnectivityDeny*/
					false, /*PodConnectivityDeny*/
					false, /*WorldConnectivityDeny*/
				)

				By("Verifying KubeAPIServer connectivity")
				// A 403 is a sign of success in this test due to lack of HTTP
				// egress policy. We expect to get back 403 because we
				// purposefully didn't provide the auth token to fully talk to
				// the kube-apiserver.
				Expect(
					kubectl.ExecPodCmd(
						testNamespace, k8s2PodName, helpers.CurlWithHTTPCode(
							"https://%s %s",
							kubeAPIServerService.Spec.ClusterIP,
							"--insecure", // kube-apiserver needs cert, skip verification
						),
					).Stdout(),
				).To(Equal("403"),
					"HTTP egress connectivity to pod %q to kube-apiserver %q",
					k8s2PodName, kubeAPIServerService.Spec.ClusterIP,
				)
			})

			It("Still allows connection to KubeAPIServer with a duplicate policy", func() {
				installDefaultDenyIngressPolicy(
					kubectl,
					testNamespace,
					validateConnectivity,
				)
				installDefaultDenyEgressPolicy(
					kubectl,
					testNamespace,
					validateConnectivity,
				)
				By("Installing toEntities KubeAPIServer")
				importPolicy(
					kubectl,
					testNamespace,
					cnpToEntitiesKubeAPIServer,
					"to-entities-kube-apiserver",
				)

				By("Installing duplicate toEntities KubeAPIServer")
				importPolicy(
					kubectl,
					testNamespace,
					helpers.ManifestGet(
						kubectl.BasePath(), "cnp-to-entities-kube-apiserver-2.yaml",
					),
					"to-entities-kube-apiserver-2",
				)

				By("Removing the previous toEntities KubeAPIServer policy")
				_, err := kubectl.CiliumPolicyAction(
					testNamespace, cnpToEntitiesKubeAPIServer, helpers.KubectlDelete, helpers.HelperTimeout,
				)
				Expect(err).Should(
					BeNil(),
					"policy %s cannot be deleted in %q namespace", cnpToEntitiesKubeAPIServer, testNamespace,
				)

				By("Verifying KubeAPIServer connectivity is still allowed")
				// See previous It() about the assertion on 403 HTTP code.
				Expect(
					kubectl.ExecPodCmd(
						testNamespace, k8s2PodName, helpers.CurlWithHTTPCode(
							"https://%s %s",
							kubeAPIServerService.Spec.ClusterIP,
							"--insecure", // kube-apiserver needs cert, skip verification
						),
					).Stdout(),
				).To(Equal("403"),
					"HTTP egress connectivity to pod %q to kube-apiserver %q",
					k8s2PodName, kubeAPIServerService.Spec.ClusterIP,
				)
			})

			It("Denies connection to KubeAPIServer", func() {
				By("Installing allow-all egress policy")
				importPolicy(
					kubectl,
					testNamespace,
					helpers.ManifestGet(kubectl.BasePath(), "cnp-to-entities-all.yaml"),
					"allow-all-egress",
				)

				By("Installing toEntities KubeAPIServer")
				importPolicy(
					kubectl,
					testNamespace,
					cnpToEntitiesKubeAPIServerDeny,
					"to-entities-kube-apiserver-deny",
				)

				By("Verifying policy correctness")
				validateConnectivity(
					true, /*HostConnectivityAllow*/
					true, /*RemoteNodeConnectivityAllow*/
					true, /*PodConnectivityAllow*/
					true, /*WorldConnectivityAllow*/
				)

				By("Verifying KubeAPIServer connectivity is denied")
				Expect(
					kubectl.ExecPodCmd(
						testNamespace, k8s2PodName, helpers.CurlWithHTTPCode(
							"https://%s %s",
							kubeAPIServerService.Spec.ClusterIP,
							"--insecure", // kube-apiserver needs cert, skip verification
						),
					),
				).To(getMatcher(false),
					"HTTP egress connectivity should have been denied to pod %q to kube-apiserver %q",
					k8s2PodName, kubeAPIServerService.Spec.ClusterIP,
				)
			})
		})
	})

func importPolicy(kubectl *helpers.Kubectl, namespace, file, name string) {
	_, err := kubectl.CiliumPolicyAction(namespace,
		file,
		helpers.KubectlApply,
		helpers.HelperTimeout)
	ExpectWithOffset(1, err).Should(BeNil(),
		"policy %s cannot be applied in %q namespace", file, namespace)
}

func installDefaultDenyIngressPolicy(
	kubectl *helpers.Kubectl,
	ns string,
	f func(bool, bool, bool, bool),
) {
	denyIngress := helpers.ManifestGet(kubectl.BasePath(), "cnp-default-deny-ingress.yaml")

	By("Installing default-deny ingress policy")
	importPolicy(kubectl, ns, denyIngress, "default-deny-ingress")

	By("Checking that remote-node is disallowed by default")
	f(
		true,  /*HostConnectivityAllow*/
		false, /*RemoteNodeConnectivityDeny*/
		false, /*PodConnectivityDeny*/
		false, /*WorldConnectivityDeny*/
	)
}

func installDefaultDenyEgressPolicy(
	kubectl *helpers.Kubectl,
	ns string,
	f func(bool, bool, bool, bool),
) {
	denyEgress := helpers.ManifestGet(kubectl.BasePath(), "cnp-default-deny-egress.yaml")

	By("Installing default-deny egress policy")
	importPolicy(kubectl, ns, denyEgress, "default-deny-egress")

	By("Checking that remote-node is disallowed by default")
	f(
		true,  /*HostConnectivityAllow*/
		false, /*RemoteNodeConnectivityDeny*/
		false, /*PodConnectivityDeny*/
		false, /*WorldConnectivityDeny*/
	)
}

// getMatcher returns a helper.CMDSucess() matcher for success or failure
// situations.
func getMatcher(val bool) types.GomegaMatcher {
	if val {
		return helpers.CMDSuccess()
	}
	return Not(helpers.CMDSuccess())
}
