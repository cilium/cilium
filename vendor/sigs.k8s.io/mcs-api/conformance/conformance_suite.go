/*
Copyright 2023 The Kubernetes Authors.

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

package conformance

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"slices"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/types"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	rest "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"
	mcsclient "sigs.k8s.io/mcs-api/pkg/client/clientset/versioned"
)

type clusterClients struct {
	name string
	k8s  kubernetes.Interface
	mcs  mcsclient.Interface
	rest *rest.Config
}

var (
	contexts                         string
	clients                          []clusterClients
	loadingRules                     *clientcmd.ClientConfigLoadingRules
	skipVerifyEndpointSliceManagedBy bool
	ctx                              = context.TODO()
)

// TestConformance runs the conformance test.
func TestConformance(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Conformance Suite")
}

func init() {
	loadingRules = clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRules.DefaultClientConfig = &clientcmd.DefaultClientConfig
	flag.StringVar(&loadingRules.ExplicitPath, "kubeconfig", "", "absolute path(s) to the kubeconfig file(s)")
	flag.StringVar(&contexts, "contexts", "", "comma-separated list of contexts to use")
	flag.BoolVar(&skipVerifyEndpointSliceManagedBy, "skip-verify-eps-managed-by", false,
		fmt.Sprintf("The MSC spec states that any EndpointSlice created by an mcs-controller must be marked as managed by "+
			"the mcs-controller. By default, the conformance test verifies that the %q label on MCS EndpointSlices is not equal to %q. "+
			"However with some implementations, MCS EndpointSlices may be created and managed by K8s. If this flag is set to true, "+
			"the test only verifies the presence of the label.",
			discoveryv1.LabelManagedBy, K8sEndpointSliceManagedByName))
}

var _ = BeforeSuite(func() {
	Expect(setupClients()).To(Succeed(), "Test suite set up failed")
})

func setupClients() error {
	splitContexts := strings.Split(contexts, ",")
	clients = make([]clusterClients, len(splitContexts))
	accumulatedErrors := []error{}

	for i, kubeContext := range splitContexts {
		err := func() error {
			overrides := clientcmd.ConfigOverrides{ClusterDefaults: clientcmd.ClusterDefaults}
			overrides.CurrentContext = kubeContext

			clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &overrides)

			rawConfig, err := clientConfig.RawConfig()
			if err != nil {
				return fmt.Errorf("error setting up a Kubernetes API client on context %s: %w", kubeContext, err)
			}

			name := kubeContext
			if name == "" {
				name = rawConfig.CurrentContext
			}

			configContext, ok := rawConfig.Contexts[name]
			if ok {
				name = configContext.Cluster
			}

			restConfig, err := clientConfig.ClientConfig()
			if err != nil {
				return fmt.Errorf("error setting up a Kubernetes API client on context %s: %w", name, err)
			}

			k8sClient, err := kubernetes.NewForConfig(restConfig)
			if err != nil {
				return fmt.Errorf("error setting up a Kubernetes API client on context %s: %w", name, err)
			}

			mcsClient, err := mcsclient.NewForConfig(restConfig)
			if err != nil {
				return fmt.Errorf("error setting up an MCS API client on context %s: %w", name, err)
			}

			if _, err := mcsClient.MulticlusterV1alpha1().ServiceExports("").List(context.TODO(), metav1.ListOptions{}); err != nil {
				return fmt.Errorf("error listing ServiceExports on context %s: %w. Is the MCS API installed?", name, err)
			}

			if _, err := mcsClient.MulticlusterV1alpha1().ServiceImports("").List(context.TODO(), metav1.ListOptions{}); err != nil {
				return fmt.Errorf("error listing ServiceImports on context %s: %w. Is the MCS API installed?", name, err)
			}

			clients[i] = clusterClients{name: name, k8s: k8sClient, mcs: mcsClient, rest: restConfig}

			return nil
		}()

		accumulatedErrors = append(accumulatedErrors, err)
	}

	return errors.Join(accumulatedErrors...)
}

type testDriver struct {
	namespace          string
	helloService       *corev1.Service
	helloServiceExport *v1alpha1.ServiceExport
	helloDeployment    *appsv1.Deployment
	requestPod         *corev1.Pod
	autoExportService  bool
}

func newTestDriver() *testDriver {
	t := &testDriver{}

	BeforeEach(func() {
		t.namespace = fmt.Sprintf("mcs-conformance-%v", rand.Uint32())
		t.helloService = newHelloService()
		t.helloServiceExport = newHelloServiceExport()
		t.helloDeployment = newHelloDeployment()
		t.requestPod = newRequestPod()
		t.autoExportService = true
	})

	JustBeforeEach(func() {
		Expect(clients).ToNot(BeEmpty())

		// Set up the shared namespace
		for _, client := range clients {
			_, err := client.k8s.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: t.namespace},
			}, metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())
		}

		// Set up the remote service (the first cluster is considered to be the remote)
		t.deployHelloService(&clients[0], t.helloService)

		// Start the request pod on all clusters
		for _, client := range clients {
			t.startRequestPod(ctx, client)
		}

		if t.autoExportService {
			t.createServiceExport(&clients[0], t.helloServiceExport)
		}
	})

	AfterEach(func() {
		// Clean up the shared namespace
		for _, client := range clients {
			err := client.k8s.CoreV1().Namespaces().Delete(ctx, t.namespace, metav1.DeleteOptions{})
			if !apierrors.IsNotFound(err) {
				Expect(err).ToNot(HaveOccurred())
			}
		}
	})

	return t
}

func (t *testDriver) createServiceExport(c *clusterClients, serviceExport *v1alpha1.ServiceExport) {
	_, err := c.mcs.MulticlusterV1alpha1().ServiceExports(t.namespace).Create(
		ctx, serviceExport, metav1.CreateOptions{})
	Expect(err).ToNot(HaveOccurred())

	By(fmt.Sprintf("Service \"%s/%s\" exported on cluster %q", t.namespace, helloServiceName, c.name))
}

func (t *testDriver) deleteServiceExport(c *clusterClients) {
	Expect(c.mcs.MulticlusterV1alpha1().ServiceExports(t.namespace).Delete(ctx, helloServiceName,
		metav1.DeleteOptions{})).ToNot(HaveOccurred())

	By(fmt.Sprintf("Service \"%s/%s\" unexported on cluster %q", t.namespace, helloServiceName, c.name))
}

func (t *testDriver) deployHelloService(c *clusterClients, service *corev1.Service) {
	if t.helloDeployment != nil {
		_, err := c.k8s.AppsV1().Deployments(t.namespace).Create(ctx, t.helloDeployment, metav1.CreateOptions{})
		Expect(err).ToNot(HaveOccurred())
	}

	deployed, err := c.k8s.CoreV1().Services(t.namespace).Create(ctx, service, metav1.CreateOptions{})
	Expect(err).ToNot(HaveOccurred())

	By(fmt.Sprintf("Service \"%s/%s\" deployed on cluster %q", deployed.Namespace, deployed.Name, c.name))
}

func (t *testDriver) getServiceImport(c *clusterClients, name string) *v1alpha1.ServiceImport {
	si, err := c.mcs.MulticlusterV1alpha1().ServiceImports(t.namespace).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) || errors.Is(err, context.DeadlineExceeded) ||
		(err != nil && strings.Contains(err.Error(), "rate limiter")) {
		return nil
	}

	Expect(err).ToNot(HaveOccurred(), "Error retrieving ServiceImport")

	return si
}

func (t *testDriver) awaitServiceImport(c *clusterClients, name string, reportNonConformanceOnMissing bool,
	verify func(Gomega, *v1alpha1.ServiceImport)) *v1alpha1.ServiceImport {
	var serviceImport *v1alpha1.ServiceImport

	Eventually(func(g Gomega) {
		si := t.getServiceImport(c, name)

		missingMsg := fmt.Sprintf("ServiceImport was not found on cluster %q", c.name)

		var missing any = missingMsg
		if reportNonConformanceOnMissing {
			missing = reportNonConformant(missingMsg)
		}

		g.Expect(si).NotTo(BeNil(), missing)

		serviceImport = si

		if verify != nil {
			verify(g, serviceImport)
		}

		// The final run succeeded so cancel any prior non-conformance reported.
		cancelNonConformanceReport()
	}).Within(20 * time.Second).WithPolling(100 * time.Millisecond).Should(Succeed())

	return serviceImport
}

func (t *testDriver) awaitNoServiceImport(c *clusterClients, name, nonConformanceMsg string) {
	Eventually(func() bool {
		_, err := c.mcs.MulticlusterV1alpha1().ServiceImports(t.namespace).Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return true
		}

		Expect(err).ToNot(HaveOccurred())

		return false
	}, 20*time.Second, 100*time.Millisecond).Should(BeTrue(), reportNonConformant(nonConformanceMsg))
}

func (t *testDriver) ensureServiceImport(c *clusterClients, name, nonConformanceMsg string) {
	Consistently(func() error {
		_, err := c.mcs.MulticlusterV1alpha1().ServiceImports(t.namespace).Get(ctx, name, metav1.GetOptions{})
		return err
	}, 5*time.Second, 100*time.Millisecond).ShouldNot(HaveOccurred(), reportNonConformant(nonConformanceMsg))
}

func (t *testDriver) ensureNoServiceImport(c *clusterClients, name, nonConformanceMsg string) {
	Consistently(func() bool {
		_, err := c.mcs.MulticlusterV1alpha1().ServiceImports(t.namespace).Get(ctx, name, metav1.GetOptions{})
		return apierrors.IsNotFound(err)
	}, 5*time.Second, 100*time.Millisecond).Should(BeTrue(), reportNonConformant(nonConformanceMsg))
}

func (t *testDriver) awaitServiceExportCondition(c *clusterClients, condType v1alpha1.ServiceExportConditionType,
	wantStatus metav1.ConditionStatus) {
	Eventually(func() bool {
		se, err := c.mcs.MulticlusterV1alpha1().ServiceExports(t.namespace).Get(ctx, helloServiceName, metav1.GetOptions{})
		Expect(err).ToNot(HaveOccurred())

		cond := meta.FindStatusCondition(se.Status.Conditions, string(condType))
		return cond != nil && cond.Status == wantStatus
	}, 20*time.Second, 100*time.Millisecond).Should(BeTrue(),
		reportNonConformant(fmt.Sprintf("The %s condition was not set to %s", condType, wantStatus)))
}

func (t *testDriver) startRequestPod(ctx context.Context, client clusterClients) {
	_, err := client.k8s.CoreV1().Pods(t.namespace).Create(ctx, t.requestPod, metav1.CreateOptions{})
	Expect(err).ToNot(HaveOccurred())

	Eventually(func() error {
		pod, err := client.k8s.CoreV1().Pods(t.namespace).Get(ctx, t.requestPod.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}

		if pod.Status.Phase != corev1.PodRunning {
			return fmt.Errorf("pod is not running yet, current status %v", pod.Status.Phase)
		}

		return nil
	}, 20, 1).Should(Succeed())
}

func (t *testDriver) execCmdOnRequestPod(c *clusterClients, command []string) string {
	stdout, _, _ := execCmd(c.k8s, c.rest, t.requestPod.Name, t.namespace, command)
	return string(stdout)
}

func (t *testDriver) awaitCmdOutputMatches(c *clusterClients, command []string, expected any, nIter int, msg func() string) {
	var matcher types.GomegaMatcher

	switch v := expected.(type) {
	case string:
		matcher = ContainSubstring(v)
	case types.GomegaMatcher:
		matcher = v
	}

	Eventually(func(g Gomega) {
		output := t.execCmdOnRequestPod(c, command)
		g.Expect(output).To(matcher, "Command output")
	}).Within(time.Duration(20*int64(nIter))*time.Second).ProbeEvery(time.Second).MustPassRepeatedly(nIter).Should(Succeed(), msg)
}

func (t *testDriver) awaitServicePodIP(c *clusterClients) string {
	By(fmt.Sprintf("Awaiting service deployment pod IP on cluster %q", c.name))

	servicePodIP := ""

	Eventually(func(g Gomega) {
		pods, err := c.k8s.CoreV1().Pods(t.namespace).List(context.TODO(), metav1.ListOptions{
			LabelSelector: metav1.FormatLabelSelector(newHelloDeployment().Spec.Selector),
		})

		g.Expect(err).NotTo(HaveOccurred())
		g.Expect(pods.Items).NotTo(BeEmpty())

		servicePodIP = pods.Items[0].Status.PodIP
		g.Expect(servicePodIP).NotTo(BeEmpty(), "Service deployment pod was not allocated an IP")
	}).Within(20 * time.Second).WithPolling(100 * time.Millisecond).Should(Succeed())

	By(fmt.Sprintf("Retrieved service deployment pod IP %q", servicePodIP))

	return servicePodIP
}

func (t *testDriver) execPortConnectivityCommand(port int, matchStr string, nIter int) {
	command := []string{"sh", "-c", fmt.Sprintf("echo hi | nc %s.%s.svc.clusterset.local %d",
		t.helloService.Name, t.namespace, port)}

	for _, client := range clients {
		By(fmt.Sprintf("Executing command %q on cluster %q", strings.Join(command, " "), client.name))

		t.awaitCmdOutputMatches(&client, command, matchStr, nIter, reportNonConformant(""))
	}
}

type twoClusterTestDriver struct {
	*testDriver
	helloService2       *corev1.Service
	helloServiceExport2 *v1alpha1.ServiceExport
}

func newTwoClusterTestDriver(t *testDriver) *twoClusterTestDriver {
	tt := &twoClusterTestDriver{testDriver: t}

	BeforeEach(func() {
		requireTwoClusters()

		tt.helloService2 = newHelloService()
		tt.helloServiceExport2 = newHelloServiceExport()
		t.autoExportService = false
	})

	JustBeforeEach(func() {
		t.createServiceExport(&clients[0], t.helloServiceExport)

		// The conflict resolution policy in the MCS spec (KEP 1645) allows an implementation to favor maintaining
		// service continuity and avoiding potentially disruptive changes, as such, an implementation may choose the
		// first observed exported service when resolving conflicts. To support this, verify the ServiceImport is
		// created on the first cluster prior to deploying on the second cluster.
		t.awaitServiceImport(&clients[0], helloServiceName, false, nil)

		// Delay a little before deploying on the second cluster to ensure the first cluster's ServiceExport timestamp
		// is older so conflict checking is deterministic for implementations that use the timestamp when resolving conflicts.
		// Make the delay at least 1 sec as creation timestamps have seconds granularity.
		time.Sleep(1100 * time.Millisecond)

		t.deployHelloService(&clients[1], tt.helloService2)
		t.createServiceExport(&clients[1], tt.helloServiceExport2)
	})

	return tt
}

func toMCSPorts(from []corev1.ServicePort) []v1alpha1.ServicePort {
	var mcsPorts []v1alpha1.ServicePort

	for _, port := range from {
		mcsPorts = append(mcsPorts, v1alpha1.ServicePort{
			Name:        port.Name,
			Protocol:    port.Protocol,
			Port:        port.Port,
			AppProtocol: port.AppProtocol,
		})
	}

	return sortMCSPorts(mcsPorts)
}

func sortMCSPorts(p []v1alpha1.ServicePort) []v1alpha1.ServicePort {
	slices.SortFunc(p, func(a, b v1alpha1.ServicePort) int {
		return cmp.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})

	return p
}

func requireTwoClusters() {
	if len(clients) < 2 {
		Skip("This test requires at least 2 clusters - skipping")
	}
}
