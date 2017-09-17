/*
Copyright 2016 The Kubernetes Authors.

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

package network

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/kubernetes/pkg/client/clientset_generated/internalclientset"
	"k8s.io/kubernetes/pkg/cloudprovider"
	"k8s.io/kubernetes/pkg/controller/endpoint"
	"k8s.io/kubernetes/test/e2e/framework"
	imageutils "k8s.io/kubernetes/test/utils/image"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = SIGDescribe("Services", func() {
	f := framework.NewDefaultFramework("services")

	var cs clientset.Interface
	var internalClientset internalclientset.Interface
	serviceLBNames := []string{}

	BeforeEach(func() {
		cs = f.ClientSet
		internalClientset = f.InternalClientset
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			framework.DescribeSvc(f.Namespace.Name)
		}
		for _, lb := range serviceLBNames {
			framework.Logf("cleaning gce resource for %s", lb)
			framework.CleanupServiceGCEResources(cs, lb, framework.TestContext.CloudConfig.Zone)
		}
		//reset serviceLBNames
		serviceLBNames = []string{}
	})

	// TODO: We get coverage of TCP/UDP and multi-port services through the DNS test. We should have a simpler test for multi-port TCP here.

	It("should provide secure master service [Conformance]", func() {
		_, err := cs.CoreV1().Services(metav1.NamespaceDefault).Get("kubernetes", metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	It("should serve a basic endpoint from pods [Conformance]", func() {
		// TODO: use the ServiceTestJig here
		serviceName := "endpoint-test2"
		ns := f.Namespace.Name
		labels := map[string]string{
			"foo": "bar",
			"baz": "blah",
		}

		By("creating service " + serviceName + " in namespace " + ns)
		defer func() {
			err := cs.CoreV1().Services(ns).Delete(serviceName, nil)
			Expect(err).NotTo(HaveOccurred())
		}()

		service := &v1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name: serviceName,
			},
			Spec: v1.ServiceSpec{
				Selector: labels,
				Ports: []v1.ServicePort{{
					Port:       80,
					TargetPort: intstr.FromInt(80),
				}},
			},
		}
		_, err := cs.CoreV1().Services(ns).Create(service)
		Expect(err).NotTo(HaveOccurred())

		framework.ValidateEndpointsOrFail(cs, ns, serviceName, framework.PortsByPodName{})

		names := map[string]bool{}
		defer func() {
			for name := range names {
				err := cs.CoreV1().Pods(ns).Delete(name, nil)
				Expect(err).NotTo(HaveOccurred())
			}
		}()

		name1 := "pod1"
		name2 := "pod2"

		framework.CreatePodOrFail(cs, ns, name1, labels, []v1.ContainerPort{{ContainerPort: 80}})
		names[name1] = true
		framework.ValidateEndpointsOrFail(cs, ns, serviceName, framework.PortsByPodName{name1: {80}})

		framework.CreatePodOrFail(cs, ns, name2, labels, []v1.ContainerPort{{ContainerPort: 80}})
		names[name2] = true
		framework.ValidateEndpointsOrFail(cs, ns, serviceName, framework.PortsByPodName{name1: {80}, name2: {80}})

		framework.DeletePodOrFail(cs, ns, name1)
		delete(names, name1)
		framework.ValidateEndpointsOrFail(cs, ns, serviceName, framework.PortsByPodName{name2: {80}})

		framework.DeletePodOrFail(cs, ns, name2)
		delete(names, name2)
		framework.ValidateEndpointsOrFail(cs, ns, serviceName, framework.PortsByPodName{})
	})

	It("should serve multiport endpoints from pods [Conformance]", func() {
		// TODO: use the ServiceTestJig here
		// repacking functionality is intentionally not tested here - it's better to test it in an integration test.
		serviceName := "multi-endpoint-test"
		ns := f.Namespace.Name

		defer func() {
			err := cs.CoreV1().Services(ns).Delete(serviceName, nil)
			Expect(err).NotTo(HaveOccurred())
		}()

		labels := map[string]string{"foo": "bar"}

		svc1port := "svc1"
		svc2port := "svc2"

		By("creating service " + serviceName + " in namespace " + ns)
		service := &v1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name: serviceName,
			},
			Spec: v1.ServiceSpec{
				Selector: labels,
				Ports: []v1.ServicePort{
					{
						Name:       "portname1",
						Port:       80,
						TargetPort: intstr.FromString(svc1port),
					},
					{
						Name:       "portname2",
						Port:       81,
						TargetPort: intstr.FromString(svc2port),
					},
				},
			},
		}
		_, err := cs.CoreV1().Services(ns).Create(service)
		Expect(err).NotTo(HaveOccurred())
		port1 := 100
		port2 := 101
		framework.ValidateEndpointsOrFail(cs, ns, serviceName, framework.PortsByPodName{})

		names := map[string]bool{}
		defer func() {
			for name := range names {
				err := cs.CoreV1().Pods(ns).Delete(name, nil)
				Expect(err).NotTo(HaveOccurred())
			}
		}()

		containerPorts1 := []v1.ContainerPort{
			{
				Name:          svc1port,
				ContainerPort: int32(port1),
			},
		}
		containerPorts2 := []v1.ContainerPort{
			{
				Name:          svc2port,
				ContainerPort: int32(port2),
			},
		}

		podname1 := "pod1"
		podname2 := "pod2"

		framework.CreatePodOrFail(cs, ns, podname1, labels, containerPorts1)
		names[podname1] = true
		framework.ValidateEndpointsOrFail(cs, ns, serviceName, framework.PortsByPodName{podname1: {port1}})

		framework.CreatePodOrFail(cs, ns, podname2, labels, containerPorts2)
		names[podname2] = true
		framework.ValidateEndpointsOrFail(cs, ns, serviceName, framework.PortsByPodName{podname1: {port1}, podname2: {port2}})

		framework.DeletePodOrFail(cs, ns, podname1)
		delete(names, podname1)
		framework.ValidateEndpointsOrFail(cs, ns, serviceName, framework.PortsByPodName{podname2: {port2}})

		framework.DeletePodOrFail(cs, ns, podname2)
		delete(names, podname2)
		framework.ValidateEndpointsOrFail(cs, ns, serviceName, framework.PortsByPodName{})
	})

	It("should preserve source pod IP for traffic thru service cluster IP", func() {

		// This behavior is not supported if Kube-proxy is in "userspace" mode.
		// So we check the kube-proxy mode and skip this test if that's the case.
		if proxyMode, err := framework.ProxyMode(f); err == nil {
			if proxyMode == "userspace" {
				framework.Skipf("The test doesn't work with kube-proxy in userspace mode")
			}
		} else {
			framework.Logf("Couldn't detect KubeProxy mode - test failure may be expected: %v", err)
		}

		serviceName := "sourceip-test"
		ns := f.Namespace.Name

		By("creating a TCP service " + serviceName + " with type=ClusterIP in namespace " + ns)
		jig := framework.NewServiceTestJig(cs, serviceName)
		servicePort := 8080
		tcpService := jig.CreateTCPServiceWithPort(ns, nil, int32(servicePort))
		jig.SanityCheckService(tcpService, v1.ServiceTypeClusterIP)
		defer func() {
			framework.Logf("Cleaning up the sourceip test service")
			err := cs.CoreV1().Services(ns).Delete(serviceName, nil)
			Expect(err).NotTo(HaveOccurred())
		}()
		serviceIp := tcpService.Spec.ClusterIP
		framework.Logf("sourceip-test cluster ip: %s", serviceIp)

		By("Picking multiple nodes")
		nodes := framework.GetReadySchedulableNodesOrDie(f.ClientSet)

		if len(nodes.Items) == 1 {
			framework.Skipf("The test requires two Ready nodes on %s, but found just one.", framework.TestContext.Provider)
		}

		node1 := nodes.Items[0]
		node2 := nodes.Items[1]

		By("Creating a webserver pod be part of the TCP service which echoes back source ip")
		serverPodName := "echoserver-sourceip"
		jig.LaunchEchoserverPodOnNode(f, node1.Name, serverPodName)
		defer func() {
			framework.Logf("Cleaning up the echo server pod")
			err := cs.CoreV1().Pods(ns).Delete(serverPodName, nil)
			Expect(err).NotTo(HaveOccurred())
		}()

		// Waiting for service to expose endpoint.
		framework.ValidateEndpointsOrFail(cs, ns, serviceName, framework.PortsByPodName{serverPodName: {servicePort}})

		By("Retrieve sourceip from a pod on the same node")
		sourceIp1, execPodIp1 := execSourceipTest(f, cs, ns, node1.Name, serviceIp, servicePort)
		By("Verifying the preserved source ip")
		Expect(sourceIp1).To(Equal(execPodIp1))

		By("Retrieve sourceip from a pod on a different node")
		sourceIp2, execPodIp2 := execSourceipTest(f, cs, ns, node2.Name, serviceIp, servicePort)
		By("Verifying the preserved source ip")
		Expect(sourceIp2).To(Equal(execPodIp2))
	})

	It("should be able to up and down services", func() {
		// TODO: use the ServiceTestJig here
		// this test uses framework.NodeSSHHosts that does not work if a Node only reports LegacyHostIP
		framework.SkipUnlessProviderIs(framework.ProvidersWithSSH...)
		// this test does not work if the Node does not support SSH Key
		framework.SkipUnlessSSHKeyPresent()

		ns := f.Namespace.Name
		numPods, servicePort := 3, 80

		By("creating service1 in namespace " + ns)
		podNames1, svc1IP, err := framework.StartServeHostnameService(cs, internalClientset, ns, "service1", servicePort, numPods)
		Expect(err).NotTo(HaveOccurred())
		By("creating service2 in namespace " + ns)
		podNames2, svc2IP, err := framework.StartServeHostnameService(cs, internalClientset, ns, "service2", servicePort, numPods)
		Expect(err).NotTo(HaveOccurred())

		hosts, err := framework.NodeSSHHosts(cs)
		Expect(err).NotTo(HaveOccurred())
		if len(hosts) == 0 {
			framework.Failf("No ssh-able nodes")
		}
		host := hosts[0]

		By("verifying service1 is up")
		framework.ExpectNoError(framework.VerifyServeHostnameServiceUp(cs, ns, host, podNames1, svc1IP, servicePort))

		By("verifying service2 is up")
		framework.ExpectNoError(framework.VerifyServeHostnameServiceUp(cs, ns, host, podNames2, svc2IP, servicePort))

		// Stop service 1 and make sure it is gone.
		By("stopping service1")
		framework.ExpectNoError(framework.StopServeHostnameService(f.ClientSet, f.InternalClientset, ns, "service1"))

		By("verifying service1 is not up")
		framework.ExpectNoError(framework.VerifyServeHostnameServiceDown(cs, host, svc1IP, servicePort))
		By("verifying service2 is still up")
		framework.ExpectNoError(framework.VerifyServeHostnameServiceUp(cs, ns, host, podNames2, svc2IP, servicePort))

		// Start another service and verify both are up.
		By("creating service3 in namespace " + ns)
		podNames3, svc3IP, err := framework.StartServeHostnameService(cs, internalClientset, ns, "service3", servicePort, numPods)
		Expect(err).NotTo(HaveOccurred())

		if svc2IP == svc3IP {
			framework.Failf("service IPs conflict: %v", svc2IP)
		}

		By("verifying service2 is still up")
		framework.ExpectNoError(framework.VerifyServeHostnameServiceUp(cs, ns, host, podNames2, svc2IP, servicePort))

		By("verifying service3 is up")
		framework.ExpectNoError(framework.VerifyServeHostnameServiceUp(cs, ns, host, podNames3, svc3IP, servicePort))
	})

	It("should work after restarting kube-proxy [Disruptive]", func() {
		// TODO: use the ServiceTestJig here
		framework.SkipUnlessProviderIs("gce", "gke")

		ns := f.Namespace.Name
		numPods, servicePort := 3, 80

		svc1 := "service1"
		svc2 := "service2"

		defer func() {
			framework.ExpectNoError(framework.StopServeHostnameService(f.ClientSet, f.InternalClientset, ns, svc1))
		}()
		podNames1, svc1IP, err := framework.StartServeHostnameService(cs, internalClientset, ns, svc1, servicePort, numPods)
		Expect(err).NotTo(HaveOccurred())

		defer func() {
			framework.ExpectNoError(framework.StopServeHostnameService(f.ClientSet, f.InternalClientset, ns, svc2))
		}()
		podNames2, svc2IP, err := framework.StartServeHostnameService(cs, internalClientset, ns, svc2, servicePort, numPods)
		Expect(err).NotTo(HaveOccurred())

		if svc1IP == svc2IP {
			framework.Failf("VIPs conflict: %v", svc1IP)
		}

		hosts, err := framework.NodeSSHHosts(cs)
		Expect(err).NotTo(HaveOccurred())
		if len(hosts) == 0 {
			framework.Failf("No ssh-able nodes")
		}
		host := hosts[0]

		framework.ExpectNoError(framework.VerifyServeHostnameServiceUp(cs, ns, host, podNames1, svc1IP, servicePort))
		framework.ExpectNoError(framework.VerifyServeHostnameServiceUp(cs, ns, host, podNames2, svc2IP, servicePort))

		By(fmt.Sprintf("Restarting kube-proxy on %v", host))
		if err := framework.RestartKubeProxy(host); err != nil {
			framework.Failf("error restarting kube-proxy: %v", err)
		}
		framework.ExpectNoError(framework.VerifyServeHostnameServiceUp(cs, ns, host, podNames1, svc1IP, servicePort))
		framework.ExpectNoError(framework.VerifyServeHostnameServiceUp(cs, ns, host, podNames2, svc2IP, servicePort))

		By("Removing iptable rules")
		result, err := framework.SSH(`
			sudo iptables -t nat -F KUBE-SERVICES || true;
			sudo iptables -t nat -F KUBE-PORTALS-HOST || true;
			sudo iptables -t nat -F KUBE-PORTALS-CONTAINER || true`, host, framework.TestContext.Provider)
		if err != nil || result.Code != 0 {
			framework.LogSSHResult(result)
			framework.Failf("couldn't remove iptable rules: %v", err)
		}
		framework.ExpectNoError(framework.VerifyServeHostnameServiceUp(cs, ns, host, podNames1, svc1IP, servicePort))
		framework.ExpectNoError(framework.VerifyServeHostnameServiceUp(cs, ns, host, podNames2, svc2IP, servicePort))
	})

	It("should work after restarting apiserver [Disruptive]", func() {
		// TODO: use the ServiceTestJig here
		framework.SkipUnlessProviderIs("gce", "gke")

		ns := f.Namespace.Name
		numPods, servicePort := 3, 80

		defer func() {
			framework.ExpectNoError(framework.StopServeHostnameService(f.ClientSet, f.InternalClientset, ns, "service1"))
		}()
		podNames1, svc1IP, err := framework.StartServeHostnameService(cs, internalClientset, ns, "service1", servicePort, numPods)
		Expect(err).NotTo(HaveOccurred())

		hosts, err := framework.NodeSSHHosts(cs)
		Expect(err).NotTo(HaveOccurred())
		if len(hosts) == 0 {
			framework.Failf("No ssh-able nodes")
		}
		host := hosts[0]

		framework.ExpectNoError(framework.VerifyServeHostnameServiceUp(cs, ns, host, podNames1, svc1IP, servicePort))

		// Restart apiserver
		By("Restarting apiserver")
		if err := framework.RestartApiserver(cs.Discovery()); err != nil {
			framework.Failf("error restarting apiserver: %v", err)
		}
		By("Waiting for apiserver to come up by polling /healthz")
		if err := framework.WaitForApiserverUp(cs); err != nil {
			framework.Failf("error while waiting for apiserver up: %v", err)
		}
		framework.ExpectNoError(framework.VerifyServeHostnameServiceUp(cs, ns, host, podNames1, svc1IP, servicePort))

		// Create a new service and check if it's not reusing IP.
		defer func() {
			framework.ExpectNoError(framework.StopServeHostnameService(f.ClientSet, f.InternalClientset, ns, "service2"))
		}()
		podNames2, svc2IP, err := framework.StartServeHostnameService(cs, internalClientset, ns, "service2", servicePort, numPods)
		Expect(err).NotTo(HaveOccurred())

		if svc1IP == svc2IP {
			framework.Failf("VIPs conflict: %v", svc1IP)
		}
		framework.ExpectNoError(framework.VerifyServeHostnameServiceUp(cs, ns, host, podNames1, svc1IP, servicePort))
		framework.ExpectNoError(framework.VerifyServeHostnameServiceUp(cs, ns, host, podNames2, svc2IP, servicePort))
	})

	// TODO: Run this test against the userspace proxy and nodes
	// configured with a default deny firewall to validate that the
	// proxy whitelists NodePort traffic.
	It("should be able to create a functioning NodePort service", func() {
		serviceName := "nodeport-test"
		ns := f.Namespace.Name

		jig := framework.NewServiceTestJig(cs, serviceName)
		nodeIP := framework.PickNodeIP(jig.Client) // for later

		By("creating service " + serviceName + " with type=NodePort in namespace " + ns)
		service := jig.CreateTCPServiceOrFail(ns, func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeNodePort
		})
		jig.SanityCheckService(service, v1.ServiceTypeNodePort)
		nodePort := int(service.Spec.Ports[0].NodePort)

		By("creating pod to be part of service " + serviceName)
		jig.RunOrFail(ns, nil)

		By("hitting the pod through the service's NodePort")
		jig.TestReachableHTTP(nodeIP, nodePort, framework.KubeProxyLagTimeout)

		By("verifying the node port is locked")
		hostExec := framework.LaunchHostExecPod(f.ClientSet, f.Namespace.Name, "hostexec")
		// Even if the node-ip:node-port check above passed, this hostexec pod
		// might fall on a node with a laggy kube-proxy.
		cmd := fmt.Sprintf(`for i in $(seq 1 300); do if ss -ant46 'sport = :%d' | grep ^LISTEN; then exit 0; fi; sleep 1; done; exit 1`, nodePort)
		stdout, err := framework.RunHostCmd(hostExec.Namespace, hostExec.Name, cmd)
		if err != nil {
			framework.Failf("expected node port %d to be in use, stdout: %v. err: %v", nodePort, stdout, err)
		}
	})

	It("should be able to change the type and ports of a service [Slow]", func() {
		// requires cloud load-balancer support
		framework.SkipUnlessProviderIs("gce", "gke", "aws")

		loadBalancerSupportsUDP := !framework.ProviderIs("aws")

		loadBalancerLagTimeout := framework.LoadBalancerLagTimeoutDefault
		if framework.ProviderIs("aws") {
			loadBalancerLagTimeout = framework.LoadBalancerLagTimeoutAWS
		}
		loadBalancerCreateTimeout := framework.LoadBalancerCreateTimeoutDefault
		if nodes := framework.GetReadySchedulableNodesOrDie(cs); len(nodes.Items) > framework.LargeClusterMinNodesNumber {
			loadBalancerCreateTimeout = framework.LoadBalancerCreateTimeoutLarge
		}

		// This test is more monolithic than we'd like because LB turnup can be
		// very slow, so we lumped all the tests into one LB lifecycle.

		serviceName := "mutability-test"
		ns1 := f.Namespace.Name // LB1 in ns1 on TCP
		framework.Logf("namespace for TCP test: %s", ns1)

		By("creating a second namespace")
		namespacePtr, err := f.CreateNamespace("services", nil)
		Expect(err).NotTo(HaveOccurred())
		ns2 := namespacePtr.Name // LB2 in ns2 on UDP
		framework.Logf("namespace for UDP test: %s", ns2)

		jig := framework.NewServiceTestJig(cs, serviceName)
		nodeIP := framework.PickNodeIP(jig.Client) // for later

		// Test TCP and UDP Services.  Services with the same name in different
		// namespaces should get different node ports and load balancers.

		By("creating a TCP service " + serviceName + " with type=ClusterIP in namespace " + ns1)
		tcpService := jig.CreateTCPServiceOrFail(ns1, nil)
		jig.SanityCheckService(tcpService, v1.ServiceTypeClusterIP)

		By("creating a UDP service " + serviceName + " with type=ClusterIP in namespace " + ns2)
		udpService := jig.CreateUDPServiceOrFail(ns2, nil)
		jig.SanityCheckService(udpService, v1.ServiceTypeClusterIP)

		By("verifying that TCP and UDP use the same port")
		if tcpService.Spec.Ports[0].Port != udpService.Spec.Ports[0].Port {
			framework.Failf("expected to use the same port for TCP and UDP")
		}
		svcPort := int(tcpService.Spec.Ports[0].Port)
		framework.Logf("service port (TCP and UDP): %d", svcPort)

		By("creating a pod to be part of the TCP service " + serviceName)
		jig.RunOrFail(ns1, nil)

		By("creating a pod to be part of the UDP service " + serviceName)
		jig.RunOrFail(ns2, nil)

		// Change the services to NodePort.

		By("changing the TCP service to type=NodePort")
		tcpService = jig.UpdateServiceOrFail(ns1, tcpService.Name, func(s *v1.Service) {
			s.Spec.Type = v1.ServiceTypeNodePort
		})
		jig.SanityCheckService(tcpService, v1.ServiceTypeNodePort)
		tcpNodePort := int(tcpService.Spec.Ports[0].NodePort)
		framework.Logf("TCP node port: %d", tcpNodePort)

		By("changing the UDP service to type=NodePort")
		udpService = jig.UpdateServiceOrFail(ns2, udpService.Name, func(s *v1.Service) {
			s.Spec.Type = v1.ServiceTypeNodePort
		})
		jig.SanityCheckService(udpService, v1.ServiceTypeNodePort)
		udpNodePort := int(udpService.Spec.Ports[0].NodePort)
		framework.Logf("UDP node port: %d", udpNodePort)

		By("hitting the TCP service's NodePort")
		jig.TestReachableHTTP(nodeIP, tcpNodePort, framework.KubeProxyLagTimeout)

		By("hitting the UDP service's NodePort")
		jig.TestReachableUDP(nodeIP, udpNodePort, framework.KubeProxyLagTimeout)

		// Change the services to LoadBalancer.

		// Here we test that LoadBalancers can receive static IP addresses.  This isn't
		// necessary, but is an additional feature this monolithic test checks.
		requestedIP := ""
		staticIPName := ""
		if framework.ProviderIs("gce", "gke") {
			By("creating a static load balancer IP")
			staticIPName = fmt.Sprintf("e2e-external-lb-test-%s", framework.RunId)
			requestedIP, err = framework.CreateGCEStaticIP(staticIPName)
			defer func() {
				if staticIPName != "" {
					// Release GCE static IP - this is not kube-managed and will not be automatically released.
					if err := framework.DeleteGCEStaticIP(staticIPName); err != nil {
						framework.Logf("failed to release static IP %s: %v", staticIPName, err)
					}
				}
			}()
			Expect(err).NotTo(HaveOccurred())
			framework.Logf("Allocated static load balancer IP: %s", requestedIP)
		}

		By("changing the TCP service to type=LoadBalancer")
		tcpService = jig.UpdateServiceOrFail(ns1, tcpService.Name, func(s *v1.Service) {
			s.Spec.LoadBalancerIP = requestedIP // will be "" if not applicable
			s.Spec.Type = v1.ServiceTypeLoadBalancer
		})

		if loadBalancerSupportsUDP {
			By("changing the UDP service to type=LoadBalancer")
			udpService = jig.UpdateServiceOrFail(ns2, udpService.Name, func(s *v1.Service) {
				s.Spec.Type = v1.ServiceTypeLoadBalancer
			})
		}
		serviceLBNames = append(serviceLBNames, cloudprovider.GetLoadBalancerName(tcpService))
		if loadBalancerSupportsUDP {
			serviceLBNames = append(serviceLBNames, cloudprovider.GetLoadBalancerName(udpService))
		}

		By("waiting for the TCP service to have a load balancer")
		// Wait for the load balancer to be created asynchronously
		tcpService = jig.WaitForLoadBalancerOrFail(ns1, tcpService.Name, loadBalancerCreateTimeout)
		jig.SanityCheckService(tcpService, v1.ServiceTypeLoadBalancer)
		if int(tcpService.Spec.Ports[0].NodePort) != tcpNodePort {
			framework.Failf("TCP Spec.Ports[0].NodePort changed (%d -> %d) when not expected", tcpNodePort, tcpService.Spec.Ports[0].NodePort)
		}
		if requestedIP != "" && framework.GetIngressPoint(&tcpService.Status.LoadBalancer.Ingress[0]) != requestedIP {
			framework.Failf("unexpected TCP Status.LoadBalancer.Ingress (expected %s, got %s)", requestedIP, framework.GetIngressPoint(&tcpService.Status.LoadBalancer.Ingress[0]))
		}
		tcpIngressIP := framework.GetIngressPoint(&tcpService.Status.LoadBalancer.Ingress[0])
		framework.Logf("TCP load balancer: %s", tcpIngressIP)

		if framework.ProviderIs("gce", "gke") {
			// Do this as early as possible, which overrides the `defer` above.
			// This is mostly out of fear of leaking the IP in a timeout case
			// (as of this writing we're not 100% sure where the leaks are
			// coming from, so this is first-aid rather than surgery).
			By("demoting the static IP to ephemeral")
			if staticIPName != "" {
				// Deleting it after it is attached "demotes" it to an
				// ephemeral IP, which can be auto-released.
				if err := framework.DeleteGCEStaticIP(staticIPName); err != nil {
					framework.Failf("failed to release static IP %s: %v", staticIPName, err)
				}
				staticIPName = ""
			}
		}

		var udpIngressIP string
		if loadBalancerSupportsUDP {
			By("waiting for the UDP service to have a load balancer")
			// 2nd one should be faster since they ran in parallel.
			udpService = jig.WaitForLoadBalancerOrFail(ns2, udpService.Name, loadBalancerCreateTimeout)
			jig.SanityCheckService(udpService, v1.ServiceTypeLoadBalancer)
			if int(udpService.Spec.Ports[0].NodePort) != udpNodePort {
				framework.Failf("UDP Spec.Ports[0].NodePort changed (%d -> %d) when not expected", udpNodePort, udpService.Spec.Ports[0].NodePort)
			}
			udpIngressIP = framework.GetIngressPoint(&udpService.Status.LoadBalancer.Ingress[0])
			framework.Logf("UDP load balancer: %s", udpIngressIP)

			By("verifying that TCP and UDP use different load balancers")
			if tcpIngressIP == udpIngressIP {
				framework.Failf("Load balancers are not different: %s", framework.GetIngressPoint(&tcpService.Status.LoadBalancer.Ingress[0]))
			}
		}

		By("hitting the TCP service's NodePort")
		jig.TestReachableHTTP(nodeIP, tcpNodePort, framework.KubeProxyLagTimeout)

		By("hitting the UDP service's NodePort")
		jig.TestReachableUDP(nodeIP, udpNodePort, framework.KubeProxyLagTimeout)

		By("hitting the TCP service's LoadBalancer")
		jig.TestReachableHTTP(tcpIngressIP, svcPort, loadBalancerLagTimeout)

		if loadBalancerSupportsUDP {
			By("hitting the UDP service's LoadBalancer")
			jig.TestReachableUDP(udpIngressIP, svcPort, loadBalancerLagTimeout)
		}

		// Change the services' node ports.

		By("changing the TCP service's NodePort")
		tcpService = jig.ChangeServiceNodePortOrFail(ns1, tcpService.Name, tcpNodePort)
		jig.SanityCheckService(tcpService, v1.ServiceTypeLoadBalancer)
		tcpNodePortOld := tcpNodePort
		tcpNodePort = int(tcpService.Spec.Ports[0].NodePort)
		if tcpNodePort == tcpNodePortOld {
			framework.Failf("TCP Spec.Ports[0].NodePort (%d) did not change", tcpNodePort)
		}
		if framework.GetIngressPoint(&tcpService.Status.LoadBalancer.Ingress[0]) != tcpIngressIP {
			framework.Failf("TCP Status.LoadBalancer.Ingress changed (%s -> %s) when not expected", tcpIngressIP, framework.GetIngressPoint(&tcpService.Status.LoadBalancer.Ingress[0]))
		}
		framework.Logf("TCP node port: %d", tcpNodePort)

		By("changing the UDP service's NodePort")
		udpService = jig.ChangeServiceNodePortOrFail(ns2, udpService.Name, udpNodePort)
		if loadBalancerSupportsUDP {
			jig.SanityCheckService(udpService, v1.ServiceTypeLoadBalancer)
		} else {
			jig.SanityCheckService(udpService, v1.ServiceTypeNodePort)
		}
		udpNodePortOld := udpNodePort
		udpNodePort = int(udpService.Spec.Ports[0].NodePort)
		if udpNodePort == udpNodePortOld {
			framework.Failf("UDP Spec.Ports[0].NodePort (%d) did not change", udpNodePort)
		}
		if loadBalancerSupportsUDP && framework.GetIngressPoint(&udpService.Status.LoadBalancer.Ingress[0]) != udpIngressIP {
			framework.Failf("UDP Status.LoadBalancer.Ingress changed (%s -> %s) when not expected", udpIngressIP, framework.GetIngressPoint(&udpService.Status.LoadBalancer.Ingress[0]))
		}
		framework.Logf("UDP node port: %d", udpNodePort)

		By("hitting the TCP service's new NodePort")
		jig.TestReachableHTTP(nodeIP, tcpNodePort, framework.KubeProxyLagTimeout)

		By("hitting the UDP service's new NodePort")
		jig.TestReachableUDP(nodeIP, udpNodePort, framework.KubeProxyLagTimeout)

		By("checking the old TCP NodePort is closed")
		jig.TestNotReachableHTTP(nodeIP, tcpNodePortOld, framework.KubeProxyLagTimeout)

		By("checking the old UDP NodePort is closed")
		jig.TestNotReachableUDP(nodeIP, udpNodePortOld, framework.KubeProxyLagTimeout)

		By("hitting the TCP service's LoadBalancer")
		jig.TestReachableHTTP(tcpIngressIP, svcPort, loadBalancerLagTimeout)

		if loadBalancerSupportsUDP {
			By("hitting the UDP service's LoadBalancer")
			jig.TestReachableUDP(udpIngressIP, svcPort, loadBalancerLagTimeout)
		}

		// Change the services' main ports.

		By("changing the TCP service's port")
		tcpService = jig.UpdateServiceOrFail(ns1, tcpService.Name, func(s *v1.Service) {
			s.Spec.Ports[0].Port++
		})
		jig.SanityCheckService(tcpService, v1.ServiceTypeLoadBalancer)
		svcPortOld := svcPort
		svcPort = int(tcpService.Spec.Ports[0].Port)
		if svcPort == svcPortOld {
			framework.Failf("TCP Spec.Ports[0].Port (%d) did not change", svcPort)
		}
		if int(tcpService.Spec.Ports[0].NodePort) != tcpNodePort {
			framework.Failf("TCP Spec.Ports[0].NodePort (%d) changed", tcpService.Spec.Ports[0].NodePort)
		}
		if framework.GetIngressPoint(&tcpService.Status.LoadBalancer.Ingress[0]) != tcpIngressIP {
			framework.Failf("TCP Status.LoadBalancer.Ingress changed (%s -> %s) when not expected", tcpIngressIP, framework.GetIngressPoint(&tcpService.Status.LoadBalancer.Ingress[0]))
		}

		By("changing the UDP service's port")
		udpService = jig.UpdateServiceOrFail(ns2, udpService.Name, func(s *v1.Service) {
			s.Spec.Ports[0].Port++
		})
		if loadBalancerSupportsUDP {
			jig.SanityCheckService(udpService, v1.ServiceTypeLoadBalancer)
		} else {
			jig.SanityCheckService(udpService, v1.ServiceTypeNodePort)
		}
		if int(udpService.Spec.Ports[0].Port) != svcPort {
			framework.Failf("UDP Spec.Ports[0].Port (%d) did not change", udpService.Spec.Ports[0].Port)
		}
		if int(udpService.Spec.Ports[0].NodePort) != udpNodePort {
			framework.Failf("UDP Spec.Ports[0].NodePort (%d) changed", udpService.Spec.Ports[0].NodePort)
		}
		if loadBalancerSupportsUDP && framework.GetIngressPoint(&udpService.Status.LoadBalancer.Ingress[0]) != udpIngressIP {
			framework.Failf("UDP Status.LoadBalancer.Ingress changed (%s -> %s) when not expected", udpIngressIP, framework.GetIngressPoint(&udpService.Status.LoadBalancer.Ingress[0]))
		}

		framework.Logf("service port (TCP and UDP): %d", svcPort)

		By("hitting the TCP service's NodePort")
		jig.TestReachableHTTP(nodeIP, tcpNodePort, framework.KubeProxyLagTimeout)

		By("hitting the UDP service's NodePort")
		jig.TestReachableUDP(nodeIP, udpNodePort, framework.KubeProxyLagTimeout)

		By("hitting the TCP service's LoadBalancer")
		jig.TestReachableHTTP(tcpIngressIP, svcPort, loadBalancerCreateTimeout) // this may actually recreate the LB

		if loadBalancerSupportsUDP {
			By("hitting the UDP service's LoadBalancer")
			jig.TestReachableUDP(udpIngressIP, svcPort, loadBalancerCreateTimeout) // this may actually recreate the LB)
		}

		// Change the services back to ClusterIP.

		By("changing TCP service back to type=ClusterIP")
		tcpService = jig.UpdateServiceOrFail(ns1, tcpService.Name, func(s *v1.Service) {
			s.Spec.Type = v1.ServiceTypeClusterIP
			s.Spec.Ports[0].NodePort = 0
		})
		// Wait for the load balancer to be destroyed asynchronously
		tcpService = jig.WaitForLoadBalancerDestroyOrFail(ns1, tcpService.Name, tcpIngressIP, svcPort, loadBalancerCreateTimeout)
		jig.SanityCheckService(tcpService, v1.ServiceTypeClusterIP)

		By("changing UDP service back to type=ClusterIP")
		udpService = jig.UpdateServiceOrFail(ns2, udpService.Name, func(s *v1.Service) {
			s.Spec.Type = v1.ServiceTypeClusterIP
			s.Spec.Ports[0].NodePort = 0
		})
		if loadBalancerSupportsUDP {
			// Wait for the load balancer to be destroyed asynchronously
			udpService = jig.WaitForLoadBalancerDestroyOrFail(ns2, udpService.Name, udpIngressIP, svcPort, loadBalancerCreateTimeout)
			jig.SanityCheckService(udpService, v1.ServiceTypeClusterIP)
		}

		By("checking the TCP NodePort is closed")
		jig.TestNotReachableHTTP(nodeIP, tcpNodePort, framework.KubeProxyLagTimeout)

		By("checking the UDP NodePort is closed")
		jig.TestNotReachableUDP(nodeIP, udpNodePort, framework.KubeProxyLagTimeout)

		By("checking the TCP LoadBalancer is closed")
		jig.TestNotReachableHTTP(tcpIngressIP, svcPort, loadBalancerLagTimeout)

		if loadBalancerSupportsUDP {
			By("checking the UDP LoadBalancer is closed")
			jig.TestNotReachableUDP(udpIngressIP, svcPort, loadBalancerLagTimeout)
		}
	})

	It("should be able to change the type from ExternalName to ClusterIP", func() {
		serviceName := "externalname-service"
		ns := f.Namespace.Name
		jig := framework.NewServiceTestJig(cs, serviceName)

		By("creating a service " + serviceName + " with the type=ExternalName in namespace " + ns)
		externalNameService := jig.CreateExternalNameServiceOrFail(ns, nil)
		defer func() {
			framework.Logf("Cleaning up the ExternalName to ClusterIP test service")
			err := cs.CoreV1().Services(ns).Delete(serviceName, nil)
			Expect(err).NotTo(HaveOccurred())
		}()
		jig.SanityCheckService(externalNameService, v1.ServiceTypeExternalName)
		By("changing the ExternalName service to type=ClusterIP")
		clusterIPService := jig.UpdateServiceOrFail(ns, externalNameService.Name, func(s *v1.Service) {
			s.Spec.Type = v1.ServiceTypeClusterIP
			s.Spec.ExternalName = ""
			s.Spec.Ports = []v1.ServicePort{
				{Port: 80, Name: "http", Protocol: "TCP"},
			}
		})
		jig.SanityCheckService(clusterIPService, v1.ServiceTypeClusterIP)
	})

	It("should be able to change the type from ExternalName to NodePort", func() {
		serviceName := "externalname-service"
		ns := f.Namespace.Name
		jig := framework.NewServiceTestJig(cs, serviceName)

		By("creating a service " + serviceName + " with the type=ExternalName in namespace " + ns)
		externalNameService := jig.CreateExternalNameServiceOrFail(ns, nil)
		defer func() {
			framework.Logf("Cleaning up the ExternalName to NodePort test service")
			err := cs.CoreV1().Services(ns).Delete(serviceName, nil)
			Expect(err).NotTo(HaveOccurred())
		}()
		jig.SanityCheckService(externalNameService, v1.ServiceTypeExternalName)
		By("changing the ExternalName service to type=NodePort")
		nodePortService := jig.UpdateServiceOrFail(ns, externalNameService.Name, func(s *v1.Service) {
			s.Spec.Type = v1.ServiceTypeNodePort
			s.Spec.ExternalName = ""
			s.Spec.Ports = []v1.ServicePort{
				{Port: 80, Name: "http", Protocol: "TCP"},
			}
		})
		jig.SanityCheckService(nodePortService, v1.ServiceTypeNodePort)
	})

	It("should be able to change the type from ClusterIP to ExternalName", func() {
		serviceName := "clusterip-service"
		ns := f.Namespace.Name
		jig := framework.NewServiceTestJig(cs, serviceName)

		By("creating a service " + serviceName + " with the type=ClusterIP in namespace " + ns)
		clusterIPService := jig.CreateTCPServiceOrFail(ns, nil)
		defer func() {
			framework.Logf("Cleaning up the ClusterIP to ExternalName test service")
			err := cs.CoreV1().Services(ns).Delete(serviceName, nil)
			Expect(err).NotTo(HaveOccurred())
		}()
		jig.SanityCheckService(clusterIPService, v1.ServiceTypeClusterIP)
		By("changing the ClusterIP service to type=ExternalName")
		externalNameService := jig.UpdateServiceOrFail(ns, clusterIPService.Name, func(s *v1.Service) {
			s.Spec.Type = v1.ServiceTypeExternalName
			s.Spec.ExternalName = "foo.example.com"
			s.Spec.ClusterIP = ""
		})
		jig.SanityCheckService(externalNameService, v1.ServiceTypeExternalName)
	})

	It("should be able to change the type from NodePort to ExternalName", func() {
		serviceName := "nodeport-service"
		ns := f.Namespace.Name
		jig := framework.NewServiceTestJig(cs, serviceName)

		By("creating a service " + serviceName + " with the type=NodePort in namespace " + ns)
		nodePortService := jig.CreateTCPServiceOrFail(ns, func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeNodePort
		})
		defer func() {
			framework.Logf("Cleaning up the NodePort to ExternalName test service")
			err := cs.CoreV1().Services(ns).Delete(serviceName, nil)
			Expect(err).NotTo(HaveOccurred())
		}()
		jig.SanityCheckService(nodePortService, v1.ServiceTypeNodePort)
		By("changing the NodePort service to type=ExternalName")
		externalNameService := jig.UpdateServiceOrFail(ns, nodePortService.Name, func(s *v1.Service) {
			s.Spec.Type = v1.ServiceTypeExternalName
			s.Spec.ExternalName = "foo.example.com"
			s.Spec.ClusterIP = ""
			s.Spec.Ports[0].NodePort = 0
		})
		jig.SanityCheckService(externalNameService, v1.ServiceTypeExternalName)
	})

	It("should use same NodePort with same port but different protocols", func() {
		serviceName := "nodeports"
		ns := f.Namespace.Name

		t := framework.NewServerTest(cs, ns, serviceName)
		defer func() {
			defer GinkgoRecover()
			errs := t.Cleanup()
			if len(errs) != 0 {
				framework.Failf("errors in cleanup: %v", errs)
			}
		}()

		By("creating service " + serviceName + " with same NodePort but different protocols in namespace " + ns)
		service := &v1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      t.ServiceName,
				Namespace: t.Namespace,
			},
			Spec: v1.ServiceSpec{
				Selector: t.Labels,
				Type:     v1.ServiceTypeNodePort,
				Ports: []v1.ServicePort{
					{
						Name:     "tcp-port",
						Port:     53,
						Protocol: v1.ProtocolTCP,
					},
					{
						Name:     "udp-port",
						Port:     53,
						Protocol: v1.ProtocolUDP,
					},
				},
			},
		}
		result, err := t.CreateService(service)
		Expect(err).NotTo(HaveOccurred())

		if len(result.Spec.Ports) != 2 {
			framework.Failf("got unexpected len(Spec.Ports) for new service: %v", result)
		}
		if result.Spec.Ports[0].NodePort != result.Spec.Ports[1].NodePort {
			framework.Failf("should use same NodePort for new service: %v", result)
		}
	})

	It("should prevent NodePort collisions", func() {
		// TODO: use the ServiceTestJig here
		baseName := "nodeport-collision-"
		serviceName1 := baseName + "1"
		serviceName2 := baseName + "2"
		ns := f.Namespace.Name

		t := framework.NewServerTest(cs, ns, serviceName1)
		defer func() {
			defer GinkgoRecover()
			errs := t.Cleanup()
			if len(errs) != 0 {
				framework.Failf("errors in cleanup: %v", errs)
			}
		}()

		By("creating service " + serviceName1 + " with type NodePort in namespace " + ns)
		service := t.BuildServiceSpec()
		service.Spec.Type = v1.ServiceTypeNodePort
		result, err := t.CreateService(service)
		Expect(err).NotTo(HaveOccurred())

		if result.Spec.Type != v1.ServiceTypeNodePort {
			framework.Failf("got unexpected Spec.Type for new service: %v", result)
		}
		if len(result.Spec.Ports) != 1 {
			framework.Failf("got unexpected len(Spec.Ports) for new service: %v", result)
		}
		port := result.Spec.Ports[0]
		if port.NodePort == 0 {
			framework.Failf("got unexpected Spec.Ports[0].NodePort for new service: %v", result)
		}

		By("creating service " + serviceName2 + " with conflicting NodePort")
		service2 := t.BuildServiceSpec()
		service2.Name = serviceName2
		service2.Spec.Type = v1.ServiceTypeNodePort
		service2.Spec.Ports[0].NodePort = port.NodePort
		result2, err := t.CreateService(service2)
		if err == nil {
			framework.Failf("Created service with conflicting NodePort: %v", result2)
		}
		expectedErr := fmt.Sprintf("%d.*port is already allocated", port.NodePort)
		Expect(fmt.Sprintf("%v", err)).To(MatchRegexp(expectedErr))

		By("deleting service " + serviceName1 + " to release NodePort")
		err = t.DeleteService(serviceName1)
		Expect(err).NotTo(HaveOccurred())

		By("creating service " + serviceName2 + " with no-longer-conflicting NodePort")
		_, err = t.CreateService(service2)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should check NodePort out-of-range", func() {
		// TODO: use the ServiceTestJig here
		serviceName := "nodeport-range-test"
		ns := f.Namespace.Name

		t := framework.NewServerTest(cs, ns, serviceName)
		defer func() {
			defer GinkgoRecover()
			errs := t.Cleanup()
			if len(errs) != 0 {
				framework.Failf("errors in cleanup: %v", errs)
			}
		}()

		service := t.BuildServiceSpec()
		service.Spec.Type = v1.ServiceTypeNodePort

		By("creating service " + serviceName + " with type NodePort in namespace " + ns)
		service, err := t.CreateService(service)
		Expect(err).NotTo(HaveOccurred())

		if service.Spec.Type != v1.ServiceTypeNodePort {
			framework.Failf("got unexpected Spec.Type for new service: %v", service)
		}
		if len(service.Spec.Ports) != 1 {
			framework.Failf("got unexpected len(Spec.Ports) for new service: %v", service)
		}
		port := service.Spec.Ports[0]
		if port.NodePort == 0 {
			framework.Failf("got unexpected Spec.Ports[0].nodePort for new service: %v", service)
		}
		if !framework.ServiceNodePortRange.Contains(int(port.NodePort)) {
			framework.Failf("got unexpected (out-of-range) port for new service: %v", service)
		}

		outOfRangeNodePort := 0
		rand.Seed(time.Now().UTC().UnixNano())
		for {
			outOfRangeNodePort = 1 + rand.Intn(65535)
			if !framework.ServiceNodePortRange.Contains(outOfRangeNodePort) {
				break
			}
		}
		By(fmt.Sprintf("changing service "+serviceName+" to out-of-range NodePort %d", outOfRangeNodePort))
		result, err := framework.UpdateService(cs, ns, serviceName, func(s *v1.Service) {
			s.Spec.Ports[0].NodePort = int32(outOfRangeNodePort)
		})
		if err == nil {
			framework.Failf("failed to prevent update of service with out-of-range NodePort: %v", result)
		}
		expectedErr := fmt.Sprintf("%d.*port is not in the valid range", outOfRangeNodePort)
		Expect(fmt.Sprintf("%v", err)).To(MatchRegexp(expectedErr))

		By("deleting original service " + serviceName)
		err = t.DeleteService(serviceName)
		Expect(err).NotTo(HaveOccurred())

		By(fmt.Sprintf("creating service "+serviceName+" with out-of-range NodePort %d", outOfRangeNodePort))
		service = t.BuildServiceSpec()
		service.Spec.Type = v1.ServiceTypeNodePort
		service.Spec.Ports[0].NodePort = int32(outOfRangeNodePort)
		service, err = t.CreateService(service)
		if err == nil {
			framework.Failf("failed to prevent create of service with out-of-range NodePort (%d): %v", outOfRangeNodePort, service)
		}
		Expect(fmt.Sprintf("%v", err)).To(MatchRegexp(expectedErr))
	})

	It("should release NodePorts on delete", func() {
		// TODO: use the ServiceTestJig here
		serviceName := "nodeport-reuse"
		ns := f.Namespace.Name

		t := framework.NewServerTest(cs, ns, serviceName)
		defer func() {
			defer GinkgoRecover()
			errs := t.Cleanup()
			if len(errs) != 0 {
				framework.Failf("errors in cleanup: %v", errs)
			}
		}()

		service := t.BuildServiceSpec()
		service.Spec.Type = v1.ServiceTypeNodePort

		By("creating service " + serviceName + " with type NodePort in namespace " + ns)
		service, err := t.CreateService(service)
		Expect(err).NotTo(HaveOccurred())

		if service.Spec.Type != v1.ServiceTypeNodePort {
			framework.Failf("got unexpected Spec.Type for new service: %v", service)
		}
		if len(service.Spec.Ports) != 1 {
			framework.Failf("got unexpected len(Spec.Ports) for new service: %v", service)
		}
		port := service.Spec.Ports[0]
		if port.NodePort == 0 {
			framework.Failf("got unexpected Spec.Ports[0].nodePort for new service: %v", service)
		}
		if !framework.ServiceNodePortRange.Contains(int(port.NodePort)) {
			framework.Failf("got unexpected (out-of-range) port for new service: %v", service)
		}
		nodePort := port.NodePort

		By("deleting original service " + serviceName)
		err = t.DeleteService(serviceName)
		Expect(err).NotTo(HaveOccurred())

		hostExec := framework.LaunchHostExecPod(f.ClientSet, f.Namespace.Name, "hostexec")
		cmd := fmt.Sprintf(`! ss -ant46 'sport = :%d' | tail -n +2 | grep LISTEN`, nodePort)
		var stdout string
		if pollErr := wait.PollImmediate(framework.Poll, framework.KubeProxyLagTimeout, func() (bool, error) {
			var err error
			stdout, err = framework.RunHostCmd(hostExec.Namespace, hostExec.Name, cmd)
			if err != nil {
				framework.Logf("expected node port (%d) to not be in use, stdout: %v", nodePort, stdout)
				return false, nil
			}
			return true, nil
		}); pollErr != nil {
			framework.Failf("expected node port (%d) to not be in use in %v, stdout: %v", nodePort, framework.KubeProxyLagTimeout, stdout)
		}

		By(fmt.Sprintf("creating service "+serviceName+" with same NodePort %d", nodePort))
		service = t.BuildServiceSpec()
		service.Spec.Type = v1.ServiceTypeNodePort
		service.Spec.Ports[0].NodePort = nodePort
		service, err = t.CreateService(service)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should create endpoints for unready pods", func() {
		serviceName := "tolerate-unready"
		ns := f.Namespace.Name

		t := framework.NewServerTest(cs, ns, serviceName)
		defer func() {
			defer GinkgoRecover()
			errs := t.Cleanup()
			if len(errs) != 0 {
				framework.Failf("errors in cleanup: %v", errs)
			}
		}()

		t.Name = "slow-terminating-unready-pod"
		t.Image = imageutils.GetE2EImage(imageutils.Netexec)
		port := 80
		terminateSeconds := int64(600)

		service := &v1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:        t.ServiceName,
				Namespace:   t.Namespace,
				Annotations: map[string]string{endpoint.TolerateUnreadyEndpointsAnnotation: "true"},
			},
			Spec: v1.ServiceSpec{
				Selector: t.Labels,
				Ports: []v1.ServicePort{{
					Name:       "http",
					Port:       int32(port),
					TargetPort: intstr.FromInt(port),
				}},
			},
		}
		rcSpec := framework.RcByNameContainer(t.Name, 1, t.Image, t.Labels, v1.Container{
			Args:  []string{fmt.Sprintf("--http-port=%d", port)},
			Name:  t.Name,
			Image: t.Image,
			Ports: []v1.ContainerPort{{ContainerPort: int32(port), Protocol: v1.ProtocolTCP}},
			ReadinessProbe: &v1.Probe{
				Handler: v1.Handler{
					Exec: &v1.ExecAction{
						Command: []string{"/bin/false"},
					},
				},
			},
			Lifecycle: &v1.Lifecycle{
				PreStop: &v1.Handler{
					Exec: &v1.ExecAction{
						Command: []string{"/bin/sleep", fmt.Sprintf("%d", terminateSeconds)},
					},
				},
			},
		}, nil)
		rcSpec.Spec.Template.Spec.TerminationGracePeriodSeconds = &terminateSeconds

		By(fmt.Sprintf("creating RC %v with selectors %v", rcSpec.Name, rcSpec.Spec.Selector))
		_, err := t.CreateRC(rcSpec)
		framework.ExpectNoError(err)

		By(fmt.Sprintf("creating Service %v with selectors %v", service.Name, service.Spec.Selector))
		_, err = t.CreateService(service)
		framework.ExpectNoError(err)

		By("Verifying pods for RC " + t.Name)
		framework.ExpectNoError(framework.VerifyPods(t.Client, t.Namespace, t.Name, false, 1))

		svcName := fmt.Sprintf("%v.%v.svc.cluster.local", serviceName, f.Namespace.Name)
		By("Waiting for endpoints of Service with DNS name " + svcName)

		execPodName := framework.CreateExecPodOrFail(f.ClientSet, f.Namespace.Name, "execpod-", nil)
		cmd := fmt.Sprintf("wget -qO- http://%s:%d/", svcName, port)
		var stdout string
		if pollErr := wait.PollImmediate(framework.Poll, framework.KubeProxyLagTimeout, func() (bool, error) {
			var err error
			stdout, err = framework.RunHostCmd(f.Namespace.Name, execPodName, cmd)
			if err != nil {
				framework.Logf("expected un-ready endpoint for Service %v, stdout: %v, err %v", t.Name, stdout, err)
				return false, nil
			}
			return true, nil
		}); pollErr != nil {
			framework.Failf("expected un-ready endpoint for Service %v within %v, stdout: %v", t.Name, framework.KubeProxyLagTimeout, stdout)
		}

		By("Scaling down replication controller to zero")
		framework.ScaleRC(f.ClientSet, f.InternalClientset, t.Namespace, rcSpec.Name, 0, false)

		By("Update service to not tolerate unready services")
		_, err = framework.UpdateService(f.ClientSet, t.Namespace, t.ServiceName, func(s *v1.Service) {
			s.ObjectMeta.Annotations[endpoint.TolerateUnreadyEndpointsAnnotation] = "false"
		})
		framework.ExpectNoError(err)

		By("Check if pod is unreachable")
		cmd = fmt.Sprintf("wget -qO- -T 2 http://%s:%d/; test \"$?\" -eq \"1\"", svcName, port)
		if pollErr := wait.PollImmediate(framework.Poll, framework.KubeProxyLagTimeout, func() (bool, error) {
			var err error
			stdout, err = framework.RunHostCmd(f.Namespace.Name, execPodName, cmd)
			if err != nil {
				framework.Logf("expected un-ready endpoint for Service %v, stdout: %v, err %v", t.Name, stdout, err)
				return false, nil
			}
			return true, nil
		}); pollErr != nil {
			framework.Failf("expected un-ready endpoint for Service %v within %v, stdout: %v", t.Name, framework.KubeProxyLagTimeout, stdout)
		}

		By("Update service to tolerate unready services again")
		_, err = framework.UpdateService(f.ClientSet, t.Namespace, t.ServiceName, func(s *v1.Service) {
			s.ObjectMeta.Annotations[endpoint.TolerateUnreadyEndpointsAnnotation] = "true"
		})
		framework.ExpectNoError(err)

		By("Check if terminating pod is available through service")
		cmd = fmt.Sprintf("wget -qO- http://%s:%d/", svcName, port)
		if pollErr := wait.PollImmediate(framework.Poll, framework.KubeProxyLagTimeout, func() (bool, error) {
			var err error
			stdout, err = framework.RunHostCmd(f.Namespace.Name, execPodName, cmd)
			if err != nil {
				framework.Logf("expected un-ready endpoint for Service %v, stdout: %v, err %v", t.Name, stdout, err)
				return false, nil
			}
			return true, nil
		}); pollErr != nil {
			framework.Failf("expected un-ready endpoint for Service %v within %v, stdout: %v", t.Name, framework.KubeProxyLagTimeout, stdout)
		}

		By("Remove pods immediately")
		label := labels.SelectorFromSet(labels.Set(t.Labels))
		options := metav1.ListOptions{LabelSelector: label.String()}
		podClient := t.Client.Core().Pods(f.Namespace.Name)
		pods, err := podClient.List(options)
		if err != nil {
			framework.Logf("warning: error retrieving pods: %s", err)
		} else {
			for _, pod := range pods.Items {
				var gracePeriodSeconds int64 = 0
				err := podClient.Delete(pod.Name, &metav1.DeleteOptions{GracePeriodSeconds: &gracePeriodSeconds})
				if err != nil {
					framework.Logf("warning: error force deleting pod '%s': %s", pod.Name, err)
				}
			}
		}
	})

	It("should only allow access from service loadbalancer source ranges [Slow]", func() {
		// this feature currently supported only on GCE/GKE/AWS
		framework.SkipUnlessProviderIs("gce", "gke", "aws")

		loadBalancerLagTimeout := framework.LoadBalancerLagTimeoutDefault
		if framework.ProviderIs("aws") {
			loadBalancerLagTimeout = framework.LoadBalancerLagTimeoutAWS
		}
		loadBalancerCreateTimeout := framework.LoadBalancerCreateTimeoutDefault
		if nodes := framework.GetReadySchedulableNodesOrDie(cs); len(nodes.Items) > framework.LargeClusterMinNodesNumber {
			loadBalancerCreateTimeout = framework.LoadBalancerCreateTimeoutLarge
		}

		namespace := f.Namespace.Name
		serviceName := "lb-sourcerange"
		jig := framework.NewServiceTestJig(cs, serviceName)

		By("Prepare allow source ips")
		// prepare the exec pods
		// acceptPod are allowed to access the loadbalancer
		acceptPodName := framework.CreateExecPodOrFail(cs, namespace, "execpod-accept", nil)
		dropPodName := framework.CreateExecPodOrFail(cs, namespace, "execpod-drop", nil)

		acceptPod, err := cs.CoreV1().Pods(namespace).Get(acceptPodName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())
		dropPod, err := cs.CoreV1().Pods(namespace).Get(dropPodName, metav1.GetOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("creating a pod to be part of the service " + serviceName)
		// This container is an nginx container listening on port 80
		// See kubernetes/contrib/ingress/echoheaders/nginx.conf for content of response
		jig.RunOrFail(namespace, nil)
		// Create loadbalancer service with source range from node[0] and podAccept
		svc := jig.CreateTCPServiceOrFail(namespace, func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeLoadBalancer
			svc.Spec.LoadBalancerSourceRanges = []string{acceptPod.Status.PodIP + "/32"}
		})

		// Clean up loadbalancer service
		defer func() {
			jig.UpdateServiceOrFail(svc.Namespace, svc.Name, func(svc *v1.Service) {
				svc.Spec.Type = v1.ServiceTypeNodePort
				svc.Spec.LoadBalancerSourceRanges = nil
			})
			Expect(cs.CoreV1().Services(svc.Namespace).Delete(svc.Name, nil)).NotTo(HaveOccurred())
		}()

		svc = jig.WaitForLoadBalancerOrFail(namespace, serviceName, loadBalancerCreateTimeout)
		jig.SanityCheckService(svc, v1.ServiceTypeLoadBalancer)

		// timeout when we haven't just created the load balancer
		normalReachabilityTimeout := 2 * time.Minute

		By("check reachability from different sources")
		svcIP := framework.GetIngressPoint(&svc.Status.LoadBalancer.Ingress[0])
		// Wait longer as this is our first request after creation.  We can't check using a separate method,
		// because the LB should only be reachable from the "accept" pod
		framework.CheckReachabilityFromPod(true, loadBalancerLagTimeout, namespace, acceptPodName, svcIP)
		framework.CheckReachabilityFromPod(false, normalReachabilityTimeout, namespace, dropPodName, svcIP)

		By("Update service LoadBalancerSourceRange and check reachability")
		jig.UpdateServiceOrFail(svc.Namespace, svc.Name, func(svc *v1.Service) {
			// only allow access from dropPod
			svc.Spec.LoadBalancerSourceRanges = []string{dropPod.Status.PodIP + "/32"}
		})
		framework.CheckReachabilityFromPod(false, normalReachabilityTimeout, namespace, acceptPodName, svcIP)
		framework.CheckReachabilityFromPod(true, normalReachabilityTimeout, namespace, dropPodName, svcIP)

		By("Delete LoadBalancerSourceRange field and check reachability")
		jig.UpdateServiceOrFail(svc.Namespace, svc.Name, func(svc *v1.Service) {
			svc.Spec.LoadBalancerSourceRanges = nil
		})
		framework.CheckReachabilityFromPod(true, normalReachabilityTimeout, namespace, acceptPodName, svcIP)
		framework.CheckReachabilityFromPod(true, normalReachabilityTimeout, namespace, dropPodName, svcIP)
	})

	It("should be able to create an internal type load balancer [Slow]", func() {
		framework.SkipUnlessProviderIs("azure", "gke", "gce")

		createTimeout := framework.LoadBalancerCreateTimeoutDefault
		pollInterval := framework.Poll * 10

		namespace := f.Namespace.Name
		serviceName := "lb-internal"
		jig := framework.NewServiceTestJig(cs, serviceName)

		By("creating pod to be part of service " + serviceName)
		jig.RunOrFail(namespace, nil)

		enableILB, disableILB := framework.EnableAndDisableInternalLB()

		isInternalEndpoint := func(lbIngress *v1.LoadBalancerIngress) bool {
			ingressEndpoint := framework.GetIngressPoint(lbIngress)
			// Needs update for providers using hostname as endpoint.
			return strings.HasPrefix(ingressEndpoint, "10.")
		}

		By("creating a service with type LoadBalancer and cloud specific Internal-LB annotation enabled")
		svc := jig.CreateTCPServiceOrFail(namespace, func(svc *v1.Service) {
			svc.Spec.Type = v1.ServiceTypeLoadBalancer
			enableILB(svc)
		})
		svc = jig.WaitForLoadBalancerOrFail(namespace, serviceName, createTimeout)
		jig.SanityCheckService(svc, v1.ServiceTypeLoadBalancer)
		lbIngress := &svc.Status.LoadBalancer.Ingress[0]
		// should have an internal IP.
		Expect(isInternalEndpoint(lbIngress)).To(BeTrue())

		By("switching to external type LoadBalancer")
		svc = jig.UpdateServiceOrFail(namespace, serviceName, func(svc *v1.Service) {
			disableILB(svc)
		})
		framework.Logf("Waiting up to %v for service %q to have an external LoadBalancer", createTimeout, serviceName)
		if pollErr := wait.PollImmediate(pollInterval, createTimeout, func() (bool, error) {
			svc, err := jig.Client.Core().Services(namespace).Get(serviceName, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			lbIngress = &svc.Status.LoadBalancer.Ingress[0]
			return !isInternalEndpoint(lbIngress), nil
		}); pollErr != nil {
			framework.Failf("Loadbalancer IP not changed to external.")
		}
		// should have an external IP.
		jig.SanityCheckService(svc, v1.ServiceTypeLoadBalancer)
		Expect(isInternalEndpoint(lbIngress)).To(BeFalse())

		// GCE cannot test a specific IP because the test may not own it. This cloud specific condition
		// will be removed when GCP supports similar functionality.
		if framework.ProviderIs("azure") {
			By("switching back to interal type LoadBalancer, with static IP specified.")
			internalStaticIP := "10.240.11.11"
			svc = jig.UpdateServiceOrFail(namespace, serviceName, func(svc *v1.Service) {
				svc.Spec.LoadBalancerIP = internalStaticIP
				enableILB(svc)
			})
			framework.Logf("Waiting up to %v for service %q to have an internal LoadBalancer", createTimeout, serviceName)
			if pollErr := wait.PollImmediate(pollInterval, createTimeout, func() (bool, error) {
				svc, err := jig.Client.Core().Services(namespace).Get(serviceName, metav1.GetOptions{})
				if err != nil {
					return false, err
				}
				lbIngress = &svc.Status.LoadBalancer.Ingress[0]
				return isInternalEndpoint(lbIngress), nil
			}); pollErr != nil {
				framework.Failf("Loadbalancer IP not changed to internal.")
			}
			// should have the given static internal IP.
			jig.SanityCheckService(svc, v1.ServiceTypeLoadBalancer)
			Expect(framework.GetIngressPoint(lbIngress)).To(Equal(internalStaticIP))
		}

		By("switching to ClusterIP type to destroy loadbalancer")
		jig.ChangeServiceType(svc.Namespace, svc.Name, v1.ServiceTypeClusterIP, createTimeout)
	})
})

var _ = SIGDescribe("ESIPP [Slow]", func() {
	f := framework.NewDefaultFramework("esipp")
	loadBalancerCreateTimeout := framework.LoadBalancerCreateTimeoutDefault

	var cs clientset.Interface
	serviceLBNames := []string{}

	BeforeEach(func() {
		// requires cloud load-balancer support - this feature currently supported only on GCE/GKE
		framework.SkipUnlessProviderIs("gce", "gke")

		cs = f.ClientSet
		if nodes := framework.GetReadySchedulableNodesOrDie(cs); len(nodes.Items) > framework.LargeClusterMinNodesNumber {
			loadBalancerCreateTimeout = framework.LoadBalancerCreateTimeoutLarge
		}
	})

	AfterEach(func() {
		if CurrentGinkgoTestDescription().Failed {
			framework.DescribeSvc(f.Namespace.Name)
		}
		for _, lb := range serviceLBNames {
			framework.Logf("cleaning gce resource for %s", lb)
			framework.CleanupServiceGCEResources(cs, lb, framework.TestContext.CloudConfig.Zone)
		}
		//reset serviceLBNames
		serviceLBNames = []string{}
	})

	It("should work for type=LoadBalancer", func() {
		namespace := f.Namespace.Name
		serviceName := "external-local"
		jig := framework.NewServiceTestJig(cs, serviceName)

		svc := jig.CreateOnlyLocalLoadBalancerService(namespace, serviceName, loadBalancerCreateTimeout, true, nil)
		serviceLBNames = append(serviceLBNames, cloudprovider.GetLoadBalancerName(svc))
		healthCheckNodePort := int(svc.Spec.HealthCheckNodePort)
		if healthCheckNodePort == 0 {
			framework.Failf("Service HealthCheck NodePort was not allocated")
		}
		defer func() {
			jig.ChangeServiceType(svc.Namespace, svc.Name, v1.ServiceTypeClusterIP, loadBalancerCreateTimeout)

			// Make sure we didn't leak the health check node port.
			threshold := 2
			for _, ips := range jig.GetEndpointNodes(svc) {
				Expect(jig.TestHTTPHealthCheckNodePort(ips[0], healthCheckNodePort, "/healthz", framework.KubeProxyEndpointLagTimeout, false, threshold)).NotTo(HaveOccurred())
			}
			Expect(cs.CoreV1().Services(svc.Namespace).Delete(svc.Name, nil)).NotTo(HaveOccurred())
		}()

		svcTCPPort := int(svc.Spec.Ports[0].Port)
		ingressIP := framework.GetIngressPoint(&svc.Status.LoadBalancer.Ingress[0])

		By("reading clientIP using the TCP service's service port via its external VIP")
		content := jig.GetHTTPContent(ingressIP, svcTCPPort, framework.KubeProxyLagTimeout, "/clientip")
		clientIP := content.String()
		framework.Logf("ClientIP detected by target pod using VIP:SvcPort is %s", clientIP)

		By("checking if Source IP is preserved")
		if strings.HasPrefix(clientIP, "10.") {
			framework.Failf("Source IP was NOT preserved")
		}
	})

	It("should work for type=NodePort", func() {
		namespace := f.Namespace.Name
		serviceName := "external-local"
		jig := framework.NewServiceTestJig(cs, serviceName)

		svc := jig.CreateOnlyLocalNodePortService(namespace, serviceName, true)
		defer func() {
			Expect(cs.CoreV1().Services(svc.Namespace).Delete(svc.Name, nil)).NotTo(HaveOccurred())
		}()

		tcpNodePort := int(svc.Spec.Ports[0].NodePort)
		endpointsNodeMap := jig.GetEndpointNodes(svc)
		path := "/clientip"

		for nodeName, nodeIPs := range endpointsNodeMap {
			nodeIP := nodeIPs[0]
			By(fmt.Sprintf("reading clientIP using the TCP service's NodePort, on node %v: %v%v%v", nodeName, nodeIP, tcpNodePort, path))
			content := jig.GetHTTPContent(nodeIP, tcpNodePort, framework.KubeProxyLagTimeout, path)
			clientIP := content.String()
			framework.Logf("ClientIP detected by target pod using NodePort is %s", clientIP)
			if strings.HasPrefix(clientIP, "10.") {
				framework.Failf("Source IP was NOT preserved")
			}
		}
	})

	It("should only target nodes with endpoints", func() {
		namespace := f.Namespace.Name
		serviceName := "external-local"
		jig := framework.NewServiceTestJig(cs, serviceName)
		nodes := jig.GetNodes(framework.MaxNodesForEndpointsTests)

		svc := jig.CreateOnlyLocalLoadBalancerService(namespace, serviceName, loadBalancerCreateTimeout, false,
			func(svc *v1.Service) {
				// Change service port to avoid collision with opened hostPorts
				// in other tests that run in parallel.
				if len(svc.Spec.Ports) != 0 {
					svc.Spec.Ports[0].TargetPort = intstr.FromInt(int(svc.Spec.Ports[0].Port))
					svc.Spec.Ports[0].Port = 8081
				}

			})
		serviceLBNames = append(serviceLBNames, cloudprovider.GetLoadBalancerName(svc))
		defer func() {
			jig.ChangeServiceType(svc.Namespace, svc.Name, v1.ServiceTypeClusterIP, loadBalancerCreateTimeout)
			Expect(cs.CoreV1().Services(svc.Namespace).Delete(svc.Name, nil)).NotTo(HaveOccurred())
		}()

		healthCheckNodePort := int(svc.Spec.HealthCheckNodePort)
		if healthCheckNodePort == 0 {
			framework.Failf("Service HealthCheck NodePort was not allocated")
		}

		ips := framework.CollectAddresses(nodes, v1.NodeExternalIP)

		ingressIP := framework.GetIngressPoint(&svc.Status.LoadBalancer.Ingress[0])
		svcTCPPort := int(svc.Spec.Ports[0].Port)

		threshold := 2
		path := "/healthz"
		for i := 0; i < len(nodes.Items); i++ {
			endpointNodeName := nodes.Items[i].Name

			By("creating a pod to be part of the service " + serviceName + " on node " + endpointNodeName)
			jig.RunOrFail(namespace, func(rc *v1.ReplicationController) {
				rc.Name = serviceName
				if endpointNodeName != "" {
					rc.Spec.Template.Spec.NodeName = endpointNodeName
				}
			})

			By(fmt.Sprintf("waiting for service endpoint on node %v", endpointNodeName))
			jig.WaitForEndpointOnNode(namespace, serviceName, endpointNodeName)

			// HealthCheck should pass only on the node where num(endpoints) > 0
			// All other nodes should fail the healthcheck on the service healthCheckNodePort
			for n, publicIP := range ips {
				// Make sure the loadbalancer picked up the health check change.
				// Confirm traffic can reach backend through LB before checking healthcheck nodeport.
				jig.TestReachableHTTP(ingressIP, svcTCPPort, framework.KubeProxyLagTimeout)
				expectedSuccess := nodes.Items[n].Name == endpointNodeName
				framework.Logf("Health checking %s, http://%s:%d%s, expectedSuccess %v", nodes.Items[n].Name, publicIP, healthCheckNodePort, path, expectedSuccess)
				Expect(jig.TestHTTPHealthCheckNodePort(publicIP, healthCheckNodePort, path, framework.KubeProxyEndpointLagTimeout, expectedSuccess, threshold)).NotTo(HaveOccurred())
			}
			framework.ExpectNoError(framework.DeleteRCAndPods(f.ClientSet, f.InternalClientset, namespace, serviceName))
		}
	})

	It("should work from pods", func() {
		namespace := f.Namespace.Name
		serviceName := "external-local"
		jig := framework.NewServiceTestJig(cs, serviceName)
		nodes := jig.GetNodes(framework.MaxNodesForEndpointsTests)

		svc := jig.CreateOnlyLocalLoadBalancerService(namespace, serviceName, loadBalancerCreateTimeout, true, nil)
		serviceLBNames = append(serviceLBNames, cloudprovider.GetLoadBalancerName(svc))
		defer func() {
			jig.ChangeServiceType(svc.Namespace, svc.Name, v1.ServiceTypeClusterIP, loadBalancerCreateTimeout)
			Expect(cs.CoreV1().Services(svc.Namespace).Delete(svc.Name, nil)).NotTo(HaveOccurred())
		}()

		ingressIP := framework.GetIngressPoint(&svc.Status.LoadBalancer.Ingress[0])
		path := fmt.Sprintf("%s:%d/clientip", ingressIP, int(svc.Spec.Ports[0].Port))
		nodeName := nodes.Items[0].Name
		podName := "execpod-sourceip"

		By(fmt.Sprintf("Creating %v on node %v", podName, nodeName))
		execPodName := framework.CreateExecPodOrFail(f.ClientSet, namespace, podName, func(pod *v1.Pod) {
			pod.Spec.NodeName = nodeName
		})
		defer func() {
			err := cs.CoreV1().Pods(namespace).Delete(execPodName, nil)
			Expect(err).NotTo(HaveOccurred())
		}()
		execPod, err := f.ClientSet.Core().Pods(namespace).Get(execPodName, metav1.GetOptions{})
		framework.ExpectNoError(err)

		framework.Logf("Waiting up to %v wget %v", framework.KubeProxyLagTimeout, path)
		cmd := fmt.Sprintf(`wget -T 30 -qO- %v`, path)

		var srcIP string
		By(fmt.Sprintf("Hitting external lb %v from pod %v on node %v", ingressIP, podName, nodeName))
		if pollErr := wait.PollImmediate(framework.Poll, framework.LoadBalancerCreateTimeoutDefault, func() (bool, error) {
			stdout, err := framework.RunHostCmd(execPod.Namespace, execPod.Name, cmd)
			if err != nil {
				framework.Logf("got err: %v, retry until timeout", err)
				return false, nil
			}
			srcIP = strings.TrimSpace(strings.Split(stdout, ":")[0])
			return srcIP == execPod.Status.PodIP, nil
		}); pollErr != nil {
			framework.Failf("Source IP not preserved from %v, expected '%v' got '%v'", podName, execPod.Status.PodIP, srcIP)
		}
	})

	It("should handle updates to ExternalTrafficPolicy field", func() {
		namespace := f.Namespace.Name
		serviceName := "external-local"
		jig := framework.NewServiceTestJig(cs, serviceName)

		nodes := jig.GetNodes(framework.MaxNodesForEndpointsTests)
		if len(nodes.Items) < 2 {
			framework.Failf("Need at least 2 nodes to verify source ip from a node without endpoint")
		}

		svc := jig.CreateOnlyLocalLoadBalancerService(namespace, serviceName, loadBalancerCreateTimeout, true, nil)
		serviceLBNames = append(serviceLBNames, cloudprovider.GetLoadBalancerName(svc))
		defer func() {
			jig.ChangeServiceType(svc.Namespace, svc.Name, v1.ServiceTypeClusterIP, loadBalancerCreateTimeout)
			Expect(cs.CoreV1().Services(svc.Namespace).Delete(svc.Name, nil)).NotTo(HaveOccurred())
		}()

		// save the health check node port because it disappears when ESIPP is turned off.
		healthCheckNodePort := int(svc.Spec.HealthCheckNodePort)

		By("turning ESIPP off")
		svc = jig.UpdateServiceOrFail(svc.Namespace, svc.Name, func(svc *v1.Service) {
			svc.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyTypeCluster
		})
		if svc.Spec.HealthCheckNodePort > 0 {
			framework.Failf("Service HealthCheck NodePort still present")
		}

		endpointNodeMap := jig.GetEndpointNodes(svc)
		noEndpointNodeMap := map[string][]string{}
		for _, n := range nodes.Items {
			if _, ok := endpointNodeMap[n.Name]; ok {
				continue
			}
			noEndpointNodeMap[n.Name] = framework.GetNodeAddresses(&n, v1.NodeExternalIP)
		}

		svcTCPPort := int(svc.Spec.Ports[0].Port)
		svcNodePort := int(svc.Spec.Ports[0].NodePort)
		ingressIP := framework.GetIngressPoint(&svc.Status.LoadBalancer.Ingress[0])
		path := "/clientip"

		By(fmt.Sprintf("endpoints present on nodes %v, absent on nodes %v", endpointNodeMap, noEndpointNodeMap))
		for nodeName, nodeIPs := range noEndpointNodeMap {
			By(fmt.Sprintf("Checking %v (%v:%v%v) proxies to endpoints on another node", nodeName, nodeIPs[0], svcNodePort, path))
			jig.GetHTTPContent(nodeIPs[0], svcNodePort, framework.KubeProxyLagTimeout, path)
		}

		for nodeName, nodeIPs := range endpointNodeMap {
			By(fmt.Sprintf("checking kube-proxy health check fails on node with endpoint (%s), public IP %s", nodeName, nodeIPs[0]))
			var body bytes.Buffer
			var result bool
			var err error
			if pollErr := wait.PollImmediate(framework.Poll, framework.ServiceTestTimeout, func() (bool, error) {
				result, err = framework.TestReachableHTTPWithContent(nodeIPs[0], healthCheckNodePort, "/healthz", "", &body)
				return !result, nil
			}); pollErr != nil {
				framework.Failf("Kube-proxy still exposing health check on node %v:%v, after ESIPP was turned off. Last err %v, last body %v",
					nodeName, healthCheckNodePort, err, body.String())
			}
		}

		// Poll till kube-proxy re-adds the MASQUERADE rule on the node.
		By(fmt.Sprintf("checking source ip is NOT preserved through loadbalancer %v", ingressIP))
		var clientIP string
		pollErr := wait.PollImmediate(framework.Poll, framework.KubeProxyLagTimeout, func() (bool, error) {
			content := jig.GetHTTPContent(ingressIP, svcTCPPort, framework.KubeProxyLagTimeout, "/clientip")
			clientIP = content.String()
			if strings.HasPrefix(clientIP, "10.") {
				return true, nil
			}
			return false, nil
		})
		if pollErr != nil {
			framework.Failf("Source IP WAS preserved even after ESIPP turned off. Got %v, expected a ten-dot cluster ip.", clientIP)
		}

		// TODO: We need to attempt to create another service with the previously
		// allocated healthcheck nodePort. If the health check nodePort has been
		// freed, the new service creation will succeed, upon which we cleanup.
		// If the health check nodePort has NOT been freed, the new service
		// creation will fail.

		By("setting ExternalTraffic field back to OnlyLocal")
		svc = jig.UpdateServiceOrFail(svc.Namespace, svc.Name, func(svc *v1.Service) {
			svc.Spec.ExternalTrafficPolicy = v1.ServiceExternalTrafficPolicyTypeLocal
			// Request the same healthCheckNodePort as before, to test the user-requested allocation path
			svc.Spec.HealthCheckNodePort = int32(healthCheckNodePort)
		})
		pollErr = wait.PollImmediate(framework.Poll, framework.KubeProxyLagTimeout, func() (bool, error) {
			content := jig.GetHTTPContent(ingressIP, svcTCPPort, framework.KubeProxyLagTimeout, path)
			clientIP = content.String()
			By(fmt.Sprintf("Endpoint %v:%v%v returned client ip %v", ingressIP, svcTCPPort, path, clientIP))
			if !strings.HasPrefix(clientIP, "10.") {
				return true, nil
			}
			return false, nil
		})
		if pollErr != nil {
			framework.Failf("Source IP (%v) is not the client IP even after ESIPP turned on, expected a public IP.", clientIP)
		}
	})
})

func execSourceipTest(f *framework.Framework, c clientset.Interface, ns, nodeName, serviceIP string, servicePort int) (string, string) {
	framework.Logf("Creating an exec pod on node %v", nodeName)
	execPodName := framework.CreateExecPodOrFail(f.ClientSet, ns, fmt.Sprintf("execpod-sourceip-%s", nodeName), func(pod *v1.Pod) {
		pod.Spec.NodeName = nodeName
	})
	defer func() {
		framework.Logf("Cleaning up the exec pod")
		err := c.Core().Pods(ns).Delete(execPodName, nil)
		Expect(err).NotTo(HaveOccurred())
	}()
	execPod, err := f.ClientSet.Core().Pods(ns).Get(execPodName, metav1.GetOptions{})
	framework.ExpectNoError(err)

	var stdout string
	timeout := 2 * time.Minute
	framework.Logf("Waiting up to %v wget %s:%d", timeout, serviceIP, servicePort)
	cmd := fmt.Sprintf(`wget -T 30 -qO- %s:%d | grep client_address`, serviceIP, servicePort)
	for start := time.Now(); time.Since(start) < timeout; time.Sleep(2) {
		stdout, err = framework.RunHostCmd(execPod.Namespace, execPod.Name, cmd)
		if err != nil {
			framework.Logf("got err: %v, retry until timeout", err)
			continue
		}
		// Need to check output because wget -q might omit the error.
		if strings.TrimSpace(stdout) == "" {
			framework.Logf("got empty stdout, retry until timeout")
			continue
		}
		break
	}

	framework.ExpectNoError(err)

	// The stdout return from RunHostCmd seems to come with "\n", so TrimSpace is needed.
	// Desired stdout in this format: client_address=x.x.x.x
	outputs := strings.Split(strings.TrimSpace(stdout), "=")
	if len(outputs) != 2 {
		// Fail the test if output format is unexpected.
		framework.Failf("exec pod returned unexpected stdout format: [%v]\n", stdout)
	}
	return execPod.Status.PodIP, outputs[1]
}
