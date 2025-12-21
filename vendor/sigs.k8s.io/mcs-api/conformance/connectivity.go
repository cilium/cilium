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
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var _ = Describe("", func() {
	t := newTestDriver()

	BeforeEach(func() {
		t.autoExportService = false
	})

	Context("Connectivity to a service that is not exported", func() {
		It("should be inaccessible", Label(RequiredLabel), func() {
			AddReportEntry(SpecRefReportEntry, "https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api#exporting-services")
			By("attempting to access the remote service", func() {
				By("issuing a request from all clusters", func() {
					command := []string{"sh", "-c", fmt.Sprintf("echo hi | nc %s.%s.svc.clusterset.local 42",
						t.helloService.Name, t.namespace)}

					// Run on all clusters
					for _, client := range clients {
						// Repeat multiple times
						for i := 0; i < 20; i++ {
							Expect(t.execCmdOnRequestPod(&client, command)).NotTo(ContainSubstring("pod ip"), reportNonConformant(""))
						}
					}
				})
			})
		})
	})

	Context("Connectivity to an exported ClusterIP service", func() {
		It("should be accessible through DNS", Label(OptionalLabel, ConnectivityLabel, ClusterIPLabel), func() {
			AddReportEntry(SpecRefReportEntry, "https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api#dns")
			By("Exporting the service", func() {
				// On the "remote" cluster
				t.createServiceExport(&clients[0], newHelloServiceExport())
			})
			By("Issuing a request from all clusters", func() {
				t.execPortConnectivityCommand(42, "pod ip", 1)
			})
		})
	})

	Context("Connectivity to a ClusterIP service existing in two clusters but exported from one", func() {
		BeforeEach(func() {
			requireTwoClusters()
		})

		JustBeforeEach(func() {
			t.deployHelloService(&clients[1], newHelloService())
		})

		It("should only access the exporting cluster", Label(OptionalLabel, ConnectivityLabel, ClusterIPLabel), func() {
			AddReportEntry(SpecRefReportEntry, "https://github.com/kubernetes/enhancements/blob/master/keps/sig-multicluster/1645-multi-cluster-services-api/README.md#exporting-services")

			By(fmt.Sprintf("Exporting the service on cluster %q", clients[0].name))

			t.createServiceExport(&clients[0], newHelloServiceExport())

			servicePodIP := t.awaitServicePodIP(&clients[0])

			t.execPortConnectivityCommand(42, servicePodIP, 10)
		})
	})

	Context("Connectivity to exported services with same port name but different port numbers on each cluster", func() {
		tt := newTwoClusterTestDriver(t)

		BeforeEach(func() {
			tt.helloService2.Spec.Ports = []corev1.ServicePort{
				{Name: "tcp", Port: 4242, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromInt32(42)},
			}
		})

		It("should only route traffic to the cluster that exposes the port", Label(OptionalLabel, ConnectivityLabel, ClusterIPLabel, StrictPortConflictLabel), func() {
			AddReportEntry(SpecRefReportEntry, "https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api#service-port")

			servicePodIP := t.awaitServicePodIP(&clients[0])

			t.execPortConnectivityCommand(42, servicePodIP, 10)
		})
	})

	Context("Connectivity to exported services with different port name on each cluster", func() {
		tt := newTwoClusterTestDriver(t)

		BeforeEach(func() {
			tt.helloService2.Spec.Ports = []corev1.ServicePort{
				{Name: "tcp2", Port: 4242, Protocol: corev1.ProtocolTCP, TargetPort: intstr.FromInt32(42)},
			}
		})

		It("should route traffic to each port only to the cluster that exposes it", Label(OptionalLabel, ConnectivityLabel, ClusterIPLabel, StrictPortConflictLabel), func() {
			AddReportEntry(SpecRefReportEntry, "https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api#service-port")

			cluster1PodIP := t.awaitServicePodIP(&clients[0])
			cluster2PodIP := t.awaitServicePodIP(&clients[1])

			t.execPortConnectivityCommand(42, cluster1PodIP, 10)
			t.execPortConnectivityCommand(4242, cluster2PodIP, 10)
		})
	})
})
