/*
Copyright 2024 The Kubernetes Authors.

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
	"net"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"
)

var (
	_ = Describe("", testGeneralServiceImport)
	_ = Describe("", Label(ClusterIPLabel), testClusterIPServiceImport)
	_ = Describe("", Label(HeadlessLabel), testHeadlessServiceImport)
	_ = Describe("", Label(ExternalNameLabel), testExternalNameService)
	_ = Describe("", testServiceTypeConflict)
)

func testGeneralServiceImport() {
	t := newTestDriver()

	assertHasKeyValues := func(g Gomega, actual, expected map[string]string) {
		for k, v := range expected {
			g.Expect(actual).To(HaveKeyWithValue(k, v), reportNonConformant(""))
		}
	}

	assertNotHasKeyValues := func(g Gomega, actual, expected map[string]string) {
		for k, v := range expected {
			g.Expect(actual).ToNot(HaveKeyWithValue(k, v), reportNonConformant(""))
		}
	}

	// Other tests also unexport the service and verifies the ServiceImport is deleted, but it doesn't require more than one
	// cluster, so it provides basic coverage in a simple single cluster environment. The following test is more comprehensive in that it
	// exports a service from two clusters and ensures proper behavior when unexported from both.
	SpecifyWithSpecRef("A ServiceImport should only exist as long as there's at least one exporting cluster",
		"https://github.com/kubernetes/enhancements/blob/master/keps/sig-multicluster/1645-multi-cluster-services-api/README.md#importing-services",
		Label(RequiredLabel), func() {
			requireTwoClusters()

			t.awaitServiceImport(&clients[0], t.helloService.Name, false, nil)

			By(fmt.Sprintf("Exporting the service on the second cluster %q", clients[1].name))

			t.deployHelloService(&clients[1], newHelloService())
			t.createServiceExport(&clients[1], newHelloServiceExport())

			// Sanity check and to also wait a bit for the second cluster to export. There's no deterministic way to tell if/when
			// the second cluster has finished exporting other than utilizing different service ports in each cluster but service
			// port merging behavior is already covered in another test case, so it's ideal not to rely on behavior that could
			// cause orthogonal failures and to avoid duplicate testing.
			t.ensureServiceImport(&clients[0], t.helloService.Name, fmt.Sprintf(
				"the ServiceImport no longer exists after exporting on cluster %q", clients[1].name))

			t.deleteServiceExport(&clients[0])

			t.ensureServiceImport(&clients[0], t.helloService.Name, fmt.Sprintf(
				"the ServiceImport no longer exists after unexporting the service on cluster %q while still exported on cluster %q",
				clients[0].name, clients[1].name))

			t.deleteServiceExport(&clients[1])

			t.awaitNoServiceImport(&clients[0], helloServiceName,
				"the ServiceImport still exists after unexporting the service on all clusters")
		})

	Context("", func() {
		BeforeEach(func() {
			t.helloServiceExport.Spec.ExportedAnnotations = map[string]string{"dummy-annotation": "true"}
			t.helloServiceExport.Spec.ExportedLabels = map[string]string{"dummy-label": "true"}
		})

		SpecifyWithSpecRef("Only labels and annotations specified as exported in the ServiceExport should be propagated to the ServiceImport",
			"https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api#labels-and-annotations",
			Label(OptionalLabel), Label(ExportedLabelsLabel), func() {
				t.awaitServiceImport(&clients[0], helloServiceName, false,
					func(g Gomega, serviceImport *v1alpha1.ServiceImport) {
						assertHasKeyValues(g, serviceImport.Annotations, t.helloServiceExport.Spec.ExportedAnnotations)
						assertNotHasKeyValues(g, serviceImport.Annotations, t.helloService.Annotations)

						assertHasKeyValues(g, serviceImport.Labels, t.helloServiceExport.Spec.ExportedLabels)
						assertNotHasKeyValues(g, serviceImport.Labels, t.helloService.Labels)
					})
			})
	})

	Context("A service exported on two clusters", func() {
		tt := newTwoClusterTestDriver(t)

		Context("with conflicting annotations and labels", func() {
			BeforeEach(func() {
				t.helloServiceExport.Spec.ExportedAnnotations = map[string]string{"dummy-annotation": "true"}
				t.helloServiceExport.Spec.ExportedLabels = map[string]string{"dummy-label": "true"}

				tt.helloServiceExport2.Spec.ExportedAnnotations = map[string]string{"dummy-annotation2": "true"}
				tt.helloServiceExport2.Spec.ExportedLabels = map[string]string{"dummy-label2": "true"}
			})

			SpecifyWithSpecRef("should apply the conflict resolution policy and report a Conflict condition on each ServiceExport",
				"https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api#labels-and-annotations",
				Label(OptionalLabel), Label(ExportedLabelsLabel), func() {
					t.awaitServiceExportCondition(&clients[0], v1alpha1.ServiceExportConditionConflict, metav1.ConditionTrue)
					t.awaitServiceExportCondition(&clients[1], v1alpha1.ServiceExportConditionConflict, metav1.ConditionTrue)

					t.awaitServiceImport(&clients[0], t.helloService.Name, false,
						func(g Gomega, serviceImport *v1alpha1.ServiceImport) {
							assertHasKeyValues(g, serviceImport.Annotations, t.helloServiceExport.Spec.ExportedAnnotations)
							assertNotHasKeyValues(g, serviceImport.Annotations, tt.helloServiceExport2.Spec.ExportedAnnotations)

							assertHasKeyValues(g, serviceImport.Labels, t.helloServiceExport.Spec.ExportedLabels)
							assertNotHasKeyValues(g, serviceImport.Labels, tt.helloServiceExport2.Spec.ExportedLabels)
						})
				})
		})
	})
}

func testClusterIPServiceImport() {
	t := newTestDriver()

	SpecifyWithSpecRef("Exporting a ClusterIP service should create a ServiceImport of type ClusterSetIP in the service's namespace in each cluster. "+
		"Unexporting should delete the ServiceImport",
		"https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api#importing-services",
		Label(RequiredLabel), func() {
			t.awaitServiceExportCondition(&clients[0], v1alpha1.ServiceExportConditionValid, metav1.ConditionTrue)

			for i := range clients {
				serviceImport := t.awaitServiceImport(&clients[i], helloServiceName, true, nil)

				Expect(serviceImport.Spec.Type).To(Equal(v1alpha1.ClusterSetIP), reportNonConformant(
					fmt.Sprintf("ServiceImport on cluster %q has type %q", clients[i].name, serviceImport.Spec.Type)))
			}

			t.deleteServiceExport(&clients[0])

			for i := range clients {
				t.awaitNoServiceImport(&clients[i], helloServiceName, fmt.Sprintf(
					"the ServiceImport still exists on cluster %q after unexporting the service", clients[i].name))
			}
		})

	SpecifyWithSpecRef("The SessionAffinity for a ClusterSetIP ServiceImport should match the exported service's SessionAffinity",
		"https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api#session-affinity",
		Label(RequiredLabel), func() {
			t.awaitServiceImport(&clients[0], helloServiceName, false, func(g Gomega, serviceImport *v1alpha1.ServiceImport) {
				g.Expect(serviceImport.Spec.SessionAffinity).To(Equal(t.helloService.Spec.SessionAffinity), reportNonConformant(""))

				g.Expect(serviceImport.Spec.SessionAffinityConfig).To(Equal(t.helloService.Spec.SessionAffinityConfig), reportNonConformant(
					"The SessionAffinityConfig of the ServiceImport does not match the exported Service's SessionAffinityConfig"))
			})
		})

	Context("", func() {
		BeforeEach(func() {
			t.helloService.Spec.InternalTrafficPolicy = ptr.To(corev1.ServiceInternalTrafficPolicyCluster)
		})
		SpecifyWithSpecRef("The InternalTrafficPolicy for a ClusterSetIP ServiceImport should match the exported service's InternalTrafficPolicy",
			"https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api#internal-traffic-policy",
			Label(RequiredLabel), func() {
				t.awaitServiceImport(&clients[0], helloServiceName, false, func(g Gomega, serviceImport *v1alpha1.ServiceImport) {
					g.Expect(serviceImport.Spec.InternalTrafficPolicy).To(Equal(t.helloService.Spec.InternalTrafficPolicy), reportNonConformant(
						"The InternalTrafficPolicy of the ServiceImport does not match the exported Service's InternalTrafficPolicy"))
				})
			},
		)
	})

	Context("", func() {
		BeforeEach(func() {
			t.helloService.Spec.TrafficDistribution = ptr.To(corev1.ServiceTrafficDistributionPreferClose)
		})
		SpecifyWithSpecRef("The TrafficDistribution for a ClusterSetIP ServiceImport should match the exported service's TrafficDistribution",
			"https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api#traffic-distribution",
			Label(RequiredLabel), func() {
				t.awaitServiceImport(&clients[0], helloServiceName, false, func(g Gomega, serviceImport *v1alpha1.ServiceImport) {
					g.Expect(serviceImport.Spec.TrafficDistribution).To(Equal(t.helloService.Spec.TrafficDistribution), reportNonConformant(
						"The TrafficDistribution of the ServiceImport does not match the exported Service's TrafficDistribution"))
				})
			},
		)
	})

	SpecifyWithSpecRef("An IP should be allocated for a ClusterSetIP ServiceImport",
		"https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api#clustersetip",
		Label(RequiredLabel), func() {
			serviceImport := t.awaitServiceImport(&clients[0], t.helloService.Name, false,
				func(g Gomega, serviceImport *v1alpha1.ServiceImport) {
					g.Expect(serviceImport.Spec.IPs).ToNot(BeEmpty(), reportNonConformant(""))
				})

			Expect(net.ParseIP(serviceImport.Spec.IPs[0])).ToNot(BeNil(),
				reportNonConformant(fmt.Sprintf("The value %q is not a valid IP", serviceImport.Spec.IPs[0])))
		})

	SpecifyWithSpecRef("The ports for a ClusterSetIP ServiceImport should match those of the exported service",
		"https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api#service-port",
		Label(RequiredLabel), func() {
			t.awaitServiceImport(&clients[0], helloServiceName, false, func(g Gomega, serviceImport *v1alpha1.ServiceImport) {
				g.Expect(sortMCSPorts(serviceImport.Spec.Ports)).To(Equal(toMCSPorts(t.helloService.Spec.Ports)), reportNonConformant(""))
			})
		})

	Context("A ClusterIP service exported on two clusters", func() {
		tt := newTwoClusterTestDriver(t)

		Context("", func() {
			BeforeEach(func() {
				tt.helloService2.Spec.Ports = []corev1.ServicePort{
					t.helloService.Spec.Ports[0],
					{
						Name:     "stcp",
						Port:     142,
						Protocol: corev1.ProtocolSCTP,
					},
				}
			})

			SpecifyWithSpecRef("should expose the union of the constituent service ports and raise a conflict",
				"https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api#service-port",
				Label(RequiredLabel), func() {
					t.awaitServiceExportCondition(&clients[0], v1alpha1.ServiceExportConditionConflict, metav1.ConditionTrue)
					t.awaitServiceExportCondition(&clients[1], v1alpha1.ServiceExportConditionConflict, metav1.ConditionTrue)

					t.awaitServiceImport(&clients[0], t.helloService.Name, false,
						func(g Gomega, serviceImport *v1alpha1.ServiceImport) {
							g.Expect(sortMCSPorts(serviceImport.Spec.Ports)).To(Equal(toMCSPorts(
								append(t.helloService.Spec.Ports, tt.helloService2.Spec.Ports[1]))), reportNonConformant(""))
						})
				})
		})

		Context("with conflicting ports", Label(RequiredLabel), func() {
			BeforeEach(func() {
				tt.helloService2.Spec.Ports = []corev1.ServicePort{t.helloService.Spec.Ports[0]}
				tt.helloService2.Spec.Ports[0].Port = t.helloService.Spec.Ports[0].Port + 1
			})

			SpecifyWithSpecRef("should apply the conflict resolution policy and report a Conflict condition on each ServiceExport",
				"https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api#service-port",
				func() {
					t.awaitServiceExportCondition(&clients[0], v1alpha1.ServiceExportConditionConflict, metav1.ConditionTrue)
					t.awaitServiceExportCondition(&clients[1], v1alpha1.ServiceExportConditionConflict, metav1.ConditionTrue)

					t.awaitServiceImport(&clients[0], t.helloService.Name, false,
						func(g Gomega, serviceImport *v1alpha1.ServiceImport) {
							g.Expect(sortMCSPorts(serviceImport.Spec.Ports)).To(Equal(toMCSPorts(t.helloService.Spec.Ports)),
								reportNonConformant("The service ports were not resolved correctly"))
						})
				})
		})
	})
}

func testHeadlessServiceImport() {
	t := newTestDriver()

	BeforeEach(func() {
		t.helloService.Spec.ClusterIP = corev1.ClusterIPNone
	})

	SpecifyWithSpecRef("Exporting a headless service should create a ServiceImport of type Headless in the service's namespace in each cluster. "+
		"Unexporting should delete the ServiceImport",
		"https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api#service-types",
		Label(RequiredLabel), func() {
			for i := range clients {
				serviceImport := t.awaitServiceImport(&clients[i], helloServiceName, true, nil)

				Expect(serviceImport.Spec.Type).To(Equal(v1alpha1.Headless), reportNonConformant(
					fmt.Sprintf("ServiceImport on cluster %q has type %q", clients[i].name, serviceImport.Spec.Type)))
			}

			t.deleteServiceExport(&clients[0])

			for i := range clients {
				t.awaitNoServiceImport(&clients[i], helloServiceName, fmt.Sprintf(
					"the ServiceImport still exists on cluster %q after unexporting the service", clients[i].name))
			}
		})

	SpecifyWithSpecRef("No clusterset IP should be allocated for a Headless ServiceImport",
		"https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api#clustersetip",
		Label(RequiredLabel), func() {
			t.awaitServiceImport(&clients[0], t.helloService.Name, false, nil)

			Consistently(func() []string {
				return t.getServiceImport(&clients[0], t.helloService.Name).Spec.IPs
			}).Within(5*time.Second).ProbeEvery(time.Second).Should(BeEmpty(), reportNonConformant(""))
		})
}

func testExternalNameService() {
	t := newTestDriver()

	BeforeEach(func() {
		t.helloService.Spec.Type = corev1.ServiceTypeExternalName
		t.helloService.Spec.ExternalName = "example.com"
	})

	SpecifyWithSpecRef("Exporting an ExternalName service should set ServiceExport Valid condition to False",
		"https://github.com/kubernetes/enhancements/blob/master/keps/sig-multicluster/1645-multi-cluster-services-api/README.md#service-types",
		Label(RequiredLabel), func() {
			t.awaitServiceExportCondition(&clients[0], v1alpha1.ServiceExportConditionValid, metav1.ConditionFalse)
			t.ensureNoServiceImport(&clients[0], helloServiceName,
				"the ServiceImport should not exist for an ExternalName service")
		})
}

func testServiceTypeConflict() {
	t := newTwoClusterTestDriver(newTestDriver())

	BeforeEach(func() {
		t.helloService2.Spec.ClusterIP = corev1.ClusterIPNone
	})

	SpecifyWithSpecRef("A service exported on two clusters with conflicting headlessness should apply the conflict resolution policy and "+
		"report a Conflict condition on the ServiceExport",
		"https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api#headlessness",
		Label(RequiredLabel), func() {
			t.awaitServiceExportCondition(&clients[0], v1alpha1.ServiceExportConditionConflict, metav1.ConditionTrue)
			t.awaitServiceExportCondition(&clients[1], v1alpha1.ServiceExportConditionConflict, metav1.ConditionTrue)

			for i := range clients {
				serviceImport := t.awaitServiceImport(&clients[i], helloServiceName, true, nil)

				Expect(serviceImport.Spec.Type).To(Equal(v1alpha1.ClusterSetIP), reportNonConformant(
					fmt.Sprintf("ServiceImport on cluster %q has type %q", clients[i].name, serviceImport.Spec.Type)))
			}
		})
}
