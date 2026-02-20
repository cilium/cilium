/*
Copyright 2025 The Kubernetes Authors.

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
	"regexp"
	"slices"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	"github.com/onsi/gomega/types"
	corev1 "k8s.io/api/core/v1"
	discovery "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/mcs-api/pkg/apis/v1alpha1"
)

var _ = Describe("", Label(OptionalLabel, DNSLabel, HeadlessLabel), func() {
	const replicas = 2

	t := newTestDriver()

	BeforeEach(func() {
		t.helloService.Spec.ClusterIP = corev1.ClusterIPNone
		t.helloDeployment.Spec.Replicas = ptr.To(int32(replicas))
	})

	Specify("A DNS query of the <service>.<ns>.svc.clusterset.local domain for a headless service should return the "+
		"ready endpoint addresses of all the backing pods", func() {
		AddReportEntry(SpecRefReportEntry, "https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api#dns")

		command := []string{"sh", "-c", fmt.Sprintf("nslookup %s.%s.svc.clusterset.local", t.helloService.Name, t.namespace)}

		endpoints := t.awaitK8sEndpoints(&clients[0], discovery.AddressTypeIPv4)

		var addresses []string
		for _, ep := range endpoints {
			addresses = append(addresses, ep.address)
		}

		for _, client := range clients {
			By(fmt.Sprintf("Executing command %q on cluster %q", strings.Join(command, " "), client.name))

			t.awaitCmdOutputMatches(&client, command, HaveAddresses(addresses), 1, reportNonConformant(""))
		}
	})

	Context("", func() {
		BeforeEach(func() {
			t.helloDeployment = nil
		})

		JustBeforeEach(func() {
			_, err := clients[0].k8s.AppsV1().StatefulSets(t.namespace).Create(ctx, newStatefulSet(replicas), metav1.CreateOptions{})
			Expect(err).ToNot(HaveOccurred())
		})

		Specify("A DNS query of the <hostname>.<clusterid>.<service>.<ns>.svc.clusterset.local domain for a headless StatefulSet "+
			"service should return the requested pod's endpoint address", Label(EndpointSliceLabel), func() {
			AddReportEntry(SpecRefReportEntry, "https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api#dns")

			for _, client := range clients {
				eps := t.awaitMCSEndpointSlice(&client, discovery.AddressTypeIPv4, func(g Gomega, eps *discovery.EndpointSlice) {
					g.Expect(eps.Endpoints).To(HaveLen(replicas),
						"the MCS EndpointSlice %q does not contain the expected number of endpoints %d",
						eps.Name, replicas)

					for i := range eps.Endpoints {
						ep := eps.Endpoints[i]

						g.Expect(ptr.Deref(ep.Conditions.Ready, true)).To(BeTrue(),
							"the endpoint address %s in the MCS EndpointSlice %q is not ready",
							strings.Join(ep.Addresses, ","), eps.Name)

						g.Expect(ptr.Deref(ep.Hostname, "")).ToNot(BeEmpty(),
							"the hostname field for endpoint address %s in the MCS EndpointSlice %q is not set",
							strings.Join(ep.Addresses, ","), eps.Name)
					}
				}, "an MCS EndpointSlice was not found on cluster %q", client.name)

				clusterID := eps.Labels[v1alpha1.LabelSourceCluster]

				for i := range eps.Endpoints {
					ep := &eps.Endpoints[i]

					command := []string{"sh", "-c", fmt.Sprintf("nslookup %s.%s.%s.%s.svc.clusterset.local",
						ptr.Deref(ep.Hostname, ""), clusterID, t.helloService.Name, t.namespace)}

					By(fmt.Sprintf("Executing command %q on cluster %q", strings.Join(command, " "), client.name))

					t.awaitCmdOutputMatches(&client, command, HaveAddresses(ep.Addresses), 1, reportNonConformant(""))
				}
			}
		})
	})

	Specify("A DNS SRV query of the <service>.<ns>.svc.clusterset.local domain for a headless service should return valid SRV "+
		"records", func() {
		AddReportEntry(SpecRefReportEntry, "https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api#dns")

		endpoints := t.awaitK8sEndpoints(&clients[0], discovery.AddressTypeIPv4)

		domainName := fmt.Sprintf("%s.%s.svc.clusterset.local", t.helloService.Name, t.namespace)

		for _, client := range clients {
			srvRecs := t.expectSRVRecords(&client, domainName)

			Expect(srvRecs).To(HaveLen(len(endpoints)), reportNonConformant(
				fmt.Sprintf("Expected %d SRV records. Received %d: %v", len(endpoints), len(srvRecs), srvRecs)))

			for _, ep := range endpoints {
				index := slices.IndexFunc(srvRecs, func(r srvRecord) bool {
					return strings.HasPrefix(r.domainName, ep.hostName)
				})

				Expect(index).To(BeNumerically(">=", 0), reportNonConformant(
					fmt.Sprintf("SRV record for endpoint host name %q not received. Actual records received: %v",
						ep.hostName, srvRecs)))

				Expect(srvRecs[index].port).To(Equal(t.helloService.Spec.Ports[0].Port))
			}
		}
	})
})

type endpointInfo struct {
	address  string
	hostName string
}

func (e endpointInfo) String() string {
	return fmt.Sprintf("address:%q, hostName:%q", e.address, e.hostName)
}

func (t *testDriver) awaitK8sEndpoints(c *clusterClients, addressType discovery.AddressType) []endpointInfo {
	By(fmt.Sprintf("Retrieving K8s endpoint addresses for the service on cluster %q", c.name))

	var endpoints []endpointInfo

	Eventually(func(g Gomega) {
		epsList, err := c.k8s.DiscoveryV1().EndpointSlices(t.namespace).List(ctx, metav1.ListOptions{
			LabelSelector: labels.SelectorFromSet(map[string]string{
				discovery.LabelServiceName: t.helloService.Name,
			}).String(),
		})
		g.Expect(err).ToNot(HaveOccurred())

		endpoints = nil

		for i := range epsList.Items {
			eps := &epsList.Items[i]

			if eps.AddressType != addressType {
				continue
			}

			for j := range epsList.Items[i].Endpoints {
				ep := &epsList.Items[i].Endpoints[j]

				g.Expect(ptr.Deref(ep.Conditions.Ready, true)).To(BeTrue(),
					"the endpoint address %s in the K8s EndpointSlice %q is not ready",
					strings.Join(ep.Addresses, ","), eps.Name)

				for _, addr := range ep.Addresses {
					epi := endpointInfo{address: addr}

					switch {
					case ptr.Deref(ep.Hostname, "") != "":
						epi.hostName = *ep.Hostname
					case strings.Contains(addr, "."):
						epi.hostName = strings.ReplaceAll(addr, ".", "-")
					case strings.Contains(addr, ":"):
						epi.hostName = strings.ReplaceAll(addr, ":", "-")
					}

					endpoints = append(endpoints, epi)
				}
			}
		}

		expCount := int(ptr.Deref(t.helloDeployment.Spec.Replicas, 1))

		g.Expect(endpoints).To(HaveLen(expCount),
			"the K8s EndpointSlice does not contain the expected number of ready endpoints %d", expCount)

		// The final run succeeded so cancel any prior non-conformance reported.
		cancelNonConformanceReport()
	}).Within(20 * time.Second).ProbeEvery(100 * time.Millisecond).Should(Succeed())

	By(fmt.Sprintf("Found endpoints %v", endpoints))

	return endpoints
}

// Match DNS records of type A from nslookup output of the form:
//
//	Server:		10.96.0.10
//	Address:	10.96.0.10:53
//
//	Name:	hello.mcs-conformance-2021198391.svc.clusterset.local
//	Address: 10.244.0.52
//	Name:	hello.mcs-conformance-2021198391.svc.clusterset.local
//	Address: 10.244.0.51
//
// to extract the domain addresses (in this case "10.244.0.52" and "10.244.0.51")
var addressesRegEx = regexp.MustCompile(`Name:.*\s*Address:\s*(.*)`)

type haveAddressesMatcher struct {
	expected []string
}

func (m *haveAddressesMatcher) Match(v interface{}) (bool, error) {
	matches := addressesRegEx.FindAllStringSubmatch(v.(string), -1)

	var actual []string

	for i := range matches {
		actual = append(actual, strings.TrimSpace(matches[i][1]))
	}

	slices.Sort(actual)

	return slices.Equal(actual, m.expected), nil
}

func (m *haveAddressesMatcher) FailureMessage(actual interface{}) string {
	return format.Message(actual, "to have addresses", m.expected)
}

func (m *haveAddressesMatcher) NegatedFailureMessage(actual interface{}) string {
	return format.Message(actual, "to not have addresses", m.expected)
}

func HaveAddresses(expected []string) types.GomegaMatcher {
	slices.Sort(expected)

	return &haveAddressesMatcher{
		expected: expected,
	}
}
