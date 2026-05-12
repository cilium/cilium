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
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/mcs-api/pkg/apis/v1beta1"
)

// K8sEndpointSliceManagedByName is the name used for endpoint slices managed by the Kubernetes controller
const K8sEndpointSliceManagedByName = "endpointslice-controller.k8s.io"

var _ = Describe("", Label(OptionalLabel, EndpointSliceLabel), func() {
	t := newTestDriver()

	SpecifyWithSpecRef("Exporting a service should create an MCS EndpointSlice in the service's namespace in each cluster with the "+
		"required MCS labels. Unexporting should delete the EndpointSlice.",
		"https://github.com/kubernetes/enhancements/tree/master/keps/sig-multicluster/1645-multi-cluster-services-api#using-endpointslice-objects-to-track-endpoints",
		func(ctx context.Context) {
			endpointSliceNames := make([][]string, len(clients))

			for i, client := range clients {
				for _, ipFamily := range t.awaitServiceImportIPFamilies(ctx, &client) {
					eps := t.awaitMCSEndpointSlice(ctx, &client, addressTypeOf(ipFamily), nil, reportNonConformant(fmt.Sprintf(
						"an MCS EndpointSlice was not found on cluster %q. An MCS EndpointSlice is identified by the presence "+
							"of the required MCS labels (%q and %q). "+
							"If the MCS implementation does not use MCS EndpointSlices, you can specify a Ginkgo label filter using "+
							"the %q label where appropriate to skip this test.",
						client.name, v1beta1.LabelServiceName, v1beta1.LabelSourceCluster, EndpointSliceLabel)))

					endpointSliceNames[i] = append(endpointSliceNames[i], eps.Name)

					Expect(eps.Labels).To(HaveKeyWithValue(v1beta1.LabelServiceName, t.helloService.Name),
						reportNonConformant(fmt.Sprintf("the MCS EndpointSlice %q does not contain the %q label referencing the service name",
							eps.Name, v1beta1.LabelServiceName)))

					Expect(eps.Labels).To(HaveKey(discoveryv1.LabelManagedBy),
						reportNonConformant(fmt.Sprintf("the MCS EndpointSlice %q does not contain the %q label",
							eps.Name, discoveryv1.LabelManagedBy)))

					if !skipVerifyEndpointSliceManagedBy {
						Expect(eps.Labels[discoveryv1.LabelManagedBy]).ToNot(Equal(K8sEndpointSliceManagedByName),
							reportNonConformant(fmt.Sprintf("the MCS EndpointSlice's %q label must not reference %q",
								discoveryv1.LabelManagedBy, K8sEndpointSliceManagedByName)))
					}
				}
			}

			t.deleteServiceExport(ctx, &clients[0])

			for i, client := range clients {
				for _, name := range endpointSliceNames[i] {
					Eventually(func(ctx context.Context) bool {
						_, err := client.k8s.DiscoveryV1().EndpointSlices(t.namespace).Get(ctx, name, metav1.GetOptions{})
						return apierrors.IsNotFound(err)
					}).WithContext(ctx).Within(20*time.Second).ProbeEvery(100*time.Millisecond).Should(BeTrue(),
						reportNonConformant(fmt.Sprintf("the EndpointSlice %q was not deleted on unexport from cluster %q",
							name, client.name)))
				}
			}
		})
})

func (t *testDriver) awaitMCSEndpointSlice(ctx context.Context, c *clusterClients, addressType discoveryv1.AddressType,
	verify func(Gomega, *discoveryv1.EndpointSlice), desc ...any) *discoveryv1.EndpointSlice {
	By(fmt.Sprintf("Retrieving %s MCS EndpointSlice for the service on cluster %q", addressType, c.name))

	var endpointSlice *discoveryv1.EndpointSlice

	hasLabel := func(eps *discoveryv1.EndpointSlice, label string) bool {
		_, exists := eps.Labels[label]
		return exists
	}

	Eventually(func(g Gomega, ctx context.Context) {
		list, err := c.k8s.DiscoveryV1().EndpointSlices(t.namespace).List(ctx, metav1.ListOptions{})
		g.Expect(err).ToNot(HaveOccurred(), "Error retrieving EndpointSlices")

		endpointSlice = nil

		for i := range list.Items {
			eps := &list.Items[i]

			if hasLabel(eps, v1beta1.LabelServiceName) && hasLabel(eps, v1beta1.LabelSourceCluster) && eps.AddressType == addressType && len(eps.Endpoints) > 0 {
				endpointSlice = eps

				if verify != nil {
					verify(g, endpointSlice)
				}
			}
		}

		g.Expect(endpointSlice).ToNot(BeNil(), desc...)

		// The final run succeeded so cancel any prior non-conformance reported.
		cancelNonConformanceReport()
	}).WithContext(ctx).Within(20 * time.Second).ProbeEvery(100 * time.Millisecond).Should(Succeed())

	return endpointSlice
}
