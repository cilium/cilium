// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointcleanup

import (
	"context"
	"fmt"
	"testing"

	"go.uber.org/goleak"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8stesting "k8s.io/client-go/testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/promise"
)

var testCESs = []cilium_v2a1.CiliumEndpointSlice{
	{
		ObjectMeta: metav1.ObjectMeta{
			Name: "ciliumEndpointSlices-000",
		},
		Namespace: "x",
		Endpoints: []cilium_v2a1.CoreCiliumEndpoint{
			{
				Name: "foo",
				Networking: &cilium_v2.EndpointNetworking{
					Addressing: cilium_v2.AddressPairList{},
					NodeIP:     "<nil>",
				},
			},
		},
	},
}

func TestGC(t *testing.T) {
	tests := map[string]struct {
		ciliumEndpoints []types.CiliumEndpoint
		// should only be used if disableCEPCRD is true.
		ciliumEndpointSlices []cilium_v2a1.CiliumEndpointSlice
		// if true, simulates running CiliumEndpointSlice watcher instead of CEP.
		enableCES bool
		// endpoints in endpointManaged.
		managedEndpoints map[string]*endpoint.Endpoint
		// expectedDeletedSet contains CiliumEndpoints that are expected to be deleted
		// during test, in the form '<namespace>/<cilium_endpoint>'.
		expectedDeletedSet []string
		// apiserverCEPs is used to mock apiserver get requests when running with CES enabled.
		apiserverCEPs map[string]*cilium_v2.CiliumEndpoint
	}{
		"CEPs with local pods without endpoints should be GCd": {
			ciliumEndpoints:    []types.CiliumEndpoint{cep("foo", "x", "<nil>"), cep("foo", "y", "<nil>")},
			managedEndpoints:   map[string]*endpoint.Endpoint{"y/foo": {}},
			expectedDeletedSet: []string{"x/foo"},
		},
		"CEPs with local pods with endpoints should not be GCd": {
			ciliumEndpoints:    []types.CiliumEndpoint{cep("foo", "x", "")},
			managedEndpoints:   map[string]*endpoint.Endpoint{"x/foo": {}},
			expectedDeletedSet: nil,
		},
		"Non local CEPs should not be GCd": {
			ciliumEndpoints:    []types.CiliumEndpoint{cep("foo", "x", "1.2.3.4")},
			managedEndpoints:   map[string]*endpoint.Endpoint{},
			expectedDeletedSet: nil,
		},
		"Nothing should be deleted if fields are missing": {
			ciliumEndpoints:    []types.CiliumEndpoint{cep("", "", "")},
			managedEndpoints:   map[string]*endpoint.Endpoint{},
			expectedDeletedSet: nil,
		},
		"CES: local CEPs without endpoints should be GCd": {
			ciliumEndpointSlices: testCESs,
			ciliumEndpoints: []types.CiliumEndpoint{
				cep("bar", "x", "<nil>"),
				cep("foo", "x", "<nil>"),
				cep("notlocal", "x", "1.2.3.4"),
			},
			enableCES:          true,
			managedEndpoints:   map[string]*endpoint.Endpoint{"x/bar": {}},
			expectedDeletedSet: []string{"x/foo"},
			apiserverCEPs: map[string]*cilium_v2.CiliumEndpoint{
				"x/foo": {
					ObjectMeta: metav1.ObjectMeta{
						UID: "00001",
					},
					Status: cilium_v2.EndpointStatus{
						Networking: &cilium_v2.EndpointNetworking{
							NodeIP: "<nil>",
						},
					},
				},
			},
		},
		"CES: Test case where IP in apiserver changes and delete should be skipped": {
			ciliumEndpointSlices: testCESs,
			ciliumEndpoints: []types.CiliumEndpoint{
				cep("foo", "x", "<nil>"),
			},
			enableCES:          true,
			managedEndpoints:   map[string]*endpoint.Endpoint{"x/bar": {}},
			expectedDeletedSet: nil,
			apiserverCEPs: map[string]*cilium_v2.CiliumEndpoint{
				"x/foo": {
					ObjectMeta: metav1.ObjectMeta{
						UID: "00001",
					},
					Status: cilium_v2.EndpointStatus{
						Networking: &cilium_v2.EndpointNetworking{
							NodeIP: "1.2.3.4",
						},
					},
				},
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			defer goleak.VerifyNone(
				t,
				// Delaying workqueues used by resource.Resource[T].Events leaks this waitingLoop goroutine.
				// It does stop when shutting down but is not guaranteed to before we actually exit.
				goleak.IgnoreTopFunction("k8s.io/client-go/util/workqueue.(*delayingType).waitingLoop"),
			)

			node.SetTestLocalNodeStore()
			defer node.UnsetTestLocalNodeStore()

			var (
				testCleanup *cleanup
				deletedSet  []string
			)

			hive := hive.New(
				k8sClient.FakeClientCell,
				k8s.ResourcesCell,
				cell.ProvidePrivate(func() localEndpointCache {
					return &fakeEPManager{test.managedEndpoints}
				}),
				cell.Provide(func() promise.Promise[endpointstate.Restorer] {
					return &fakeRestorer{}
				}),
				cell.Provide(func() *node.LocalNodeStore {
					// no need to provide a real LocalNodeStore since the one set by
					// SetTestLocalNodeStore will be referenced through the global
					// variable
					return nil
				}),
				cell.Invoke(func(clientset *k8sClient.FakeClientset) error {
					clientset.CiliumFakeClientset.PrependReactor("get", "ciliumendpoints", k8stesting.ReactionFunc(
						func(action k8stesting.Action) (bool, runtime.Object, error) {
							if !test.enableCES {
								t.Fatal("unexpected get on ciliumendpoints in CEP mode, expected only in CES mode")
							}
							name := action.(k8stesting.GetAction).GetName()
							ns := action.(k8stesting.GetActionImpl).Namespace
							cep, ok := test.apiserverCEPs[ns+"/"+name]
							if !ok {
								return true, nil, fmt.Errorf("not found")
							}
							return true, cep, nil
						},
					))
					clientset.CiliumFakeClientset.PrependReactor("delete", "ciliumendpoints", k8stesting.ReactionFunc(
						func(action k8stesting.Action) (bool, runtime.Object, error) {
							a := action.(k8stesting.DeleteAction)
							deletedSet = append(deletedSet, fmt.Sprintf("%s/%s", a.GetNamespace(), a.GetName()))
							return true, nil, nil
						},
					))
					return nil
				}),
				cell.Invoke(func(clientset k8sClient.Clientset) error {
					for _, ces := range test.ciliumEndpointSlices {
						if _, err := clientset.CiliumV2alpha1().CiliumEndpointSlices().
							Create(context.Background(), &ces, metav1.CreateOptions{}); err != nil {
							return fmt.Errorf("failed to create CiliumEndpointSlice %v: %w", ces, err)
						}
					}
					for _, cep := range test.ciliumEndpoints {
						if _, err := clientset.CiliumV2().CiliumEndpoints(cep.Namespace).
							Create(context.Background(), &cilium_v2.CiliumEndpoint{
								ObjectMeta: metav1.ObjectMeta{
									Name:      cep.Name,
									Namespace: cep.Namespace,
								},
								Status: cilium_v2.EndpointStatus{
									Networking: &cilium_v2.EndpointNetworking{
										NodeIP: cep.Networking.NodeIP,
									},
								},
							}, metav1.CreateOptions{}); err != nil {
							return fmt.Errorf("failed to create CiliumEndpoint %v: %w", cep, err)
						}
					}
					return nil
				}),
				cell.Invoke(func(
					logger logrus.FieldLogger,
					ciliumEndpoint resource.Resource[*types.CiliumEndpoint],
					ciliumEndpointSlice resource.Resource[*cilium_v2a1.CiliumEndpointSlice],
					clientset k8sClient.Clientset,
					restorerPromise promise.Promise[endpointstate.Restorer],
					endpointsCache localEndpointCache,
				) *cleanup {
					testCleanup = &cleanup{
						log:                        logger,
						ciliumEndpoint:             ciliumEndpoint,
						ciliumEndpointSlice:        ciliumEndpointSlice,
						ciliumClient:               clientset.CiliumV2(),
						restorerPromise:            restorerPromise,
						endpointsCache:             endpointsCache,
						ciliumEndpointSliceEnabled: test.enableCES,
					}
					return testCleanup
				}),
			)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			assert.NoError(t, hive.Start(ctx))

			assert.NoError(t, testCleanup.run(ctx))

			assert.ElementsMatch(t, test.expectedDeletedSet, deletedSet)

			assert.NoError(t, hive.Stop(ctx))
		})
	}
}

type fakeEPManager struct {
	byCEPName map[string]*endpoint.Endpoint
}

func (epm *fakeEPManager) LookupCEPName(namespacedName string) *endpoint.Endpoint {
	ep, ok := epm.byCEPName[namespacedName]
	if !ok {
		return nil
	}
	return ep
}

func cep(name, ns, nodeIP string) types.CiliumEndpoint {
	return types.CiliumEndpoint{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
		},
		Networking: &cilium_v2.EndpointNetworking{
			NodeIP: nodeIP,
		},
	}
}

type fakeRestorer struct {
}

func (r *fakeRestorer) Await(context.Context) (endpointstate.Restorer, error) {
	return r, nil
}

func (r *fakeRestorer) WaitForEndpointRestore(_ context.Context) {
}
