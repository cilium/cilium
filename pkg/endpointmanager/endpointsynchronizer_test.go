// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/identity"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/fake"
	k8sFakeClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

func Test_updateCEPUID(t *testing.T) {
	logger := hivetest.Logger(t)
	podWithHostIP := func(hostIP string) *slim_corev1.Pod {
		return &slim_corev1.Pod{
			Status: slim_corev1.PodStatus{
				HostIP: hostIP,
			},
		}
	}
	podWithHostIPAndUID := func(hostIP, uid string) *slim_corev1.Pod {
		return &slim_corev1.Pod{
			ObjectMeta: slim_metav1.ObjectMeta{
				UID: types.UID(uid),
			},
			Status: slim_corev1.PodStatus{
				HostIP: hostIP,
			},
		}
	}
	epWithUID := func(uid string, pod *slim_corev1.Pod) *endpoint.Endpoint {
		ep := &endpoint.Endpoint{}
		ep.SetPod(pod)
		ep.SetCiliumEndpointUID(types.UID(uid))
		return ep
	}
	epWithUIDAndAttachment := func(uid, attachmentID string, pod *slim_corev1.Pod) *endpoint.Endpoint {
		s := setupEndpointManagerSuite(t)
		model := &models.EndpointChangeRequest{
			ID:          101,
			ContainerID: attachmentID,
			State:       ptr.To(models.EndpointStateReady),
		}
		ep, err := endpoint.NewEndpointFromChangeModel(makeTestEndpointParams(logger, s), nil, &endpoint.FakeEndpointProxy{}, model, nil)
		require.NoError(t, err)
		ep.SetPod(pod)
		ep.SetCiliumEndpointUID(types.UID(uid))
		return ep
	}
	disconnectingEPWithUID := func(uid string, pod *slim_corev1.Pod) *endpoint.Endpoint {
		s := setupEndpointManagerSuite(t)
		model := &models.EndpointChangeRequest{
			ID:    102,
			State: ptr.To(models.EndpointStateWaitingDashForDashIdentity),
		}
		ep, err := endpoint.NewEndpointFromChangeModel(makeTestEndpointParams(logger, s), nil, &endpoint.FakeEndpointProxy{}, model, nil)
		require.NoError(t, err)
		ep.SetState(endpoint.StateDisconnecting, "test")
		ep.SetPod(pod)
		ep.SetCiliumEndpointUID(types.UID(uid))
		return ep
	}
	testIP := "1.2.3.4"
	someUID := func(s string) *types.UID {
		id := types.UID(s)
		return &id
	}
	for name, test := range map[string]struct {
		err           error
		cep           *v2.CiliumEndpoint
		ep            *endpoint.Endpoint
		nodeIP        string
		expectedEPUID *types.UID
	}{
		// In this test, our CEP has a UID that is different from the local Endpoint.
		// This means that the CEP is not owned by this EP.
		// Ownership should fail due to Endpoint not having a pod.
		// This condition is typically triggered when the pod is deleted.
		"no pod": {
			ep:     epWithUID("000", nil),
			err:    fmt.Errorf("no pod"),
			nodeIP: testIP,
			cep: &v2.CiliumEndpoint{
				ObjectMeta: v1.ObjectMeta{
					UID: "111", // Different UID from the local Endpoint.
				},
			},
		},
		"CiliumEndpoint not local": {
			// The CEP is explicitly not local (i.e the CEP's pod's hostIP doesn't match the nodeIP).
			ep:     epWithUID("1234", podWithHostIP(testIP)),
			nodeIP: "4.3.2.1",
			err:    fmt.Errorf("is not local"),
			cep: &v2.CiliumEndpoint{
				ObjectMeta: v1.ObjectMeta{UID: "1111"},
			},
		},
		"CiliumEndpoint not local, but already owned": {
			// The CEP is explicitly not local. But the CEP is already owned by the endpoint.
			// So ownership should proceed without error.
			ep:     epWithUID("000", podWithHostIP("4.3.2.1")), // matches CEP.
			nodeIP: testIP,
			cep: &v2.CiliumEndpoint{
				ObjectMeta: v1.ObjectMeta{UID: "000"},
			},
		},
		"ciliumendpoint already exists": {
			// CEP already exists, on the same node, we cannot take ownership of it
			// due to differing UID ref.
			//
			// This would be the case where two endpoint sync controllers are running for
			// a Pod with the same namespace/name on the same Agent, so we'd have to wait
			// until the other controller terminates and cleans up the CEP.
			err:           fmt.Errorf("did not match CEP UID"),
			expectedEPUID: someUID("b"),
			ep:            epWithUID("b", podWithHostIP(testIP)),
			nodeIP:        testIP,
			cep: &v2.CiliumEndpoint{
				ObjectMeta: v1.ObjectMeta{UID: types.UID("a")},
			},
		},
		// This is the normal case of taking ownership.
		// Note that this also happens when the nodeIP changes during a reboot
		// but the endpoint snapshot is lost on reboot. The endpoint UID will
		// remain empty, but the CEP object will have a UID and a wrong nodeIP.
		// It is to counter this case that we check the pods hostIP against the
		// nodeIP instead of the CEP's node IP.
		"take ownership of cep due to empty CiliumEndpointUID ref": {
			ep:            epWithUID("", podWithHostIP(testIP)),
			nodeIP:        testIP,
			expectedEPUID: someUID("a"),
			cep: &v2.CiliumEndpoint{
				ObjectMeta: v1.ObjectMeta{UID: types.UID("a")},
				Status: v2.EndpointStatus{
					Networking: &v2.EndpointNetworking{
						NodeIP: "4.5.6.7",
					},
				},
			},
		},
		"reclaim ownership of recreated cep owned by same pod": {
			ep:            epWithUIDAndAttachment("stale-cep-uid", "sandbox-a", podWithHostIPAndUID(testIP, "pod-uid-1")),
			nodeIP:        testIP,
			expectedEPUID: someUID("new-cep-uid"),
			cep: &v2.CiliumEndpoint{
				ObjectMeta: v1.ObjectMeta{
					UID: types.UID("new-cep-uid"),
					OwnerReferences: []v1.OwnerReference{
						{Kind: "Pod", UID: types.UID("pod-uid-1")},
					},
				},
				Status: v2.EndpointStatus{
					ExternalIdentifiers: &models.EndpointIdentifiers{CniAttachmentID: "sandbox-a"},
				},
			},
		},
		"reject ownership of cep owned by different pod instance": {
			err:           fmt.Errorf("did not match CEP UID"),
			ep:            epWithUID("cep-uid-1", podWithHostIPAndUID(testIP, "pod-uid-1")),
			nodeIP:        testIP,
			expectedEPUID: someUID("cep-uid-1"),
			cep: &v2.CiliumEndpoint{
				ObjectMeta: v1.ObjectMeta{
					UID: types.UID("cep-uid-2"),
					OwnerReferences: []v1.OwnerReference{
						{Kind: "Pod", UID: types.UID("pod-uid-2")},
					},
				},
			},
		},
		"reject ownership when endpoint is disconnecting": {
			err:           fmt.Errorf("did not match CEP UID"),
			ep:            disconnectingEPWithUID("stale-cep-uid", podWithHostIPAndUID(testIP, "pod-uid-1")),
			nodeIP:        testIP,
			expectedEPUID: someUID("stale-cep-uid"),
			cep: &v2.CiliumEndpoint{
				ObjectMeta: v1.ObjectMeta{
					UID: types.UID("new-cep-uid"),
					OwnerReferences: []v1.OwnerReference{
						{Kind: "Pod", UID: types.UID("pod-uid-1")},
					},
				},
			},
		},
		"reject ownership when cep belongs to different CNI attachment": {
			err:           fmt.Errorf("did not match CEP UID"),
			ep:            epWithUIDAndAttachment("stale-cep-uid", "sandbox-a", podWithHostIPAndUID(testIP, "pod-uid-1")),
			nodeIP:        testIP,
			expectedEPUID: someUID("stale-cep-uid"),
			cep: &v2.CiliumEndpoint{
				ObjectMeta: v1.ObjectMeta{
					UID: types.UID("new-cep-uid"),
					OwnerReferences: []v1.OwnerReference{
						{Kind: "Pod", UID: types.UID("pod-uid-1")},
					},
				},
				Status: v2.EndpointStatus{
					ExternalIdentifiers: &models.EndpointIdentifiers{CniAttachmentID: "sandbox-b"},
				},
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			ln := node.LocalNode{}
			ln.SetNodeInternalIP(netip.MustParseAddr(test.nodeIP))
			eps := &EndpointSynchronizer{
				localNodeStore: node.NewTestLocalNodeStore(ln),
			}
			err := eps.updateCEPUID(t.Context(), logger, test.ep, test.cep)
			if test.err == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, test.err.Error())
			}
			if test.expectedEPUID != nil {
				assert.Equal(t, *test.expectedEPUID, test.ep.GetCiliumEndpointUID())
			}
		})
	}
}

// Test_deleteCEP verifies that cleanup preserves a CEP adopted by another
// endpoint and uses both UID and resourceVersion to guard deletion of its own CEP.
func Test_deleteCEP(t *testing.T) {
	logger := hivetest.Logger(t)
	ep := &endpoint.Endpoint{ID: 2, K8sNamespace: "default", K8sPodName: "workload"}
	ep.SetCiliumEndpointUID("cep-uid")
	ep.SetPod(&slim_corev1.Pod{ObjectMeta: slim_metav1.ObjectMeta{Namespace: "default"}})
	for name, test := range map[string]struct {
		endpointID  int64
		uid         types.UID
		identifiers *models.EndpointIdentifiers
		wantDelete  bool
	}{
		"current owner": {
			endpointID: 2,
			uid:        "cep-uid",
			wantDelete: true,
		},
		"replacement with the same CEP UID": {
			endpointID: 3,
			uid:        "cep-uid",
		},
		"different CNI attachment": {
			endpointID:  2,
			uid:         "cep-uid",
			identifiers: &models.EndpointIdentifiers{CniAttachmentID: "sandbox-b"},
		},
		"different CEP UID": {
			endpointID: 2,
			uid:        "other-cep",
		},
		"legacy CEP without attachment ID": {
			endpointID:  2,
			uid:         "cep-uid",
			identifiers: &models.EndpointIdentifiers{},
			wantDelete:  true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			cep := &v2.CiliumEndpoint{
				ObjectMeta: v1.ObjectMeta{
					Name:            ep.K8sPodName,
					Namespace:       ep.K8sNamespace,
					UID:             test.uid,
					ResourceVersion: "1",
				},
				Status: v2.EndpointStatus{
					ID:                  test.endpointID,
					ExternalIdentifiers: test.identifiers,
				},
			}
			client := fake.NewSimpleClientset(cep)
			assert.NoError(t, deleteCEP(t.Context(), logger, client.CiliumV2(), ep))

			resource := v2.SchemeGroupVersion.WithResource("ciliumendpoints")
			expected := []k8stesting.Action{
				k8stesting.NewGetActionWithOptions(resource, cep.Namespace, cep.Name, v1.GetOptions{}),
			}
			if test.wantDelete {
				expected = append(expected, k8stesting.NewDeleteActionWithOptions(resource, cep.Namespace, cep.Name, v1.DeleteOptions{
					Preconditions: &v1.Preconditions{UID: &cep.UID, ResourceVersion: &cep.ResourceVersion},
				}))
			}
			assert.Equal(t, expected, client.Actions())
		})
	}
}

type cepNameLookupStub struct {
	EndpointsLookup
	active atomic.Pointer[endpoint.Endpoint]
}

func (l *cepNameLookupStub) LookupCEPName(namespacedName string) *endpoint.Endpoint {
	ep := l.active.Load()
	if ep != nil && ep.GetK8sNamespaceAndCEPName() == namespacedName {
		return ep
	}
	return nil
}

func TestRunK8sCiliumEndpointSync_RecreatedCEPOwnershipAfterRestart(t *testing.T) {
	logger := hivetest.Logger(t)
	s := setupEndpointManagerSuite(t)
	require.NoError(t, k8sversion.Force("1.28.0"))

	tmpDir := t.TempDir()
	origStateDir := option.Config.StateDir
	option.Config.StateDir = tmpDir
	t.Cleanup(func() {
		option.Config.StateDir = origStateDir
	})

	ln := node.LocalNode{}
	ln.SetNodeInternalIP(netip.MustParseAddr("1.2.3.4"))
	localNodeStore := node.NewTestLocalNodeStore(ln)

	fakeClientSet, cs := k8sFakeClient.NewFakeClientset(logger)
	var createCount atomic.Int32
	var revCount atomic.Int32
	fakeClientSet.CiliumFakeClientset.PrependReactor("create", "ciliumendpoints", k8stesting.ReactionFunc(
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			createAction := action.(k8stesting.CreateAction)
			cep := createAction.GetObject().(*v2.CiliumEndpoint)
			n := createCount.Add(1)
			cep.UID = types.UID(fmt.Sprintf("cep-uid-%d", n))
			cep.ResourceVersion = fmt.Sprintf("%d", revCount.Add(1))
			return false, cep, nil
		},
	))
	fakeClientSet.CiliumFakeClientset.PrependReactor("patch", "ciliumendpoints", k8stesting.ReactionFunc(
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			patchAction := action.(k8stesting.PatchAction)
			existing, err := fakeClientSet.CiliumFakeClientset.Tracker().Get(
				v2.SchemeGroupVersion.WithResource("ciliumendpoints"),
				patchAction.GetNamespace(),
				patchAction.GetName(),
			)
			if err == nil {
				existing.(*v2.CiliumEndpoint).ResourceVersion = fmt.Sprintf("%d", revCount.Add(1))
			}
			return false, nil, nil
		},
	))

	newTestEndpoint := func(id int64, serviceAccount string) *endpoint.Endpoint {
		model := &models.EndpointChangeRequest{
			ID:           id,
			K8sPodName:   "test-pod",
			K8sNamespace: "default",
			K8sUID:       "pod-uid-1",
			ContainerID:  "sandbox-1",
			State:        ptr.To(models.EndpointStateWaitingDashForDashIdentity),
		}
		p := makeTestEndpointParams(logger, s)
		p.LocalNodeStore = localNodeStore
		ep, err := endpoint.NewEndpointFromChangeModel(p, nil, &endpoint.FakeEndpointProxy{}, model, nil)
		require.NoError(t, err)
		ep.Start(uint16(id))
		t.Cleanup(ep.Stop)
		require.NoError(t, os.MkdirAll(ep.StateDirectoryPath(), 0o777))
		ep.SetK8sMetadata(nil)
		ep.SecurityIdentity = &identity.Identity{
			ID:     identity.NumericIdentity(1234),
			Labels: labels.NewLabelsFromModel([]string{"k8s:app=test"}),
		}
		ep.SetPod(&slim_corev1.Pod{
			TypeMeta: slim_metav1.TypeMeta{
				Kind:       "Pod",
				APIVersion: "v1",
			},
			ObjectMeta: slim_metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "default",
				UID:       "pod-uid-1",
			},
			Spec: slim_corev1.PodSpec{
				ServiceAccountName: serviceAccount,
			},
			Status: slim_corev1.PodStatus{
				HostIP: "1.2.3.4",
			},
		})
		return ep
	}

	lookup := &cepNameLookupStub{}
	epSync := &EndpointSynchronizer{
		Clientset:      cs,
		localNodeStore: localNodeStore,
	}

	// Stage 1: Initial endpoint creates CEP with cep-uid-1 and persists it to ep_config.json once trigger runs.
	ep1 := newTestEndpoint(501, "sa-initial")
	lookup.active.Store(ep1)
	h1, _ := cell.NewSimpleHealth()
	epSync.RunK8sCiliumEndpointSync(ep1, lookup, h1)
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, types.UID("cep-uid-1"), ep1.GetCiliumEndpointUID())
		cep, err := cs.CiliumV2().CiliumEndpoints("default").Get(context.Background(), "test-pod", v1.GetOptions{})
		if assert.NoError(c, err) {
			assert.Equal(c, types.UID("cep-uid-1"), cep.UID)
			assert.Equal(c, "sa-initial", cep.Status.ServiceAccount)
		}
	}, 5*time.Second, 20*time.Millisecond)

	// Stage 2: CEP is deleted externally and recreated with cep-uid-2 while agent crashes before flushing ep_config.json.
	require.NoError(t, cs.CiliumV2().CiliumEndpoints("default").Delete(context.Background(), "test-pod", v1.DeleteOptions{}))
	recreatedCEP := &v2.CiliumEndpoint{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
			OwnerReferences: []v1.OwnerReference{
				{
					APIVersion: "v1",
					Kind:       "Pod",
					Name:       "test-pod",
					UID:        "pod-uid-1",
				},
			},
		},
		Status: *ep1.GetCiliumEndpointStatus(),
	}
	recreatedCEP, err := cs.CiliumV2().CiliumEndpoints("default").Create(context.Background(), recreatedCEP, v1.CreateOptions{})
	require.NoError(t, err)
	require.Equal(t, types.UID("cep-uid-2"), recreatedCEP.UID)
	ep1.Stop()

	// Stage 3: Simulate ungraceful agent restart where restored endpoint still holds stale on-disk cep-uid-1
	// for the same running Pod (UID "pod-uid-1", CniAttachmentID "sandbox-1").
	restoredEP := newTestEndpoint(501, "sa-after-restart")
	restoredEP.SetCiliumEndpointUID("cep-uid-1")
	lookup.active.Store(restoredEP)
	h2, _ := cell.NewSimpleHealth()
	epSync.RunK8sCiliumEndpointSync(restoredEP, lookup, h2)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, types.UID("cep-uid-2"), restoredEP.GetCiliumEndpointUID())
		cep, err := cs.CiliumV2().CiliumEndpoints("default").Get(context.Background(), "test-pod", v1.GetOptions{})
		if assert.NoError(c, err) {
			assert.Equal(c, types.UID("cep-uid-2"), cep.UID)
			assert.Equal(c, "sa-after-restart", cep.Status.ServiceAccount)
		}
	}, 1*time.Second, 20*time.Millisecond)

	// Verify pod termination cleanly deletes the CEP without skipping or hitting a 409 Conflict.
	require.NoError(t, deleteCEP(t.Context(), logger, cs.CiliumV2(), restoredEP))
	_, err = cs.CiliumV2().CiliumEndpoints("default").Get(context.Background(), "test-pod", v1.GetOptions{})
	require.True(t, k8serrors.IsNotFound(err), "expected CEP to be deleted on stop, got err=%v", err)
}
