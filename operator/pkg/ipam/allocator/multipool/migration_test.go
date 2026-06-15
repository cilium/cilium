// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multipool

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8sTesting "k8s.io/client-go/testing"

	operatorK8s "github.com/cilium/cilium/operator/k8s"
	"github.com/cilium/cilium/pkg/hive"
	iputil "github.com/cilium/cilium/pkg/ip"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

func TestMigrateNode(t *testing.T) {
	const (
		nodeName    = "test-node"
		defaultPool = "default"
	)

	t.Run("node updated after migration", func(t *testing.T) {
		node := &v2.CiliumNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: nodeName,
			},
			Spec: v2.NodeSpec{
				IPAM: ipamTypes.IPAMSpec{
					PodCIDRs: []iputil.Prefix{
						iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.0/24")),
						iputil.PrefixFrom(netip.MustParsePrefix("fd00::/124")),
					},
				},
			},
		}

		clientset, store := fixture(t, node, nil)

		err := migrateNode(t.Context(), store, clientset.CiliumV2().CiliumNodes(), resource.Key{Name: node.Name}, defaultPool)
		require.NoError(t, err)

		updatedNode, err := clientset.CiliumV2().CiliumNodes().Get(t.Context(), node.Name, metav1.GetOptions{})
		require.NoError(t, err)

		assert.Empty(t, updatedNode.Spec.IPAM.PodCIDRs)
		assert.Equal(t, []ipamTypes.IPAMPoolAllocation{
			{
				Pool: defaultPool,
				CIDRs: []iputil.Prefix{
					iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.0/24")),
					iputil.PrefixFrom(netip.MustParsePrefix("fd00::/124"))},
			},
		}, updatedNode.Spec.IPAM.Pools.Allocated)
		assert.Empty(t, updatedNode.Status.IPAM.OperatorStatus.Error)
	})

	t.Run("retry after transient error", func(t *testing.T) {
		node := &v2.CiliumNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: nodeName,
			},
			Spec: v2.NodeSpec{
				IPAM: ipamTypes.IPAMSpec{
					PodCIDRs: []iputil.Prefix{
						iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.0/24")),
						iputil.PrefixFrom(netip.MustParsePrefix("fd00::/124")),
					},
				},
			},
		}

		var updates atomic.Int32

		synctest.Test(t, func(t *testing.T) {
			clientset, store := fixture(t, node, func(cs *k8sClient.FakeClientset) {
				cs.CiliumFakeClientset.PrependReactor("update", "ciliumnodes", func(action k8sTesting.Action) (bool, runtime.Object, error) {
					if updates.Add(1) == 1 {
						// return a transient error for the first update attempt
						return true, nil, k8sErrors.NewServerTimeout(
							schema.GroupResource{
								Group:    v2.CustomResourceDefinitionGroup,
								Resource: v2.CNPluralName,
							},
							"update",
							1,
						)
					}
					return false, nil, nil
				})
			})

			err := migrateNode(t.Context(), store, clientset.CiliumV2().CiliumNodes(), resource.Key{Name: node.Name}, defaultPool)
			require.NoError(t, err)
			require.Equal(t, int32(2), updates.Load())

			updatedNode, err := clientset.CiliumV2().CiliumNodes().Get(t.Context(), node.Name, metav1.GetOptions{})
			require.NoError(t, err)

			assert.Empty(t, updatedNode.Spec.IPAM.PodCIDRs)
			assert.Equal(t, []ipamTypes.IPAMPoolAllocation{
				{
					Pool: defaultPool,
					CIDRs: []iputil.Prefix{
						iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.0/24")),
						iputil.PrefixFrom(netip.MustParsePrefix("fd00::/124"))},
				},
			}, updatedNode.Spec.IPAM.Pools.Allocated)
			assert.Empty(t, updatedNode.Status.IPAM.OperatorStatus.Error)
		})
	})

	t.Run("refetch and retry after update conflict", func(t *testing.T) {
		node := &v2.CiliumNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: nodeName,
			},
			Spec: v2.NodeSpec{
				IPAM: ipamTypes.IPAMSpec{
					PodCIDRs: []iputil.Prefix{
						iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.0/24")),
						iputil.PrefixFrom(netip.MustParsePrefix("fd00::/124")),
					},
				},
			},
		}

		var updates atomic.Int32

		synctest.Test(t, func(t *testing.T) {
			clientset, store := fixture(t, node, func(cs *k8sClient.FakeClientset) {
				cs.CiliumFakeClientset.PrependReactor("update", "ciliumnodes", func(action k8sTesting.Action) (bool, runtime.Object, error) {
					if updates.Add(1) == 1 {
						// change the node in the store to simulate a conflict
						gvr := v2.SchemeGroupVersion.WithResource(v2.CNPluralName)
						current, err := cs.CiliumFakeClientset.Tracker().Get(gvr, "", nodeName, metav1.GetOptions{})
						require.NoError(t, err)
						currentNode := current.(*v2.CiliumNode).DeepCopy()
						currentNode.Labels = map[string]string{"conflict-test": "true"}
						if err := cs.CiliumFakeClientset.Tracker().Update(gvr, currentNode, ""); err != nil {
							return true, nil, err
						}

						// return a conflict error for the first update attempt
						return true, nil, k8sErrors.NewConflict(
							schema.GroupResource{
								Group:    v2.CustomResourceDefinitionGroup,
								Resource: v2.CNPluralName,
							},
							nodeName,
							errors.New("update refused by unit test"),
						)
					}
					return false, nil, nil
				})
			})

			err := migrateNode(t.Context(), store, clientset.CiliumV2().CiliumNodes(), resource.Key{Name: node.Name}, defaultPool)
			require.NoError(t, err)
			require.Equal(t, int32(2), updates.Load())

			updatedNode, err := clientset.CiliumV2().CiliumNodes().Get(t.Context(), node.Name, metav1.GetOptions{})
			require.NoError(t, err)

			assert.Empty(t, updatedNode.Spec.IPAM.PodCIDRs)
			assert.Equal(t, []ipamTypes.IPAMPoolAllocation{
				{
					Pool: defaultPool,
					CIDRs: []iputil.Prefix{
						iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.0/24")),
						iputil.PrefixFrom(netip.MustParsePrefix("fd00::/124"))},
				},
			}, updatedNode.Spec.IPAM.Pools.Allocated)
			assert.Empty(t, updatedNode.Status.IPAM.OperatorStatus.Error)
		})
	})

	t.Run("no retry if node was deleted", func(t *testing.T) {
		node := &v2.CiliumNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: nodeName,
			},
			Spec: v2.NodeSpec{
				IPAM: ipamTypes.IPAMSpec{
					PodCIDRs: []iputil.Prefix{
						iputil.PrefixFrom(netip.MustParsePrefix("10.0.0.0/24")),
						iputil.PrefixFrom(netip.MustParsePrefix("fd00::/124")),
					},
				},
			},
		}

		var updates atomic.Int32

		synctest.Test(t, func(t *testing.T) {
			clientset, store := fixture(t, node, func(cs *k8sClient.FakeClientset) {
				cs.CiliumFakeClientset.PrependReactor("update", "ciliumnodes", func(action k8sTesting.Action) (bool, runtime.Object, error) {
					if updates.Add(1) == 1 {
						// delete the node in the store
						gvr := v2.SchemeGroupVersion.WithResource(v2.CNPluralName)
						err := cs.CiliumFakeClientset.Tracker().Delete(gvr, "", nodeName, metav1.DeleteOptions{})
						require.NoError(t, err)

						// return a not found error
						return true, nil, k8sErrors.NewNotFound(
							schema.GroupResource{
								Group:    v2.CustomResourceDefinitionGroup,
								Resource: v2.CNPluralName,
							},
							nodeName,
						)
					}
					return false, nil, nil
				})
			})

			err := migrateNode(t.Context(), store, clientset.CiliumV2().CiliumNodes(), resource.Key{Name: node.Name}, defaultPool)
			require.NoError(t, err)
			require.Equal(t, int32(1), updates.Load())

			_, err = clientset.CiliumV2().CiliumNodes().Get(t.Context(), node.Name, metav1.GetOptions{})
			require.Error(t, err)
			require.True(t, k8sErrors.IsNotFound(err))
		})
	})
}

func TestUpdateStatusForFailure(t *testing.T) {
	const nodeName = "test-node"

	t.Run("update status for failed migration", func(t *testing.T) {
		node := &v2.CiliumNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: nodeName,
			},
		}

		migrationErr := errors.New("migration failed")

		synctest.Test(t, func(t *testing.T) {
			clientset, store := fixture(t, node, nil)

			err := updateStatusForFailure(t.Context(), store, clientset.CiliumV2().CiliumNodes(), resource.Key{Name: node.Name}, migrationErr)
			require.NoError(t, err)

			updatedNode, err := clientset.CiliumV2().CiliumNodes().Get(t.Context(), node.Name, metav1.GetOptions{})
			require.NoError(t, err)

			assert.Equal(t, fmt.Sprintf("migration to multi-pool IPAM failed: %s", migrationErr), updatedNode.Status.IPAM.OperatorStatus.Error)
		})
	})

	t.Run("refetch and retry after update status conflict", func(t *testing.T) {
		node := &v2.CiliumNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: nodeName,
			},
		}

		migrationErr := errors.New("migration failed")

		var statusUpdates atomic.Int32

		synctest.Test(t, func(t *testing.T) {
			clientset, store := fixture(t, node, func(cs *k8sClient.FakeClientset) {
				cs.CiliumFakeClientset.PrependReactor("update", "ciliumnodes", func(action k8sTesting.Action) (bool, runtime.Object, error) {
					if action.GetSubresource() != "status" {
						return false, nil, nil
					}

					if statusUpdates.Add(1) == 1 {
						// change the node in the store to simulate a conflict
						gvr := v2.SchemeGroupVersion.WithResource(v2.CNPluralName)
						current, err := cs.CiliumFakeClientset.Tracker().Get(gvr, "", nodeName, metav1.GetOptions{})
						require.NoError(t, err)
						currentNode := current.(*v2.CiliumNode).DeepCopy()
						currentNode.Status.IPAM.OperatorStatus.Error = "conflict-test"
						if err := cs.CiliumFakeClientset.Tracker().Update(gvr, currentNode, ""); err != nil {
							return true, nil, err
						}

						// return a conflict error for the first update status attempt
						return true, nil, k8sErrors.NewConflict(
							schema.GroupResource{
								Group:    v2.CustomResourceDefinitionGroup,
								Resource: v2.CNPluralName,
							},
							nodeName,
							errors.New("update status refused by unit test"),
						)
					}
					return false, nil, nil
				})
			})

			err := updateStatusForFailure(t.Context(), store, clientset.CiliumV2().CiliumNodes(), resource.Key{Name: node.Name}, migrationErr)
			require.NoError(t, err)
			require.Equal(t, int32(2), statusUpdates.Load())

			updatedNode, err := clientset.CiliumV2().CiliumNodes().Get(t.Context(), node.Name, metav1.GetOptions{})
			require.NoError(t, err)

			assert.Equal(t, fmt.Sprintf("migration to multi-pool IPAM failed: %s", migrationErr), updatedNode.Status.IPAM.OperatorStatus.Error)
		})
	})
}

func fixture(
	t *testing.T,
	node *v2.CiliumNode,
	setReactor func(cs *k8sClient.FakeClientset),
) (*k8sClient.FakeClientset, resource.Store[*v2.CiliumNode]) {
	t.Helper()

	var (
		clientset   *k8sClient.FakeClientset
		ciliumNodes resource.Resource[*v2.CiliumNode]
	)

	testHive := hive.New(
		k8sClient.FakeClientCell(),
		operatorK8s.ResourcesCell,
		cell.Invoke(
			func(cs *k8sClient.FakeClientset, cn resource.Resource[*v2.CiliumNode]) {
				clientset = cs
				ciliumNodes = cn
			},
			func(cs *k8sClient.FakeClientset) {
				if setReactor != nil {
					setReactor(cs)
				}
			},
		),
	)

	tlog := hivetest.Logger(t, hivetest.LogLevel(slog.LevelError))
	require.NoError(t, testHive.Start(tlog, t.Context()))
	t.Cleanup(func() {
		assert.NoError(t, testHive.Stop(tlog, context.Background()))
	})

	_, err := clientset.CiliumV2().CiliumNodes().Create(t.Context(), node.DeepCopy(), metav1.CreateOptions{})
	require.NoError(t, err)

	store, err := ciliumNodes.Store(t.Context())
	require.NoError(t, err)

	return clientset, store
}
