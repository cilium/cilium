// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package doublewrite

import (
	"context"
	"fmt"
	"path"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/rand"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/identity/key"
	"github.com/cilium/cilium/pkg/idpool"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/identitybackend"
	kvstoreallocator "github.com/cilium/cilium/pkg/kvstore/allocator"
	"github.com/cilium/cilium/pkg/labels"

	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/testutils"
)

func setup(tb testing.TB) (string, *k8sClient.FakeClientset, kvstore.BackendOperations, allocator.Backend) {
	tb.Helper()

	testutils.IntegrationTest(tb)

	kvstoreClient := kvstore.SetupDummy(tb, "etcd")
	kvstorePrefix := fmt.Sprintf("test-prefix-%s", rand.String(12))
	kubeClient, _ := k8sClient.NewFakeClientset(hivetest.Logger(tb))
	backend, err := NewDoubleWriteBackend(
		hivetest.Logger(tb),
		DoubleWriteBackendConfiguration{
			CRDBackendConfiguration: identitybackend.CRDBackendConfiguration{
				Store:    nil,
				StoreSet: &atomic.Bool{},
				Client:   kubeClient,
				KeyFunc:  (&key.GlobalIdentity{}).PutKeyFromMap,
			},
			KVStoreBackendConfiguration: kvstoreallocator.KVStoreBackendConfiguration{
				BasePath: kvstorePrefix,
				Suffix:   "a",
				Typ:      &key.GlobalIdentity{},
				Backend:  kvstoreClient,
			},
			ReadFromKVStore: true,
		})
	require.NoError(tb, err)
	require.NotNil(tb, backend)

	return kvstorePrefix, kubeClient, kvstoreClient, backend
}

func TestAllocateID(t *testing.T) {
	kvstorePrefix, kubeClient, kvstoreClient, backend := setup(t)

	// Allocate a new identity
	lbls := labels.NewLabelsFromSortedList("id=foo")
	k := &key.GlobalIdentity{LabelArray: lbls.LabelArray()}
	identityID := idpool.ID(10)
	_, err := backend.AllocateID(context.Background(), identityID, k)
	require.NoError(t, err)

	// Verify that both the CRD and the KVStore identities have been created
	// 1. CRD
	ids, err := kubeClient.CiliumV2().CiliumIdentities().List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	require.Len(t, ids.Items, 1)
	require.Equal(t, identityID.String(), ids.Items[0].Name)
	require.Equal(t,
		k.GetAsMap(),
		ids.Items[0].SecurityLabels,
	)

	// 2. KVStore
	kvPairs, err := kvstoreClient.ListPrefix(context.Background(), path.Join(kvstorePrefix, "id"))
	require.NoError(t, err)
	require.Len(t, kvPairs, 1)
	require.Equal(t,
		k.GetKey(),
		string(kvPairs[fmt.Sprintf("%s/id/%s", kvstorePrefix, identityID)].Data),
	)
}

func TestAllocateIDFailure(t *testing.T) {
	kvstorePrefix, kubeClient, kvstoreClient, backend := setup(t)

	// Allocate a new identity
	lbls := labels.NewLabelsFromSortedList("id=foo")
	k := &key.GlobalIdentity{LabelArray: lbls.LabelArray()}
	identityID := idpool.ID(10)

	// Pre-create the identity in the KVStore so as to trigger failure during allocation
	_, err := kvstoreClient.CreateOnly(context.Background(), path.Join(kvstorePrefix, "id", strconv.FormatUint(uint64(identityID), 10)), []byte(k.GetKey()), false)
	require.NoError(t, err)

	_, err = backend.AllocateID(context.Background(), identityID, k)
	// The KVStore allocation should have failed
	require.ErrorContains(t, err, "unable to create master key")

	// Verify that the identity has not been created as a CRD
	ids, err := kubeClient.CiliumV2().CiliumIdentities().List(context.Background(), metav1.ListOptions{})
	require.NoError(t, err)
	require.Empty(t, ids.Items)
}

func TestGetID(t *testing.T) {
	kvstorePrefix, kubeClient, kvstoreClient, backend := setup(t)

	// Allocate a new identity
	lbls := labels.NewLabelsFromSortedList("id=foo")
	k := &key.GlobalIdentity{LabelArray: lbls.LabelArray()}
	identityID := idpool.ID(10)
	_, err := backend.AllocateID(context.Background(), identityID, k)
	require.NoError(t, err)

	// Get the identity. It will be retrieved from the KVStore ("ReadFromKVStore: true").
	returnedKey, err := backend.GetByID(context.Background(), identityID)
	require.NoError(t, err)
	require.Equal(t, returnedKey.GetKey(), k.GetKey())

	// Delete the CRD identity
	err = kubeClient.CiliumV2().CiliumIdentities().Delete(context.Background(), identityID.String(), metav1.DeleteOptions{})
	require.NoError(t, err)

	// Verify that the identity is still retrievable from the KVStore
	returnedKey, err = backend.GetByID(context.Background(), identityID)
	require.NoError(t, err)
	require.Equal(t, returnedKey.GetKey(), k.GetKey())

	// Delete the KVStore identity
	err = kvstoreClient.Delete(context.Background(), path.Join(kvstorePrefix, "id", identityID.String()))
	require.NoError(t, err)

	// Verify that we can't retrieve the identity anymore
	returnedKey, err = backend.GetByID(context.Background(), identityID)
	require.NoError(t, err)
	require.Nil(t, returnedKey)
}
