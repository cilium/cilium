// SPDX-License-Identifier: Apache-2.0
// Copyright 2018-2019 Authors of Cilium

package ipcache

import (
	"sync"
	"testing"

	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/source"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"

	"github.com/stretchr/testify/assert"
)

func TestInjectLabels(t *testing.T) {
	setupTest(t)

	assert.Len(t, IdentityMetadata, 1)
	assert.NoError(t, InjectLabels(source.Local, &mockUpdater{}, &mockTriggerer{}))
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 1)

	// Insert kube-apiserver IP from outside of the cluster. This should create
	// a CIDR ID for this IP.
	UpsertMetadata("10.0.0.4/32", labels.LabelKubeAPIServer)
	assert.Len(t, IdentityMetadata, 2)
	assert.NoError(t, InjectLabels(source.Local, &mockUpdater{}, &mockTriggerer{}))
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 2)
	assert.True(t, IPIdentityCache.ipToIdentityCache["10.0.0.4/32"].ID.HasLocalScope())

	// Upsert node labels to the kube-apiserver to validate that the CIDR ID is
	// deallocated and the kube-apiserver reserved ID is associated with this
	// IP now.
	UpsertMetadata("10.0.0.4/32", labels.LabelRemoteNode)
	assert.Len(t, IdentityMetadata, 2)
	assert.NoError(t, InjectLabels(source.Local, &mockUpdater{}, &mockTriggerer{}))
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 2)
	assert.False(t, IPIdentityCache.ipToIdentityCache["10.0.0.4/32"].ID.HasLocalScope())
}

func TestFilterMetadataByLabels(t *testing.T) {
	setupTest(t)

	UpsertMetadata("2.1.1.1/32", labels.LabelWorld)
	UpsertMetadata("3.1.1.1/32", labels.LabelWorld)

	assert.Len(t, FilterMetadataByLabels(labels.LabelKubeAPIServer), 1)
	assert.Len(t, FilterMetadataByLabels(labels.LabelWorld), 2)
}

func TestRemoveAllPrefixesWithLabels(t *testing.T) {
	setupTest(t)

	assert.Len(t, IdentityMetadata, 1)
	assert.NoError(t, InjectLabels(source.Local, &mockUpdater{}, &mockTriggerer{}))
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 1)

	RemoveAllPrefixesWithLabels(map[string]labels.Labels{
		"1.1.1.1/32": labels.LabelKubeAPIServer,
	}, source.Local, &mockUpdater{}, &mockTriggerer{})
	assert.Len(t, IdentityMetadata, 1)
	assert.Equal(t, labels.LabelHost, IdentityMetadata["1.1.1.1/32"])
}

func setupTest(t *testing.T) {
	IPIdentityCache = NewIPCache()
	IPIdentityCache.k8sSyncedChecker = &mockK8sSyncedChecker{}

	IdentityAllocator = testidentity.NewMockIdentityAllocator(nil)
	IdentityMetadata = make(map[string]labels.Labels)

	UpsertMetadata("1.1.1.1/32", labels.LabelKubeAPIServer)
	UpsertMetadata("1.1.1.1/32", labels.LabelHost)
}

type mockK8sSyncedChecker struct{}

func (m *mockK8sSyncedChecker) K8sCacheIsSynced() bool { return true }

type mockUpdater struct{}

func (m *mockUpdater) UpdateIdentities(_, _ cache.IdentityCache, _ *sync.WaitGroup) {}

type mockTriggerer struct{}

func (m *mockTriggerer) TriggerPolicyUpdates(bool, string) {}
