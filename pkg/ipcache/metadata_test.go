// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package ipcache

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/source"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"

	"github.com/stretchr/testify/assert"
)

func TestInjectLabels(t *testing.T) {
	setupTest(t)

	assert.Len(t, identityMetadata, 1)
	assert.NoError(t, InjectLabels(source.Local, &mockUpdater{}, &mockTriggerer{}))
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 1)

	// Insert kube-apiserver IP from outside of the cluster. This should create
	// a CIDR ID for this IP.
	UpsertMetadata("10.0.0.4", labels.LabelKubeAPIServer)
	assert.Len(t, identityMetadata, 2)
	assert.NoError(t, InjectLabels(source.Local, &mockUpdater{}, &mockTriggerer{}))
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 2)
	assert.True(t, IPIdentityCache.ipToIdentityCache["10.0.0.4"].ID.HasLocalScope())

	// Upsert node labels to the kube-apiserver to validate that the CIDR ID is
	// deallocated and the kube-apiserver reserved ID is associated with this
	// IP now.
	UpsertMetadata("10.0.0.4", labels.LabelRemoteNode)
	assert.Len(t, identityMetadata, 2)
	assert.NoError(t, InjectLabels(source.Local, &mockUpdater{}, &mockTriggerer{}))
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 2)
	assert.False(t, IPIdentityCache.ipToIdentityCache["10.0.0.4"].ID.HasLocalScope())
}

func TestFilterMetadataByLabels(t *testing.T) {
	setupTest(t)

	UpsertMetadata("2.1.1.1", labels.LabelWorld)
	UpsertMetadata("3.1.1.1", labels.LabelWorld)

	assert.Len(t, filterMetadataByLabels(labels.LabelKubeAPIServer), 1)
	assert.Len(t, filterMetadataByLabels(labels.LabelWorld), 2)
}

func TestRemoveLabelsFromIPs(t *testing.T) {
	setupTest(t)

	assert.Len(t, identityMetadata, 1)
	assert.NoError(t, InjectLabels(source.Local, &mockUpdater{}, &mockTriggerer{}))
	assert.Len(t, IPIdentityCache.ipToIdentityCache, 1)

	removeLabelsFromIPs(map[string]labels.Labels{
		"1.1.1.1": labels.LabelKubeAPIServer,
	}, source.Local, &mockUpdater{}, &mockTriggerer{})
	assert.Len(t, identityMetadata, 1)
	assert.Equal(t, labels.LabelHost, identityMetadata["1.1.1.1"])

	// Simulate kube-apiserver policy + CIDR policy on same prefix. Validate
	// that removing the kube-apiserver policy will result in a new CIDR
	// identity for the CIDR policy.

	delete(identityMetadata, "1.1.1.1") // clean slate first
	// Entry with only kube-apiserver labels means kube-apiserver is outside of
	// the cluster, and thus will have a CIDR identity when InjectLabels() is
	// called.
	UpsertMetadata("1.1.1.1", labels.LabelKubeAPIServer)
	assert.NoError(t, InjectLabels(source.Local, &mockUpdater{}, &mockTriggerer{}))
	id := IdentityAllocator.LookupIdentityByID(
		context.TODO(),
		identity.LocalIdentityFlag, // we assume first local ID
	)
	assert.NotNil(t, id)
	assert.Equal(t, 1, id.ReferenceCount)
	// Simulate adding CIDR policy.
	ids, err := AllocateCIDRsForIPs([]net.IP{net.ParseIP("1.1.1.1")}, nil)
	assert.Nil(t, err)
	assert.Len(t, ids, 1)
	assert.Equal(t, 2, id.ReferenceCount)
	removeLabelsFromIPs(map[string]labels.Labels{ // remove kube-apiserver policy
		"1.1.1.1": labels.LabelKubeAPIServer,
	}, source.Local, &mockUpdater{}, &mockTriggerer{})
	assert.NotContains(t, identityMetadata["1.1.1.1"], labels.LabelKubeAPIServer)
	assert.Equal(t, 1, id.ReferenceCount) // CIDR policy is left
}

func setupTest(t *testing.T) {
	IPIdentityCache = NewIPCache()
	IPIdentityCache.k8sSyncedChecker = &mockK8sSyncedChecker{}

	IdentityAllocator = testidentity.NewMockIdentityAllocator(nil)
	identityMetadata = make(map[string]labels.Labels)

	UpsertMetadata("1.1.1.1", labels.LabelKubeAPIServer)
	UpsertMetadata("1.1.1.1", labels.LabelHost)
}

type mockK8sSyncedChecker struct{}

func (m *mockK8sSyncedChecker) K8sCacheIsSynced() bool { return true }

type mockUpdater struct{}

func (m *mockUpdater) UpdateIdentities(_, _ cache.IdentityCache, _ *sync.WaitGroup) {}

type mockTriggerer struct{}

func (m *mockTriggerer) TriggerPolicyUpdates(bool, string) {}
