// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/synced"
)

type fakeK8sWatcherConfiguration struct{}

func (f *fakeK8sWatcherConfiguration) K8sNetworkPolicyEnabled() bool {
	return true
}

func Test_No_Resources_InitK8sSubsystem(t *testing.T) {
	fakeClientSet, _ := client.NewFakeClientset()

	w := newWatcher(
		fakeClientSet,
		&K8sPodWatcher{
			controllersStarted: make(chan struct{}),
			podStoreSet:        make(chan struct{}),
		},
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		&synced.Resources{},
		nil,
		&fakeK8sWatcherConfiguration{},
	)

	w.resourceGroupsFn = func(cfg WatcherConfiguration) (resourceGroups []string, waitForCachesOnly []string) {
		return []string{}, []string{}
	}

	// ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	deadline, _ := t.Deadline()
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	cachesSynced := make(chan struct{})
	w.InitK8sSubsystem(ctx, cachesSynced)
	// Expect channel to be closed.
	select {
	case <-ctx.Done():
		t.Fail()
	case _, ok := <-cachesSynced:
		require.False(t, ok)
	}
}
