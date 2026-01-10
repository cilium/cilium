// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"log/slog"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/synced"
)

type fakeK8sWatcherConfiguration struct{}

func (f *fakeK8sWatcherConfiguration) K8sNetworkPolicyEnabled() bool {
	return true
}

type fakeKVStoreConfig struct{}

func (f *fakeKVStoreConfig) IsEnabled() bool {
	return false
}

func Test_No_Resources_InitK8sSubsystem(t *testing.T) {
	logger := hivetest.Logger(t)
	fakeClientSet, _ := k8sClient.NewFakeClientset(logger)
	k8sCachesSynced := make(chan struct{})
	w := newWatcher(
		logger,
		func(logger *slog.Logger, cfg WatcherConfiguration) (resourceGroups []string, waitForCachesOnly []string) {
			return []string{}, []string{}
		},
		fakeClientSet,
		&K8sPodWatcher{
			controllersStarted: make(chan struct{}),
		},
		nil,
		nil,
		nil,
		&synced.Resources{CacheStatus: make(synced.CacheStatus)},
		k8sCachesSynced,
		nil,
		&fakeK8sWatcherConfiguration{},
		&fakeKVStoreConfig{},
	)

	// ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	deadline, _ := t.Deadline()
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	w.InitK8sSubsystem(ctx)
	// Expect channel to be closed.
	select {
	case <-ctx.Done():
		t.Fail()
	case _, ok := <-k8sCachesSynced:
		require.False(t, ok)
	}
}
