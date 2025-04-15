// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"log/slog"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/synced"
)

type fakeK8sWatcherConfiguration struct{}

func (f *fakeK8sWatcherConfiguration) K8sNetworkPolicyEnabled() bool {
	return true
}

func (f *fakeK8sWatcherConfiguration) KVstoreEnabled() bool {
	return false
}

func Test_No_Resources_InitK8sSubsystem(t *testing.T) {
	logger := hivetest.Logger(t)
	fakeClientSet, _ := client.NewFakeClientset(logger)
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
		nil,
		nil,
		nil,
		nil,
		&synced.Resources{CacheStatus: make(synced.CacheStatus)},
		nil,
		&fakeK8sWatcherConfiguration{},
	)

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
