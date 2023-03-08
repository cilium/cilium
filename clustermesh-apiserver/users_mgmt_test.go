// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"context"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/cilium/cilium/operator/watchers"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/promise"
)

const (
	users1 = "users:\n- name: foo\n  role: r1\n- name: bar\n  role: r2\n- name: qux\n  role: r3\n"
	users2 = "users:\n- name: baz\n  role: r3\n- name: foo\n  role: r1\n- name: qux\n  role: r4\n"
)

type fakeUserMgmtClient struct {
	created map[string]string
	deleted map[string]int
}

func (f *fakeUserMgmtClient) init() {
	f.created = make(map[string]string)
	f.deleted = make(map[string]int)
}

func (f *fakeUserMgmtClient) UserEnforcePresence(_ context.Context, name string, roles []string) error {
	// The existing value (if any) is concatenated, to detect if this is called twice for the same name
	f.created[name] = f.created[name] + strings.Join(roles, "|")
	return nil
}

func (f *fakeUserMgmtClient) UserEnforceAbsence(_ context.Context, name string) error {
	f.deleted[name]++
	return nil
}

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(
		m,
		// To ignore goroutine started from sigs.k8s.io/controller-runtime/pkg/log.go
		// init function
		goleak.IgnoreTopFunction("time.Sleep"),
	)
}

func TestUsersManagement(t *testing.T) {
	defer func() {
		// force cleanup of goroutines run from initialization of watchers.nodeQueue,
		// otherwise goleak complains
		watchers.NodeQueueShutDown()
		time.Sleep(50 * time.Millisecond)
	}()

	var client fakeUserMgmtClient
	client.init()

	tmpdir, err := os.MkdirTemp("", "clustermesh-config")
	require.NoError(t, err)
	defer os.RemoveAll(tmpdir)

	cfgPath := path.Join(tmpdir, "users.yaml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(users1), 0600))

	hive := hive.New(
		cell.Provide(func() UsersManagementConfig {
			return UsersManagementConfig{
				ClusterUsersEnabled:    true,
				ClusterUsersConfigPath: cfgPath,
			}
		}),

		cell.Provide(func(lc hive.Lifecycle) promise.Promise[kvstore.BackendOperationsUserMgmt] {
			resolver, promise := promise.New[kvstore.BackendOperationsUserMgmt]()
			resolver.Resolve(&client)
			return promise
		}),

		cell.Invoke(registerUsersManager),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := hive.Start(ctx); err != nil {
		t.Fatalf("failed to start: %s", err)
	}

	defer func() {
		if err := hive.Stop(ctx); err != nil {
			t.Fatalf("failed to stop: %s", err)
		}
	}()

	// Wait for processing to complete
	time.Sleep(25 * time.Millisecond)

	require.Len(t, client.created, 3)
	require.Len(t, client.deleted, 0)
	require.Equal(t, "r1", client.created["foo"])
	require.Equal(t, "r2", client.created["bar"])
	require.Equal(t, "r3", client.created["qux"])

	// Update the users config file, and require that changes are propagated
	client.init()
	require.NoError(t, os.WriteFile(cfgPath, []byte(users2), 0600))

	// Wait for processing to complete
	time.Sleep(25 * time.Millisecond)

	require.Len(t, client.created, 2)
	require.Len(t, client.deleted, 1)
	require.Equal(t, "r3", client.created["baz"])
	require.Equal(t, "r4", client.created["qux"])
	require.Equal(t, 1, client.deleted["bar"])
}
