// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"path"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	etcdAPI "go.etcd.io/etcd/client/v3"
	"k8s.io/apimachinery/pkg/util/rand"

	"github.com/cilium/cilium/pkg/testutils"
)

func TestHint(t *testing.T) {
	var err error

	require.NoError(t, Hint(err))

	err = errors.New("foo bar")
	require.ErrorContains(t, Hint(err), "foo bar")

	err = fmt.Errorf("ayy lmao")
	require.ErrorContains(t, Hint(err), "ayy lmao")

	err = context.DeadlineExceeded
	require.ErrorContains(t, Hint(err), "etcd client timeout exceeded")

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	<-ctx.Done()
	err = ctx.Err()

	require.ErrorContains(t, Hint(err), "etcd client timeout exceeded")
}

func setupEtcdLockedSuite(tb testing.TB) (BackendOperations, *etcdAPI.Client) {
	testutils.IntegrationTest(tb)

	client := SetupDummyWithConfigOpts(tb, "etcd", etcdOpts)

	// setup client
	cfg := etcdAPI.Config{}
	cfg.Endpoints = []string{etcdDummyAddress}
	cfg.DialTimeout = 0
	cli, err := etcdAPI.New(cfg)
	cfg.DialTimeout = 0
	require.NoError(tb, err)
	tb.Cleanup(func() { require.NoError(tb, cli.Close()) })

	return client, cli
}

func TestGetIfLocked(t *testing.T) {
	client, cl := setupEtcdLockedSuite(t)

	randomPath := t.TempDir()
	type args struct {
		key  string
		lock KVLocker
	}
	type wanted struct {
		err   error
		value []byte
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() wanted
		cleanup     func(args args) error
	}{
		{
			name: "getting locked path",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := client.LockPath(context.Background(), "locks/"+key+"/.lock")
				require.NoError(t, err)
				_, err = cl.Put(context.Background(), key, "bar")
				require.NoError(t, err)

				return args{
					key:  key,
					lock: kvlocker,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err:   nil,
					value: []byte("bar"),
				}
			},
			cleanup: func(args args) error {
				_, err := cl.Delete(context.Background(), args.key)
				if err != nil {
					return err
				}
				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "getting locked path with no value",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := client.LockPath(context.Background(), "locks/"+key+"/.lock")
				require.NoError(t, err)
				_, err = cl.Delete(context.Background(), key)
				require.NoError(t, err)

				return args{
					key:  key,
					lock: kvlocker,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err:   nil,
					value: nil,
				}
			},
			cleanup: func(args args) error {
				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "getting locked path where lock was lost",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := client.LockPath(context.Background(), "locks/"+key+"/.lock")
				require.NoError(t, err)
				err = kvlocker.Unlock(context.TODO())
				require.NoError(t, err)

				_, err = cl.Put(context.Background(), key, "bar")
				require.NoError(t, err)

				return args{
					key:  key,
					lock: kvlocker,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err:   ErrLockLeaseExpired,
					value: nil,
				}
			},
			cleanup: func(args args) error {
				_, err := cl.Delete(context.Background(), args.key)
				return err
			},
		},
	}
	for _, tt := range tests {
		t.Log(tt.name)
		args := tt.setupArgs()
		want := tt.setupWanted()
		value, err := client.GetIfLocked(context.TODO(), args.key, args.lock)
		require.Equal(t, want.err, err)
		require.Equal(t, want.value, value)
		err = tt.cleanup(args)
		require.NoError(t, err)
	}
}

func TestDeleteIfLocked(t *testing.T) {
	client, e := setupEtcdLockedSuite(t)

	randomPath := t.TempDir()
	type args struct {
		key  string
		lock KVLocker
	}
	type wanted struct {
		err error
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() wanted
		cleanup     func(args args) error
	}{
		{
			name: "deleting locked path",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := client.LockPath(context.Background(), "locks/"+key+"/.lock")
				require.NoError(t, err)
				_, err = e.Put(context.Background(), key, "bar")
				require.NoError(t, err)

				return args{
					key:  key,
					lock: kvlocker,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: nil,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was actually deleted
				gr, err := e.Get(context.Background(), key)
				require.NoError(t, err)
				require.Equal(t, int64(0), gr.Count)

				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "deleting locked path with no value",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := client.LockPath(context.Background(), "locks/"+key+"/.lock")
				require.NoError(t, err)

				_, err = e.Delete(context.Background(), key)
				require.NoError(t, err)

				return args{
					key:  key,
					lock: kvlocker,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: nil,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was actually deleted (this should not matter
				// as the key was never in the kvstore but still)
				gr, err := e.Get(context.Background(), key)
				require.NoError(t, err)
				require.Equal(t, int64(0), gr.Count)

				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "deleting locked path where lock was lost",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := client.LockPath(context.Background(), "locks/"+key+"/.lock")
				require.NoError(t, err)
				_, err = e.Put(context.Background(), key, "bar")
				require.NoError(t, err)
				err = kvlocker.Unlock(context.TODO())
				require.NoError(t, err)

				return args{
					key:  key,
					lock: kvlocker,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: ErrLockLeaseExpired,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// If the lock was lost it means the value still exists
				value, err := e.Get(context.Background(), key)
				require.NoError(t, err)
				require.Equal(t, int64(1), value.Count)
				require.Equal(t, []byte("bar"), value.Kvs[0].Value)
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Log(tt.name)
		args := tt.setupArgs()
		want := tt.setupWanted()
		err := client.DeleteIfLocked(context.TODO(), args.key, args.lock)
		require.Equal(t, want.err, err)
		err = tt.cleanup(args)
		require.NoError(t, err)
	}
}

func TestUpdateIfLocked(t *testing.T) {
	client, e := setupEtcdLockedSuite(t)

	randomPath := t.TempDir()
	type args struct {
		key      string
		lock     KVLocker
		newValue []byte
		lease    bool
	}
	type wanted struct {
		err error
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() wanted
		cleanup     func(args args) error
	}{
		{
			name: "update locked path without lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := client.LockPath(context.Background(), "locks/"+key+"/.lock")
				require.NoError(t, err)
				_, err = e.Put(context.Background(), key, "bar")
				require.NoError(t, err)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("newbar"),
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: nil,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was actually updated
				gr, err := e.Get(context.Background(), key)
				require.NoError(t, err)
				require.Equal(t, int64(1), gr.Count)
				require.Equal(t, []byte("newbar"), gr.Kvs[0].Value)

				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "update locked path with no value without lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := client.LockPath(context.Background(), "locks/"+key+"/.lock")
				require.NoError(t, err)

				_, err = e.Delete(context.Background(), key)
				require.NoError(t, err)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("newbar"),
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: nil,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// a key that was updated with no value will create a new value
				gr, err := e.Get(context.Background(), key)
				require.NoError(t, err)
				require.Equal(t, int64(1), gr.Count)
				require.Equal(t, []byte("newbar"), gr.Kvs[0].Value)

				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "update locked path where lock was lost without lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := client.LockPath(context.Background(), "locks/"+key+"/.lock")
				require.NoError(t, err)
				_, err = e.Put(context.Background(), key, "bar")
				require.NoError(t, err)
				err = kvlocker.Unlock(context.TODO())
				require.NoError(t, err)

				return args{
					key:  key,
					lock: kvlocker,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: ErrLockLeaseExpired,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was actually updated
				gr, err := e.Get(context.Background(), key)
				require.NoError(t, err)
				require.Equal(t, int64(1), gr.Count)
				require.Equal(t, []byte("bar"), gr.Kvs[0].Value)
				return nil
			},
		},
		{
			name: "update locked path with lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := client.LockPath(context.Background(), "locks/"+key+"/.lock")
				require.NoError(t, err)
				_, err = e.Put(context.Background(), key, "bar")
				require.NoError(t, err)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("newbar"),
					lease:    true,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: nil,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was actually updated
				gr, err := e.Get(context.Background(), key)
				require.NoError(t, err)
				require.Equal(t, int64(1), gr.Count)
				require.Equal(t, []byte("newbar"), gr.Kvs[0].Value)

				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "update locked path with no value with lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := client.LockPath(context.Background(), "locks/"+key+"/.lock")
				require.NoError(t, err)

				_, err = e.Delete(context.Background(), key)
				require.NoError(t, err)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("newbar"),
					lease:    true,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: nil,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// a key that was updated with no value will create a new value
				gr, err := e.Get(context.Background(), key)
				require.NoError(t, err)
				require.Equal(t, int64(1), gr.Count)
				require.Equal(t, []byte("newbar"), gr.Kvs[0].Value)

				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "update locked path where lock was lost with lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := client.LockPath(context.Background(), "locks/"+key+"/.lock")
				require.NoError(t, err)
				_, err = e.Put(context.Background(), key, "bar")
				require.NoError(t, err)
				err = kvlocker.Unlock(context.TODO())
				require.NoError(t, err)

				return args{
					key:   key,
					lock:  kvlocker,
					lease: true,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: ErrLockLeaseExpired,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was actually updated
				gr, err := e.Get(context.Background(), key)
				require.NoError(t, err)
				require.Equal(t, int64(1), gr.Count)
				require.Equal(t, []byte("bar"), gr.Kvs[0].Value)
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Log(tt.name)
		args := tt.setupArgs()
		want := tt.setupWanted()
		err := client.UpdateIfLocked(context.Background(), args.key, args.newValue, args.lease, args.lock)
		require.Equal(t, want.err, err)
		err = tt.cleanup(args)
		require.NoError(t, err)
	}
}

func TestUpdateIfDifferentIfLocked(t *testing.T) {
	client, e := setupEtcdLockedSuite(t)

	randomPath := t.TempDir()
	type args struct {
		key      string
		lock     KVLocker
		newValue []byte
		lease    bool
	}
	type wanted struct {
		err     error
		updated bool
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() wanted
		cleanup     func(args args) error
	}{
		{
			name: "update locked path without lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := client.LockPath(context.Background(), "locks/"+key+"/.lock")
				require.NoError(t, err)
				_, err = e.Put(context.Background(), key, "bar")
				require.NoError(t, err)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("newbar"),
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err:     nil,
					updated: true,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was actually updated
				gr, err := e.Get(context.Background(), key)
				require.NoError(t, err)
				require.Equal(t, int64(1), gr.Count)
				require.Equal(t, []byte("newbar"), gr.Kvs[0].Value)
				_, err = e.Delete(context.Background(), key)
				require.NoError(t, err)
				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "update locked path without lease and with same value",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := client.LockPath(context.Background(), "locks/"+key+"/.lock")
				require.NoError(t, err)
				_, err = e.Put(context.Background(), key, "bar")
				require.NoError(t, err)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("bar"),
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: nil,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was actually updated
				gr, err := e.Get(context.Background(), key)
				require.NoError(t, err)
				require.Equal(t, int64(1), gr.Count)
				require.Equal(t, []byte("bar"), gr.Kvs[0].Value)

				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "update locked path with no value without lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := client.LockPath(context.Background(), "locks/"+key+"/.lock")
				require.NoError(t, err)

				_, err = e.Delete(context.Background(), key)
				require.NoError(t, err)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("newbar"),
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err:     nil,
					updated: true,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// a key that was updated with no value will create a new value
				gr, err := e.Get(context.Background(), key)
				require.NoError(t, err)
				require.Equal(t, int64(1), gr.Count)
				require.Equal(t, []byte("newbar"), gr.Kvs[0].Value)
				_, err = e.Delete(context.Background(), key)
				require.NoError(t, err)
				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "update locked path where lock was lost without lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := client.LockPath(context.Background(), "locks/"+key+"/.lock")
				require.NoError(t, err)
				_, err = e.Put(context.Background(), key, "bar")
				require.NoError(t, err)
				err = kvlocker.Unlock(context.TODO())
				require.NoError(t, err)

				return args{
					key:      key,
					newValue: []byte("baz"),
					lock:     kvlocker,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: ErrLockLeaseExpired,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was actually updated
				gr, err := e.Get(context.Background(), key)
				require.NoError(t, err)
				require.Equal(t, int64(1), gr.Count)
				require.Equal(t, []byte("bar"), gr.Kvs[0].Value)
				_, err = e.Delete(context.Background(), key)
				require.NoError(t, err)
				return nil
			},
		},
		{
			name: "update locked path with lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := client.LockPath(context.Background(), "locks/"+key+"/.lock")
				require.NoError(t, err)
				_, err = e.Put(context.Background(), key, "bar")
				require.NoError(t, err)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("newbar"),
					lease:    true,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err:     nil,
					updated: true,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was actually updated
				gr, err := e.Get(context.Background(), key)
				require.NoError(t, err)
				require.Equal(t, int64(1), gr.Count)
				require.Equal(t, []byte("newbar"), gr.Kvs[0].Value)
				_, err = e.Delete(context.Background(), key)
				require.NoError(t, err)
				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "update locked path with no value with lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := client.LockPath(context.Background(), "locks/"+key+"/.lock")
				require.NoError(t, err)

				_, err = e.Delete(context.Background(), key)
				require.NoError(t, err)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("newbar"),
					lease:    true,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err:     nil,
					updated: true,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// a key that was updated with no value will create a new value
				gr, err := e.Get(context.Background(), key)
				require.NoError(t, err)
				require.Equal(t, int64(1), gr.Count)
				require.Equal(t, []byte("newbar"), gr.Kvs[0].Value)

				_, err = e.Delete(context.Background(), key)
				require.NoError(t, err)

				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "update locked path with lease and with same value",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := client.LockPath(context.Background(), "locks/"+key+"/.lock")
				require.NoError(t, err)
				created, err := client.CreateOnly(context.Background(), key, []byte("bar"), true)
				require.NoError(t, err)
				require.True(t, created)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("bar"),
					lease:    true,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: nil,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was actually updated
				gr, err := e.Get(context.Background(), key)
				require.NoError(t, err)
				require.Equal(t, int64(1), gr.Count)
				require.Equal(t, []byte("bar"), gr.Kvs[0].Value)
				_, err = e.Delete(context.Background(), key)
				require.NoError(t, err)
				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "update locked path where lock was lost with lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := client.LockPath(context.Background(), "locks/"+key+"/.lock")
				require.NoError(t, err)
				_, err = e.Put(context.Background(), key, "bar")
				require.NoError(t, err)
				err = kvlocker.Unlock(context.TODO())
				require.NoError(t, err)

				return args{
					key:   key,
					lock:  kvlocker,
					lease: true,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: ErrLockLeaseExpired,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was actually updated
				gr, err := e.Get(context.Background(), key)
				require.NoError(t, err)
				require.Equal(t, int64(1), gr.Count)
				require.Equal(t, []byte("bar"), gr.Kvs[0].Value)
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Log(tt.name)
		args := tt.setupArgs()
		want := tt.setupWanted()
		updated, err := client.UpdateIfDifferentIfLocked(context.Background(), args.key, args.newValue, args.lease, args.lock)
		require.Equal(t, want.err, err)
		require.Equal(t, want.updated, updated)
		err = tt.cleanup(args)
		require.NoError(t, err)
	}
}

func TestCreateOnlyIfLocked(t *testing.T) {
	client, e := setupEtcdLockedSuite(t)

	randomPath := t.TempDir()
	type args struct {
		key      string
		lock     KVLocker
		newValue []byte
		lease    bool
	}
	type wanted struct {
		err     error
		created bool
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() wanted
		cleanup     func(args args) error
	}{
		{
			name: "create only locked path without lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := client.LockPath(context.Background(), "locks/"+key+"/.lock")
				require.NoError(t, err)

				_, err = e.Delete(context.Background(), key)
				require.NoError(t, err)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("newbar"),
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err:     nil,
					created: true,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was actually created
				gr, err := e.Get(context.Background(), key)
				require.NoError(t, err)
				require.Equal(t, int64(1), gr.Count)
				require.Equal(t, []byte("newbar"), gr.Kvs[0].Value)

				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "create only locked path with an existing value without lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := client.LockPath(context.Background(), "locks/"+key+"/.lock")
				require.NoError(t, err)

				_, err = e.Put(context.Background(), key, "bar")
				require.NoError(t, err)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("newbar"),
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: nil,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// the key should not have been created and therefore the old
				// value is still there
				gr, err := e.Get(context.Background(), key)
				require.NoError(t, err)
				require.Equal(t, int64(1), gr.Count)
				require.Equal(t, []byte("bar"), gr.Kvs[0].Value)

				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "create only locked path where lock was lost without lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := client.LockPath(context.Background(), "locks/"+key+"/.lock")
				require.NoError(t, err)
				_, err = e.Delete(context.Background(), key)
				require.NoError(t, err)
				err = kvlocker.Unlock(context.TODO())
				require.NoError(t, err)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("bar"),
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: ErrLockLeaseExpired,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was not created
				gr, err := e.Get(context.Background(), key)
				require.NoError(t, err)
				require.Equal(t, int64(0), gr.Count)
				return nil
			},
		},
		{
			name: "create only locked path with lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := client.LockPath(context.Background(), "locks/"+key+"/.lock")
				require.NoError(t, err)

				_, err = e.Delete(context.Background(), key)
				require.NoError(t, err)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("newbar"),
					lease:    true,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err:     nil,
					created: true,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was actually created
				gr, err := e.Get(context.Background(), key)
				require.NoError(t, err)
				require.Equal(t, int64(1), gr.Count)
				require.Equal(t, []byte("newbar"), gr.Kvs[0].Value)

				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "create only locked path with an existing value with lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := client.LockPath(context.Background(), "locks/"+key+"/.lock")
				require.NoError(t, err)

				_, err = e.Put(context.Background(), key, "bar")
				require.NoError(t, err)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("newbar"),
					lease:    true,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: nil,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// the key should not have been created and therefore the old
				// value is still there
				gr, err := e.Get(context.Background(), key)
				require.NoError(t, err)
				require.Equal(t, int64(1), gr.Count)
				require.Equal(t, []byte("bar"), gr.Kvs[0].Value)

				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "create only locked path where lock was lost with lease",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := client.LockPath(context.Background(), "locks/"+key+"/.lock")
				require.NoError(t, err)
				_, err = e.Delete(context.Background(), key)
				require.NoError(t, err)
				err = kvlocker.Unlock(context.TODO())
				require.NoError(t, err)

				return args{
					key:      key,
					lock:     kvlocker,
					newValue: []byte("bar"),
					lease:    true,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: ErrLockLeaseExpired,
				}
			},
			cleanup: func(args args) error {
				key := randomPath + "foo"
				// verify that key was not created
				gr, err := e.Get(context.Background(), key)
				require.NoError(t, err)
				require.Equal(t, int64(0), gr.Count)
				return nil
			},
		},
	}
	for _, tt := range tests {
		t.Log(tt.name)
		args := tt.setupArgs()
		want := tt.setupWanted()
		created, err := client.CreateOnlyIfLocked(context.Background(), args.key, args.newValue, args.lease, args.lock)
		require.Equal(t, want.err, err)
		require.Equal(t, want.created, created)
		err = tt.cleanup(args)
		require.NoError(t, err)
	}
}

func TestListPrefixIfLocked(t *testing.T) {
	client, e := setupEtcdLockedSuite(t)

	randomPath := t.TempDir()
	type args struct {
		key  string
		lock KVLocker
	}
	type wanted struct {
		err     error
		kvPairs KeyValuePairs
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWanted func() wanted
		cleanup     func(args args) error
	}{
		{
			name: "list prefix locked",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := client.LockPath(context.Background(), "locks/"+key+"/.lock")
				require.NoError(t, err)
				_, err = e.Put(context.Background(), key, "bar")
				require.NoError(t, err)
				_, err = e.Put(context.Background(), key+"1", "bar1")
				require.NoError(t, err)

				return args{
					key:  key,
					lock: kvlocker,
				}
			},
			setupWanted: func() wanted {
				key := randomPath + "foo"
				return wanted{
					err: nil,
					kvPairs: KeyValuePairs{
						key: Value{
							Data: []byte("bar"),
						},
						key + "1": Value{
							Data: []byte("bar1"),
						},
					},
				}
			},
			cleanup: func(args args) error {
				_, err := e.Delete(context.Background(), args.key, etcdAPI.WithPrefix())
				if err != nil {
					return err
				}
				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "list prefix locked with no values",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := client.LockPath(context.Background(), "locks/"+key+"/.lock")
				require.NoError(t, err)
				_, err = e.Delete(context.Background(), key, etcdAPI.WithPrefix())
				require.NoError(t, err)

				return args{
					key:  key,
					lock: kvlocker,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: nil,
				}
			},
			cleanup: func(args args) error {
				return args.lock.Unlock(context.TODO())
			},
		},
		{
			name: "list prefix locked where lock was lost",
			setupArgs: func() args {
				key := randomPath + "foo"
				kvlocker, err := client.LockPath(context.Background(), "locks/"+key+"/.lock")
				require.NoError(t, err)
				_, err = e.Put(context.Background(), key, "bar")
				require.NoError(t, err)
				_, err = e.Put(context.Background(), key+"1", "bar1")
				require.NoError(t, err)
				err = kvlocker.Unlock(context.TODO())
				require.NoError(t, err)

				return args{
					key:  key,
					lock: kvlocker,
				}
			},
			setupWanted: func() wanted {
				return wanted{
					err: ErrLockLeaseExpired,
				}
			},
			cleanup: func(args args) error {
				_, err := e.Delete(context.Background(), args.key)
				return err
			},
		},
	}
	for _, tt := range tests {
		t.Log(tt.name)
		args := tt.setupArgs()
		want := tt.setupWanted()
		kvPairs, err := client.ListPrefixIfLocked(context.TODO(), args.key, args.lock)
		require.Equal(t, want.err, err)
		for k, v := range kvPairs {
			// We don't compare revision of the value because we can't predict
			// its value.
			v1, ok := want.kvPairs[k]
			require.True(t, ok)
			require.Equal(t, v1.Data, v.Data)
		}
		err = tt.cleanup(args)
		require.NoError(t, err)
	}
}

func TestShuffleEndpoints(t *testing.T) {
	s1 := []string{"1", "2", "3", "4", "5"}
	s2 := make([]string, len(s1))
	copy(s2, s1)

	var same int
	for range 10 {
		same = 0
		shuffleEndpoints(s2)
		for i := range s1 {
			if s1[i] == s2[i] {
				same++
			}
		}
		if same != len(s1) {
			break
		}
	}
	if same == len(s1) {
		t.Errorf("Shuffle() did not modify s2 in 10 retries")
	}
}

func TestEtcdRateLimiter(t *testing.T) {
	testutils.IntegrationTest(t)

	t.Run("with QPS=100", func(t *testing.T) {
		testEtcdRateLimiter(t, 100, 10, require.Less)
	})

	t.Run("with QPS=4", func(t *testing.T) {
		testEtcdRateLimiter(t, 4, 10, require.Greater)
	})
}

func testEtcdRateLimiter(t *testing.T, qps, count int, cmp func(require.TestingT, any, any, ...any)) {
	const (
		prefix  = "foo"
		condKey = prefix + "-cond-key"
		value   = "bar"

		threshold = time.Second
	)

	ctx := context.Background()
	getKey := func(id int) string {
		return fmt.Sprintf("%s-%d", prefix, id)
	}

	// Initialize a separate etcd client which is not subject to any rate limiting
	cfg := etcdAPI.Config{
		Endpoints:   []string{etcdDummyAddress},
		DialTimeout: 5 * time.Second,
	}
	etcdClient, err := etcdAPI.New(cfg)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, etcdClient.Close())
	})

	tests := []struct {
		fn              func(*testing.T, BackendOperations, string, int, KVLocker)
		name            string
		useKVLocker     bool
		needCondKey     bool
		populateKVPairs bool
	}{
		{
			fn: func(t *testing.T, client BackendOperations, key string, k int, locker KVLocker) {
				val, err := client.GetIfLocked(ctx, getKey(k), locker)
				require.NoError(t, err)
				require.Equal(t, []byte(value), val)
			},
			name:            "GetIfLocked",
			useKVLocker:     true,
			populateKVPairs: true,
		},
		{
			fn: func(t *testing.T, client BackendOperations, key string, k int, _ KVLocker) {
				val, err := client.Get(ctx, getKey(k))
				require.NoError(t, err)
				require.Equal(t, []byte(value), val)
			},
			name:            "Get",
			populateKVPairs: true,
		},
		{
			fn: func(t *testing.T, client BackendOperations, key string, k int, _ KVLocker) {
				kvPairs, err := client.ListPrefix(ctx, getKey(k))
				require.NoError(t, err)
				require.Len(t, kvPairs, 1)
				val, ok := kvPairs[getKey(k)]
				require.True(t, ok)
				require.Equal(t, []byte(value), val.Data)
			},
			name:            "ListPrefix",
			populateKVPairs: true,
		},
		{
			fn: func(t *testing.T, client BackendOperations, key string, k int, locker KVLocker) {
				kvPairs, err := client.ListPrefixIfLocked(ctx, getKey(k), locker)
				require.NoError(t, err)
				require.Len(t, kvPairs, 1)
				val, ok := kvPairs[getKey(k)]
				require.True(t, ok)
				require.Equal(t, []byte(value), val.Data)
			},
			name:            "ListPrefixIfLocked",
			useKVLocker:     true,
			populateKVPairs: true,
		},
		{
			fn: func(t *testing.T, client BackendOperations, key string, k int, _ KVLocker) {
				updated, err := client.UpdateIfDifferent(ctx, getKey(k), []byte("bar-new"), true)
				require.NoError(t, err)
				require.True(t, updated)
			},
			name:            "UpdateIfDifferent",
			populateKVPairs: true,
		},
		{
			fn: func(t *testing.T, client BackendOperations, key string, k int, locker KVLocker) {
				updated, err := client.UpdateIfDifferentIfLocked(ctx, getKey(k), []byte("bar-new"), true, locker)
				require.NoError(t, err)
				require.True(t, updated)
			},
			name:            "UpdateIfDifferentIfLocked",
			useKVLocker:     true,
			populateKVPairs: true,
		},
		{
			fn: func(t *testing.T, client BackendOperations, key string, k int, _ KVLocker) {
				err := client.Update(ctx, getKey(k), []byte(value), true)
				require.NoError(t, err)
			},
			name: "Update",
		},
		{
			fn: func(t *testing.T, client BackendOperations, key string, k int, locker KVLocker) {
				err := client.UpdateIfLocked(ctx, getKey(k), []byte(value), true, locker)
				require.NoError(t, err)
			},
			name:        "UpdateIfLocked",
			useKVLocker: true,
		},
		{
			fn: func(t *testing.T, client BackendOperations, key string, k int, _ KVLocker) {
				created, err := client.CreateOnly(ctx, getKey(k), []byte(value), true)
				require.NoError(t, err)
				require.True(t, created)
			},
			name: "CreateOnly",
		},
		{
			fn: func(t *testing.T, client BackendOperations, key string, k int, locker KVLocker) {
				created, err := client.CreateOnlyIfLocked(ctx, getKey(k), []byte(value), true, locker)
				require.NoError(t, err)
				require.True(t, created)
			},
			name:        "CreateOnlyIfLocked",
			useKVLocker: true,
		},
		{
			fn: func(t *testing.T, client BackendOperations, key string, k int, _ KVLocker) {
				err := client.Delete(ctx, getKey(k))
				require.NoError(t, err)
			},
			name:            "Delete",
			populateKVPairs: true,
		},
		{
			fn: func(t *testing.T, client BackendOperations, key string, k int, locker KVLocker) {
				err := client.DeleteIfLocked(ctx, getKey(k), locker)
				require.NoError(t, err)
			},
			name:            "DeleteIfLocked",
			useKVLocker:     true,
			populateKVPairs: true,
		},
		{
			fn: func(t *testing.T, client BackendOperations, key string, k int, _ KVLocker) {
				err := client.DeletePrefix(ctx, getKey(k))
				require.NoError(t, err)
			},
			name:            "DeletePrefix",
			useKVLocker:     true,
			populateKVPairs: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				kvlocker KVLocker
				err      error
			)

			client := SetupDummyWithConfigOpts(t, "etcd", map[string]string{
				EtcdRateLimitOption: fmt.Sprintf("%d", qps),
			})

			if tt.populateKVPairs {
				for i := range count {
					_, err := etcdClient.Put(ctx, getKey(i), value)
					require.NoError(t, err)
				}
			}

			if tt.needCondKey {
				_, err = etcdClient.Put(ctx, condKey, value)
				require.NoError(t, err)
			}

			if tt.useKVLocker {
				kvlocker, err = client.LockPath(ctx, "locks/"+prefix+"/.lock")
				require.NoError(t, err)

				t.Cleanup(func() {
					require.NoError(t, kvlocker.Unlock(ctx))
				})
			}

			start := time.Now()
			wg := sync.WaitGroup{}
			for i := range count {
				wg.Add(1)
				go func(wg *sync.WaitGroup, i int) {
					defer wg.Done()
					tt.fn(t, client, prefix, i, kvlocker)
				}(&wg, i)
			}
			wg.Wait()

			cmp(t, time.Since(start), threshold)
		})
	}
}

type kvWrapper struct {
	etcdAPI.KV
	postGet func(context.Context) error
}

func (kvw *kvWrapper) Get(ctx context.Context, key string, opts ...etcdAPI.OpOption) (*etcdAPI.GetResponse, error) {
	res, err := kvw.KV.Get(ctx, key, opts...)
	if err != nil {
		return res, err
	}

	return res, kvw.postGet(ctx)
}

func TestPaginatedList(t *testing.T) {
	testutils.IntegrationTest(t)
	client := SetupDummyWithConfigOpts(t, "etcd", etcdOpts)

	const prefix = "list/paginated"
	ctx := context.Background()

	run := func(t *testing.T, batch int, withParallelOps bool) {
		cl := client.(*etcdClient)
		keys := map[string]struct{}{
			path.Join(prefix, "immortal-finch"):   {},
			path.Join(prefix, "rare-goshawk"):     {},
			path.Join(prefix, "cunning-bison"):    {},
			path.Join(prefix, "amusing-tick"):     {},
			path.Join(prefix, "prepared-shark"):   {},
			path.Join(prefix, "exciting-mustang"): {},
			path.Join(prefix, "ethical-ibex"):     {},
			path.Join(prefix, "accepted-kite"):    {},
			path.Join(prefix, "model-javelin"):    {},
			path.Join(prefix, "inviting-hog"):     {},
		}

		defer func(previous int) {
			cl.listBatchSize = previous
			require.NoError(t, cl.DeletePrefix(ctx, prefix))
		}(cl.listBatchSize)
		cl.listBatchSize = batch

		var next int64
		if withParallelOps {
			pkv := cl.client.KV
			defer func() { cl.client.KV = pkv }()

			cl.client.KV = &kvWrapper{
				KV: pkv,
				// paginatedList should observe neither upsertions nor deletions
				// performed after that the initial chunk of entries was retrieved.
				postGet: func(ctx context.Context) error {
					key := path.Join(prefix, rand.String(10))
					res, err := cl.client.Put(ctx, key, "value")
					if err != nil {
						return err
					}

					if next == 0 {
						next = res.Header.Revision
					}

					_, err = cl.client.Delete(ctx, slices.Collect(maps.Keys(keys))[0])
					return err
				},
			}
		}

		var expected int64
		for key := range keys {
			res, err := cl.client.Put(ctx, key, "value")
			expected = res.Header.Revision
			require.NoError(t, err)
		}

		kvs, found, err := cl.paginatedList(ctx, hivetest.Logger(t), prefix)
		require.NoError(t, err)

		for _, kv := range kvs {
			key := string(kv.Key)
			if _, ok := keys[key]; !ok {
				t.Fatalf("Retrieved unexpected key, key: %s", key)
			}
			delete(keys, key)
		}

		require.Empty(t, keys)

		// There is no guarantee that found == expected, because new operations might have occurred in parallel.
		if found < expected {
			t.Fatalf("Next revision (%d) is lower than the one of the last update (%d)", found, expected)
		}

		if withParallelOps && found >= next {
			t.Fatalf("Next revision (%d) is higher than the one of subsequent updates (%d)", found, next)
		}
	}

	for _, batchSize := range []int{1, 4, 11} {
		for _, parallelOps := range []bool{false, true} {
			t.Run(fmt.Sprintf("batch-size-%d-parallel-ops-%t", batchSize, parallelOps),
				func(t *testing.T) { run(t, batchSize, parallelOps) })
		}
	}
}
