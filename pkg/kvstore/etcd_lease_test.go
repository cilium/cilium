// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	v3rpcErrors "go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	client "go.etcd.io/etcd/client/v3"
)

var (
	// ErrNotImplemented is the error which is returned when a functionality is not implemented.
	ErrNotImplemented = errors.New("not implemented")
)

type fakeEtcdLeaseClient struct {
	ctx                context.Context
	expectedTTLSeconds int64
	grantDelay         time.Duration

	lease    client.LeaseID
	contexts map[client.LeaseID]context.Context
}

func newFakeEtcdClient(leases *fakeEtcdLeaseClient) *client.Client {
	cl := client.NewCtxClient(leases.ctx)
	cl.Lease = leases
	return cl
}

func newFakeEtcdLeaseClient(ctx context.Context, expectedTTLSeconds int64) fakeEtcdLeaseClient {
	return fakeEtcdLeaseClient{
		ctx:                ctx,
		expectedTTLSeconds: expectedTTLSeconds,
		contexts:           make(map[client.LeaseID]context.Context),
	}
}

func (f *fakeEtcdLeaseClient) Grant(ctx context.Context, ttl int64) (*client.LeaseGrantResponse, error) {
	time.Sleep(f.grantDelay)

	f.lease++
	if ttl != f.expectedTTLSeconds {
		return nil, fmt.Errorf("incorrect TTL, expected: %v, found: %v", f.expectedTTLSeconds, ttl)
	}

	return &client.LeaseGrantResponse{ID: f.lease}, nil
}

func (f *fakeEtcdLeaseClient) KeepAlive(ctx context.Context, id client.LeaseID) (<-chan *client.LeaseKeepAliveResponse, error) {
	if id != f.lease {
		return nil, fmt.Errorf("incorrect lease ID, expected: %v, found: %v", f.lease, id)
	}

	ch := make(chan *client.LeaseKeepAliveResponse)
	go func() {
		<-ctx.Done()
		close(ch)
	}()

	f.contexts[id] = ctx
	return ch, nil
}

func (f *fakeEtcdLeaseClient) Revoke(ctx context.Context, id client.LeaseID) (*client.LeaseRevokeResponse, error) {
	return nil, ErrNotImplemented
}
func (f *fakeEtcdLeaseClient) TimeToLive(ctx context.Context, id client.LeaseID, opts ...client.LeaseOption) (*client.LeaseTimeToLiveResponse, error) {
	return nil, ErrNotImplemented
}
func (f *fakeEtcdLeaseClient) Leases(ctx context.Context) (*client.LeaseLeasesResponse, error) {
	return nil, ErrNotImplemented
}
func (f *fakeEtcdLeaseClient) KeepAliveOnce(ctx context.Context, id client.LeaseID) (*client.LeaseKeepAliveResponse, error) {
	return nil, ErrNotImplemented
}
func (f *fakeEtcdLeaseClient) Close() error { return ErrNotImplemented }

func TestLeaseManager(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cl := newFakeEtcdLeaseClient(ctx, 10)
	mgr := newEtcdLeaseManager(newFakeEtcdClient(&cl), 10*time.Second, 5, nil, log)

	t.Cleanup(func() {
		cancel()
		mgr.Wait()
	})

	// Get the lease ID five times, and assert that the same ID is always returned
	for i := 0; i < 5; i++ {
		leaseID, err := mgr.GetLeaseID(ctx, fmt.Sprintf("key%d", i))
		require.NoError(t, err, "GetLeaseID should succeed")
		require.Equal(t, client.LeaseID(1), leaseID)
	}

	// Get the lease ID five more times, and assert that the same ID is always returned
	for i := 0; i < 5; i++ {
		leaseID, err := mgr.GetLeaseID(ctx, fmt.Sprintf("key%d", i+5))
		require.NoError(t, err, "GetLeaseID should succeed")
		require.Equal(t, client.LeaseID(2), leaseID)
	}

	// Release a few IDs and acquire than back
	mgr.Release("key2")
	mgr.Release("key4")

	leaseID, err := mgr.GetLeaseID(ctx, "key11")
	require.NoError(t, err, "GetLeaseID should succeed")
	require.Equal(t, client.LeaseID(1), leaseID)

	leaseID, err = mgr.GetLeaseID(ctx, "key12")
	require.NoError(t, err, "GetLeaseID should succeed")
	require.Equal(t, client.LeaseID(1), leaseID)

	// Getting yet another ID, which should be different
	leaseID, err = mgr.GetLeaseID(ctx, "key13")
	require.NoError(t, err, "GetLeaseID should succeed")
	require.Equal(t, client.LeaseID(3), leaseID)

	// Getting an ID for an already known key should return the same lease
	leaseID, err = mgr.GetLeaseID(ctx, "key1")
	require.NoError(t, err, "GetLeaseID should succeed")
	require.Equal(t, client.LeaseID(1), leaseID)

	// Getting a session for an already known key should return the same lease
	session, err := mgr.GetSession(ctx, "key1")
	require.NoError(t, err, "GetSession should succeed")
	require.Equal(t, client.LeaseID(1), session.Lease())

	// Getting a session for a new key should return a different lease
	session, err = mgr.GetSession(ctx, "key14")
	require.NoError(t, err, "GetSession should succeed")
	require.Equal(t, client.LeaseID(3), session.Lease())

	require.Equal(t, uint32(3), mgr.TotalLeases())
}

func TestLeaseManagerParallel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cl := newFakeEtcdLeaseClient(ctx, 10)
	mgr := newEtcdLeaseManager(newFakeEtcdClient(&cl), 10*time.Second, 5, nil, log)

	t.Cleanup(func() {
		cancel()
		mgr.Wait()
	})

	ch := make(chan client.LeaseID)

	// Perform multiple requests in parallel, simulating a slow client, and
	// assert that they all return the same lease ID
	cl.grantDelay = 500 * time.Millisecond

	for i := 0; i < 4; i++ {
		go func(idx int) {
			if idx%2 == 0 {
				leaseID, err := mgr.GetLeaseID(ctx, fmt.Sprintf("key%d", idx))
				require.NoError(t, err, "GetLeaseID should succeed")
				ch <- leaseID
			} else {
				session, err := mgr.GetSession(ctx, fmt.Sprintf("key%d", idx))
				require.NoError(t, err, "GetSession should succeed")
				ch <- session.Lease()
			}
		}(i)
	}

	for i := 0; i < 4; i++ {
		require.Equal(t, client.LeaseID(1), <-ch)
	}
}

func TestLeaseManagerReleasePrefix(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cl := newFakeEtcdLeaseClient(ctx, 10)
	mgr := newEtcdLeaseManager(newFakeEtcdClient(&cl), 10*time.Second, 5, nil, log)

	t.Cleanup(func() {
		cancel()
		mgr.Wait()
	})

	for i := 0; i < 9; i++ {
		leaseID, err := mgr.GetLeaseID(ctx, fmt.Sprintf("key%d%d", i/3, i))
		require.NoError(t, err, "GetLeaseID should succeed")
		require.Equal(t, client.LeaseID(1+i/5), leaseID)
	}

	// Delete the prefix which includes keys attached to both leases
	mgr.ReleasePrefix("key1")

	for i := 0; i < 9; i++ {
		// Verify that the leases for the keys matching the prefix have been
		// released, and that the others are still in place.
		require.Equal(t, i/3 != 1, mgr.KeyHasLease(fmt.Sprintf("key%d%d", i/3, i), client.LeaseID(1+i/5)))
	}
}

func TestLeaseManagerCancelIfExpired(t *testing.T) {
	expiredCH := make(chan string)
	observer := func(key string) {
		expiredCH <- key
	}

	ctx, cancel := context.WithCancel(context.Background())
	cl := newFakeEtcdLeaseClient(ctx, 10)
	mgr := newEtcdLeaseManager(newFakeEtcdClient(&cl), 10*time.Second, 5, observer, log)

	t.Cleanup(func() {
		close(expiredCH)
		cancel()
		mgr.Wait()
	})

	for i := 0; i < 15; i++ {
		leaseID, err := mgr.GetLeaseID(ctx, fmt.Sprintf("key%d", i))
		require.NoError(t, err, "GetLeaseID should succeed")
		require.Equal(t, client.LeaseID(1+i/5), leaseID)
	}

	mgr.CancelIfExpired(nil, client.LeaseID(2))
	mgr.CancelIfExpired(fmt.Errorf("something else"), client.LeaseID(2))
	mgr.CancelIfExpired(v3rpcErrors.ErrLeaseNotFound, client.LeaseID(10))

	// The keepalive context should not have been closed
	require.NoError(t, cl.contexts[client.LeaseID(1)].Err())
	require.NoError(t, cl.contexts[client.LeaseID(2)].Err())
	require.NoError(t, cl.contexts[client.LeaseID(3)].Err())

	mgr.CancelIfExpired(v3rpcErrors.ErrLeaseNotFound, client.LeaseID(2))

	// The keepalive context for the second lease should have been closed
	require.NoError(t, cl.contexts[client.LeaseID(1)].Err())
	require.Error(t, cl.contexts[client.LeaseID(2)].Err())
	require.NoError(t, cl.contexts[client.LeaseID(3)].Err())

	// Ensure consistent ordering since the expired entries are retrieved from a map.
	var expired []string
	for i := 0; i < 5; i++ {
		expired = append(expired, <-expiredCH)
	}
	sort.Strings(expired)
	require.ElementsMatch(t, expired, []string{"key5", "key6", "key7", "key8", "key9"})

	// Get the lease for one of the expired keys, and check that it is a different one.
	leaseID, err := mgr.GetLeaseID(ctx, "key7")
	require.NoError(t, err, "GetLeaseID should succeed")
	require.Equal(t, client.LeaseID(4), leaseID)
}

func TestLeaseManagerKeyHasLease(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cl := newFakeEtcdLeaseClient(ctx, 10)
	mgr := newEtcdLeaseManager(newFakeEtcdClient(&cl), 10*time.Second, 5, nil, log)

	t.Cleanup(func() {
		cancel()
		mgr.Wait()
	})

	for i := 0; i < 8; i++ {
		leaseID, err := mgr.GetLeaseID(ctx, fmt.Sprintf("key%d", i))
		require.NoError(t, err, "GetLeaseID should succeed")
		require.Equal(t, client.LeaseID(1+i/5), leaseID)
	}

	// Correct lease ID
	require.True(t, mgr.KeyHasLease("key3", client.LeaseID(1)))
	require.True(t, mgr.KeyHasLease("key7", client.LeaseID(2)))

	// Incorrect lease ID
	require.False(t, mgr.KeyHasLease("key7", client.LeaseID(1)))

	// Non existing key
	require.False(t, mgr.KeyHasLease("key99", client.LeaseID(1)))
}
