// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"sync"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"

	pb "github.com/cilium/cilium/api/v1/standalone-dns-proxy"
)

func newBufConn(t *testing.T) (*grpc.ClientConn, func()) {
	cc, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	cleanup := func() {
		_ = cc.Close()
	}
	return cc, cleanup
}

func TestConnectionManagerLifecycle(t *testing.T) {
	defer testutils.GoleakVerifyNone(t)

	cm := newConnectionManager(hivetest.Logger(t))

	// ---- Blocking check (disconnected) ----
	startBlocked := make(chan struct{})
	unblocked := make(chan struct{})
	go func() {
		close(startBlocked)
		_, _, _ = cm.getFqdnClientWithRev() // should block until first connect
		close(unblocked)
	}()
	<-startBlocked
	// Ensure it is still blocked after a short delay.
	select {
	case <-unblocked:
		t.Fatalf("waiter returned while disconnected (should block)")
	case <-time.After(120 * time.Millisecond):
	}

	// 1. Spawn waiters before any connection.
	const waiters = 50
	var wg sync.WaitGroup
	wg.Add(waiters)
	errs := make([]error, waiters)
	clients := make([]pb.FQDNDataClient, waiters)
	clientsRev := make([]uint64, waiters)
	for i := range waiters {
		go func(i int) {
			defer wg.Done()
			clients[i], clientsRev[i], errs[i] = cm.getFqdnClientWithRev()
		}(i)
	}

	listenEv := func(expectedRev uint64, expectedConn bool) {
		ev := <-cm.Events()
		require.Equal(t, expectedConn, ev.Connected)
		require.Equal(t, expectedRev, ev.Rev)

	}
	// 2. Create first connection.
	cc1, cleanup1 := newBufConn(t)
	defer cleanup1()
	rev1 := cm.updateConnection(cc1)
	require.True(t, cm.isConnected())

	// 3. Listen for the connection event
	listenEv(rev1, true)

	// Original blocked waiter should now finish quickly.
	select {
	case <-unblocked:
	case <-time.After(time.Second):
		t.Fatalf("initial blocked waiter did not unblock after connect")
	}

	wg.Wait()
	for i := range waiters {
		require.NoError(t, errs[i], "waiter %d error", i)
		require.NotNil(t, clients[i], "waiter %d nil client", i)
		require.Equal(t, rev1, clientsRev[i], "waiter %d revision mismatch", i)
	}

	// 3. Replace connection; verify revision increased and old conn transitions to Shutdown soon.
	cc2, cleanup2 := newBufConn(t)
	defer cleanup2()
	rev2 := cm.updateConnection(cc2)
	require.Greater(t, rev2, rev1)
	err := testutils.WaitUntil(cm.isConnected, 2*time.Second)
	require.NoError(t, err, "not connected after replacement")
	// Listen for the connection event
	listenEv(rev2, true)

	// 4. Stale removal should fail.
	cleared := cm.removeConnection(rev1)
	require.False(t, cleared, "stale clear succeeded unexpectedly")

	// 5. Correct removal works.
	cleared = cm.removeConnection(rev2)
	require.True(t, cleared)
	require.False(t, cm.isConnected())
	// Listen for the disconnection event, the revision should have bumped by 1
	listenEv(rev2+1, false)

	// 6. Create a new connection again.
	cc3, cleanup3 := newBufConn(t)
	defer cleanup3()
	rev3 := cm.updateConnection(cc3)
	require.True(t, cm.isConnected())
	listenEv(rev3, true)

	// Close path increments revision and emits final disconnected event.
	err = cm.Close()
	require.NoError(t, err)
	require.False(t, cm.isConnected())

	evClose := <-cm.Events()
	require.False(t, evClose.Connected)
	require.Equal(t, rev3+1, evClose.Rev)
}

func TestConnectionManagerConcurrencyStress(t *testing.T) {
	defer testutils.GoleakVerifyNone(t)

	cm := newConnectionManager(hivetest.Logger(t))

	const (
		updaters = 8
		waiters  = 60
		removers = 8
	)

	var updaterWG, waiterWG, removerWG sync.WaitGroup
	revisionCh := make(chan uint64, 2000)

	// Event consumer (single reader to avoid races).
	var evWG sync.WaitGroup
	evStop := make(chan struct{})
	type evStats struct {
		connectedEvents    int
		disconnectedEvents int
		lastRev            uint64
	}
	var statsMu lock.Mutex
	st := evStats{}
	evWG.Go(func() {
		for {
			select {
			case <-evStop:
				return
			case ev := <-cm.Events():
				statsMu.Lock()
				if ev.Connected {
					st.connectedEvents++
				} else {
					st.disconnectedEvents++
				}
				if ev.Rev > st.lastRev {
					st.lastRev = ev.Rev
				}
				statsMu.Unlock()
			}
		}
	})

	// Updaters: alternate between connected / nil.
	updaterWG.Add(updaters)
	for range updaters {
		go func() {
			defer updaterWG.Done()
			for i := range 80 {
				if i%2 == 0 {
					cc, cleanup := newBufConn(t)
					r := cm.updateConnection(cc)
					revisionCh <- r
					cleanup()
				} else {
					r := cm.updateConnection(nil)
					revisionCh <- r
				}
			}
		}()
	}

	// Waiters: each waits once until it gets a connected client (or times out).
	waiterWG.Add(waiters)
	for range waiters {
		go func() {
			defer waiterWG.Done()
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				c, rev, err := cm.getFqdnClientWithRev()
				if err == nil && c != nil && rev > 0 {
					return
				}
			}
			t.Errorf("waiter timeout")
		}()
	}

	// Removers: aggressively try to remove both stale and current revisions.
	removerWG.Add(removers)
	for range removers {
		go func() {
			defer removerWG.Done()
			for range 160 {
				cm.mu.RLock()
				cur := cm.revision
				cm.mu.RUnlock()
				if cur > 1 {
					_ = cm.removeConnection(cur - 1)
				}
				_ = cm.removeConnection(cur)
			}
		}()
	}

	updaterWG.Wait()
	waiterWG.Wait()
	removerWG.Wait()
	close(revisionCh)

	// Stop event reader.
	close(evStop)
	evWG.Wait()

	// Basic event sanity: lastRev should be >= last (events emitted after revision bump).
	statsMu.Lock()
	defer statsMu.Unlock()
	// We expect at least one connected and one disconnected event in churn.
	require.Positive(t, st.connectedEvents, "no connected events recorded")
	require.Positive(t, st.disconnectedEvents, "no disconnected events recorded")
}
