// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	v3rpcErrors "go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	client "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/spanstat"
	"github.com/cilium/cilium/pkg/time"
)

type leaseInfo struct {
	count   uint32
	session *concurrency.Session
}

// etcdLeaseManager manages the acquisition of the leases, and keeps track of
// which lease is attached to which etcd key.
type etcdLeaseManager struct {
	client *client.Client
	log    logrus.FieldLogger

	ttl     time.Duration
	limit   uint32
	expired func(key string)

	mu      lock.RWMutex
	leases  map[client.LeaseID]*leaseInfo
	keys    map[string]client.LeaseID
	current client.LeaseID

	acquiring chan struct{}
	wg        sync.WaitGroup
}

// newEtcdLeaseManager builds and returns a new lease manager instance.
func newEtcdLeaseManager(cl *client.Client, ttl time.Duration, limit uint32, expired func(key string), log logrus.FieldLogger) *etcdLeaseManager {
	return &etcdLeaseManager{
		client: cl,
		log:    log,

		ttl:     ttl,
		limit:   limit,
		expired: expired,

		current: client.NoLease,
		leases:  make(map[client.LeaseID]*leaseInfo),
		keys:    make(map[string]client.LeaseID),
	}
}

// GetLeaseID returns a lease ID, and associates it to the given key. It leverages
// one of the already acquired leases if they are not already attached to too many
// keys, otherwise a new one is acquired.
//
// There's a small possibility that the returned lease is already expired, or gets
// expired immediately before use (due the time window between the lease expiration
// on the etcd server and the subsequent client side detection and garbage collection).
// As we cannot completely remove this uncertainty period, let's adopt the easiest
// approach here, without explicitly checking if the lease is expired before returning
// it (given that it would be a client-side check only). Instead, let's just rely on
// the fact that the operation will fail (as the lease is no longer valid), triggering
// a retry. At that point, a new (hopefully valid) lease will be retrieved again.
func (elm *etcdLeaseManager) GetLeaseID(ctx context.Context, key string) (client.LeaseID, error) {
	session, err := elm.GetSession(ctx, key)
	if err != nil {
		return client.NoLease, err
	}

	return session.Lease(), nil
}

// GetSession returns a session, and associates it to the given key. It leverages
// one of the already acquired leases if they are not already attached to too many
// keys, otherwise a new one is acquired.
//
// There's a small possibility that the returned session is already expired, or gets
// expired immediately before use (due the time window between the lease expiration
// on the etcd server and the subsequent client side detection and garbage collection).
// As we cannot completely remove this uncertainty period, let's adopt the easiest
// approach here, without explicitly checking if the session is expired before returning
// it (given that it would be a client-side check only). Instead, let's just rely on
// the fact that the operation will fail (as the lease is no longer valid), triggering
// a retry. At that point, a new (hopefully valid) session will be retrieved again.
func (elm *etcdLeaseManager) GetSession(ctx context.Context, key string) (*concurrency.Session, error) {
	elm.mu.Lock()

	// This key is already attached to a lease, hence just return it.
	if leaseID := elm.keys[key]; leaseID != client.NoLease {
		// The entry is guaranteed to exist if the lease is associated with a key
		info := elm.leases[leaseID]
		elm.mu.Unlock()
		return info.session, nil
	}

	// Return the current lease if it has not been used more than limit times
	if info := elm.leases[elm.current]; info != nil && info.count < elm.limit {
		info.count++
		elm.keys[key] = elm.current
		elm.mu.Unlock()

		return info.session, nil
	}

	// Otherwise, loop through the other known leases to see if any has been released
	for lease, info := range elm.leases {
		if info.count < elm.limit {
			elm.current = lease
			info.count++
			elm.keys[key] = elm.current
			elm.mu.Unlock()

			return info.session, nil
		}
	}

	// If none is found, we need to acquire a new lease. acquiring is a channel
	// used to detect whether we are already in the process of acquiring a new
	// lease, to prevent multiple acquisitions in parallel.
	acquiring := elm.acquiring
	if acquiring == nil {
		elm.acquiring = make(chan struct{})
	}

	// Unlock, so that we don't block other paraller operations (e.g., releases)
	// while acquiring a new lease, since it might be a slow operation.
	elm.mu.Unlock()

	// Someone else is already acquiring a new lease. Wait until
	// it completes, and then retry again.
	if acquiring != nil {
		select {
		case <-acquiring:
			return elm.GetSession(ctx, key)
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-elm.client.Ctx().Done():
			return nil, elm.client.Ctx().Err()
		}
	}

	// Otherwise, we can proceed to acquire a new lease.
	session, err := elm.newSession(ctx)

	elm.mu.Lock()

	// Signal that the acquisition process has completed.
	close(elm.acquiring)
	elm.acquiring = nil

	if err != nil {
		elm.mu.Unlock()
		return nil, err
	}

	elm.current = session.Lease()
	elm.leases[session.Lease()] = &leaseInfo{session: session}
	elm.mu.Unlock()

	return elm.GetSession(ctx, key)
}

// Release decrements the counter of the lease attached to the given key.
func (elm *etcdLeaseManager) Release(key string) {
	elm.mu.Lock()
	defer elm.mu.Unlock()

	elm.releaseUnlocked(key)
}

// ReleasePrefix decrements the counter of the leases attached to the keys
// starting with the given prefix.
func (elm *etcdLeaseManager) ReleasePrefix(prefix string) {
	elm.mu.Lock()
	defer elm.mu.Unlock()

	for key, leaseID := range elm.keys {
		if strings.HasPrefix(key, prefix) {
			if info := elm.leases[leaseID]; info != nil && info.count > 0 {
				info.count--
			}
			delete(elm.keys, key)
		}
	}
}

// KeyHasLease returns whether the given key is associated with the specified lease.
func (elm *etcdLeaseManager) KeyHasLease(key string, leaseID client.LeaseID) bool {
	elm.mu.RLock()
	defer elm.mu.RUnlock()

	return elm.keys[key] == leaseID
}

// CancelIfExpired verifies whether the error reports that the given lease has
// expired, and in that case aborts the corresponding keepalive process.
func (elm *etcdLeaseManager) CancelIfExpired(err error, leaseID client.LeaseID) {
	if errors.Is(err, v3rpcErrors.ErrLeaseNotFound) {
		elm.mu.Lock()
		if info := elm.leases[leaseID]; info != nil {
			info.session.Orphan()
		}
		elm.mu.Unlock()
	}
}

// TotalLeases returns the number of managed leases.
func (elm *etcdLeaseManager) TotalLeases() uint32 {
	elm.mu.RLock()
	defer elm.mu.RUnlock()

	return uint32(len(elm.leases))
}

// Wait waits until all child goroutines terminated.
func (elm *etcdLeaseManager) Wait() {
	elm.wg.Wait()
}

func (elm *etcdLeaseManager) newSession(ctx context.Context) (session *concurrency.Session, err error) {
	defer func(duration *spanstat.SpanStat) {
		increaseMetric("lease", metricSet, "AcquireLease", duration.EndError(err).Total(), err)
	}(spanstat.Start())
	resp, err := elm.client.Grant(ctx, int64(elm.ttl.Seconds()))
	if err != nil {
		return nil, err
	}
	leaseID := resp.ID

	// Construct the session specifying the lease just acquired. This allows to
	// split the possibly blocking operation (i.e., lease acquisition), from the
	// non-blocking one (i.e., the setup of the keepalive logic), so that we can use
	// different contexts. We want the lease acquisition to be controlled by the
	// context associated with the given request, while the keepalive process should
	// continue until either the etcd client is closed or the session is orphaned.
	session, err = concurrency.NewSession(elm.client,
		concurrency.WithLease(leaseID),
		concurrency.WithTTL(int(elm.ttl.Seconds())),
	)
	if err != nil {
		return nil, err
	}

	elm.wg.Add(1)
	go elm.waitForExpiration(session)

	elm.log.WithFields(logrus.Fields{
		"LeaseID": leaseID,
		"TTL":     elm.ttl,
	}).Info("New lease successfully acquired")
	return session, nil
}

func (elm *etcdLeaseManager) waitForExpiration(session *concurrency.Session) {
	defer elm.wg.Done()

	// Block until the session gets orphaned, either because it fails to be
	// renewed or the etcd client is closed.
	<-session.Done()

	select {
	case <-elm.client.Ctx().Done():
		// The context of the etcd client was closed
		return
	default:
	}

	elm.log.WithField("LeaseID", session.Lease()).Warning("Lease expired")

	elm.mu.Lock()
	delete(elm.leases, session.Lease())

	var keys []string
	for key, id := range elm.keys {
		if id == session.Lease() {
			keys = append(keys, key)
			delete(elm.keys, key)
		}
	}
	elm.mu.Unlock()

	if elm.expired != nil {
		for _, key := range keys {
			elm.expired(key)
		}
	}
}

func (elm *etcdLeaseManager) releaseUnlocked(key string) {
	leaseID := elm.keys[key]
	if leaseID != client.NoLease {
		if info := elm.leases[leaseID]; info != nil && info.count > 0 {
			info.count--
		}
		delete(elm.keys, key)
	}
}
