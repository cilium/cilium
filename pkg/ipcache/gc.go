// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"context"
	"net/netip"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/trigger"
)

type asyncPrefixReleaser struct {
	*trigger.Trigger
	prefixReleaser

	closeChan chan struct{} // Daemon closes this when shutting down.
	doneChan  chan struct{} // Trigger closes this to confirm shutdown.

	// Mutex protects read and write to 'queue'.
	lock.Mutex
	queue []netip.Prefix
}

type prefixReleaser interface {
	releaseCIDRIdentities(ctx context.Context, identities []netip.Prefix)
}

func newAsyncPrefixReleaser(parentCtx context.Context, parent prefixReleaser, interval time.Duration) *asyncPrefixReleaser {
	result := &asyncPrefixReleaser{
		queue:          make([]netip.Prefix, 0),
		prefixReleaser: parent,
		closeChan:      make(chan struct{}),
		doneChan:       make(chan struct{}),
	}

	// trigger needs to be updated to reference the object above
	// Ignore error case since the TriggerFunc is provided.
	result.Trigger, _ = trigger.NewTrigger(trigger.Parameters{
		Name:        "ipcache-identity-gc",
		MinInterval: interval,
		TriggerFunc: func(reasons []string) {
			ctx, cancel := context.WithTimeout(
				parentCtx,
				option.Config.KVstoreConnectivityTimeout)
			defer cancel()
			result.run(ctx, reasons...)
		},
		ShutdownFunc: func() {
			close(result.doneChan)
		},
	})

	return result
}

func (pr *asyncPrefixReleaser) Shutdown() {
	close(pr.closeChan)
	pr.Trigger.Shutdown()
	<-pr.doneChan
}

// enqueue a set of prefixes to be released asynchronously.
func (pr *asyncPrefixReleaser) enqueue(prefixes []netip.Prefix, reason string) {
	pr.Lock()
	defer pr.Unlock()
	select {
	case <-pr.closeChan:
		log.WithFields(logrus.Fields{
			logfields.CIDRS:  prefixes,
			logfields.Reason: reason,
		}).Debug("Received request to release prefixes but the daemon is shutting down")
		return
	default:
		// fallthrough
	}
	pr.queue = append(pr.queue, prefixes...)
	pr.TriggerWithReason(reason)
}

// dequeue  the outstanding set of prefixes that are queued fro release.
func (pr *asyncPrefixReleaser) dequeue() (result []netip.Prefix) {
	pr.Lock()
	defer pr.Unlock()
	result = pr.queue
	pr.queue = make([]netip.Prefix, 0)
	return result
}

// run the core logic to dequeue & release identities / ipcache entries
func (pr *asyncPrefixReleaser) run(ctx context.Context, reasons ...string) {
	prefixes := pr.dequeue()
	log.WithFields(logrus.Fields{
		logfields.Count:  len(prefixes),
		logfields.Reason: reasons,
	}).Debug("Garbage collecting identities and entries from ipcache")
	pr.prefixReleaser.releaseCIDRIdentities(ctx, prefixes)
}
