// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/fqdn/bootstrap"
	"github.com/cilium/cilium/pkg/promise"
)

func TestFenceDNSProxyReadiness(t *testing.T) {
	startupErr := errors.New("DNS proxy startup failed")
	for _, tt := range []struct {
		name           string
		dnsReady       bool
		deletionsReady bool
		cancelWait     bool
		dnsErr         error
		wantErr        error
	}{
		{name: "both pending", wantErr: context.DeadlineExceeded},
		{name: "DNS pending", deletionsReady: true, wantErr: context.DeadlineExceeded},
		{name: "deletions pending", dnsReady: true, wantErr: context.DeadlineExceeded},
		{name: "ready", dnsReady: true, deletionsReady: true},
		{name: "DNS failed", deletionsReady: true, dnsErr: startupErr, wantErr: startupErr},
		{name: "canceled", deletionsReady: true, cancelWait: true, wantErr: context.Canceled},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			resolver, ready := promise.New[bootstrap.DNSProxyInitialized]()
			if tt.dnsErr != nil {
				resolver.Reject(tt.dnsErr)
			} else if tt.dnsReady {
				resolver.Resolve(bootstrap.DNSProxyInitialized{})
			}
			processed := make(chan struct{})
			if tt.deletionsReady {
				close(processed)
			}

			var fence Fence
			h := hive.New(
				cell.Provide(newFence),
				cell.Provide(func() *DeletionQueue { return &DeletionQueue{processed: processed} }),
				cell.Provide(func() promise.Promise[bootstrap.DNSProxyInitialized] { return ready }),
				cell.Invoke(func(f Fence) { fence = f }),
			)
			log := hivetest.Logger(t)
			t.Cleanup(func() { require.NoError(t, h.Stop(log, context.Background())) })
			require.NoError(t, h.Start(log, ctx), "Hive startup must not wait for DNS or queued deletions")

			waitCtx, stop := context.WithTimeout(ctx, 10*time.Millisecond)
			defer stop()
			if tt.cancelWait {
				stop()
			}
			require.ErrorIs(t, fence.Wait(waitCtx), tt.wantErr)

			if tt.dnsErr == nil {
				if !tt.dnsReady {
					resolver.Resolve(bootstrap.DNSProxyInitialized{})
				}
				if !tt.deletionsReady {
					close(processed)
				}
				require.NoError(t, fence.Wait(ctx))
			}
		})
	}
}
