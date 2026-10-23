// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/fqdn/bootstrap"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

type restorePublisher struct {
	endpointmanager.EndpointManager
	published []*endpoint.Endpoint
	err       error
}

func (p *restorePublisher) RestoreEndpoint(ep *endpoint.Endpoint) error {
	p.published = append(p.published, ep)
	return p.err
}

type observedDNSProxyPromise struct {
	promise.Promise[bootstrap.DNSProxyInitialized]
	awaiting chan struct{}
}

func (p *observedDNSProxyPromise) Await(ctx context.Context) (bootstrap.DNSProxyInitialized, error) {
	close(p.awaiting)
	return p.Promise.Await(ctx)
}

func TestEndpointRestoreDNSProxyReadiness(t *testing.T) {
	original := option.Config.RestoreState
	option.Config.RestoreState = true
	t.Cleanup(func() { option.Config.RestoreState = original })
	startupErr := errors.New("DNS proxy startup failed")
	for _, tt := range []struct {
		name    string
		wantErr error
	}{
		{name: "ready"},
		{name: "DNS startup failed", wantErr: startupErr},
		{name: "canceled", wantErr: context.Canceled},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			jobCtx, cancelJob := context.WithCancel(ctx)
			log := hivetest.Logger(t)
			ipc := ipcache.NewIPCache(&ipcache.Configuration{Context: ctx, Logger: log})
			ipc.TriggerLabelInjection()
			t.Cleanup(func() { require.NoError(t, ipc.Shutdown()) })
			cacheReady := make(chan struct{})
			close(cacheReady)
			lc := &cell.DefaultLifecycle{}
			apiFence := hive.NewFence(lc, log)
			require.NoError(t, lc.Start(log, ctx))
			t.Cleanup(func() { require.NoError(t, lc.Stop(log, context.Background())) })
			// Stop at the publication API so no endpoint regeneration setup is needed.
			publisher := &restorePublisher{err: errors.New("endpoint removed")}
			ep := &endpoint.Endpoint{ID: 123}
			resolver, ready := promise.New[bootstrap.DNSProxyInitialized]()
			observed := &observedDNSProxyPromise{ready, make(chan struct{})}
			r := &endpointRestorer{
				logger:                        log,
				endpointManager:               publisher,
				endpointAPIFence:              apiFence,
				cacheStatus:                   cacheReady,
				dirReadStatus:                 &sync.WaitGroup{},
				ipCache:                       ipc,
				dnsProxyPromise:               observed,
				restoreState:                  &endpointRestoreState{restored: []*endpoint.Endpoint{ep}},
				metrics:                       newEndpointRestoreMetrics(),
				endpointRestoreComplete:       make(chan struct{}),
				endpointRegenerateComplete:    make(chan struct{}),
				endpointInitialPolicyComplete: make(chan struct{}),
			}
			health, _ := cell.NewSimpleHealth()
			done := make(chan struct{})
			var result error
			go func() {
				defer close(done)
				result = r.InitRestore(jobCtx, health)
			}()
			t.Cleanup(func() {
				cancelJob()
				<-done
				if result == nil {
					<-r.endpointRegenerateComplete
					<-r.endpointInitialPolicyComplete
				}
			})
			select {
			case <-observed.awaiting:
			case <-done:
				t.Fatalf("endpoint restoration finished before awaiting DNS proxy readiness: %v", result)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			require.Empty(t, publisher.published, "restored endpoints must not be exposed before DNS proxy readiness")
			if errors.Is(tt.wantErr, context.Canceled) {
				cancelJob()
			} else if tt.wantErr != nil {
				resolver.Reject(tt.wantErr)
			} else {
				resolver.Resolve(bootstrap.DNSProxyInitialized{})
			}
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			require.ErrorIs(t, result, tt.wantErr)
			if tt.wantErr == nil {
				require.Equal(t, []*endpoint.Endpoint{ep}, publisher.published)
				require.NoError(t, r.WaitForEndpointRestoreWithoutRegeneration(ctx))
			} else {
				require.Empty(t, publisher.published)
			}
		})
	}
}

func TestPrivilegedRemoveStaleEPIfaces(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)

	ns.Do(func() error {
		linkAttrs := netlink.NewLinkAttrs()
		linkAttrs.Name = "lxc12345"
		veth := &netlink.Veth{
			LinkAttrs: linkAttrs,
			PeerName:  "tmp54321",
		}

		err := netlink.LinkAdd(veth)
		assert.NoError(t, err)

		_, err = safenetlink.LinkByName(linkAttrs.Name)
		assert.NoError(t, err)

		restorer := &endpointRestorer{logger: hivetest.Logger(t)}
		err = restorer.clearStaleCiliumEndpointVeths()
		assert.NoError(t, err)

		// Check that stale iface is removed
		_, err = safenetlink.LinkByName(linkAttrs.Name)
		assert.Error(t, err)

		return nil
	})
}
