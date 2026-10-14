// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/cilium/hive/hivetest"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/envoy/xds"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

func listenerWithPort(name string, port uint32) *envoy_config_listener.Listener {
	return &envoy_config_listener.Listener{
		Name: name,
		Address: &envoy_config_core.Address{
			Address: &envoy_config_core.Address_SocketAddress{
				SocketAddress: &envoy_config_core.SocketAddress{
					Address: "127.0.0.1",
					PortSpecifier: &envoy_config_core.SocketAddress_PortValue{
						PortValue: port,
					},
				},
			},
		},
	}
}

func TestEnvoyOpsWaitsBeforeConfirmingDynamicListenerPort(t *testing.T) {
	for _, tt := range []struct {
		name string
		err  error
	}{
		{name: "ack"},
		{name: "nack", err: errors.New("listener rejected")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			allocator := NewMockPortAllocator()
			port, err := allocator.AllocateCRDProxyPort("listener1")
			require.NoError(t, err)
			entered, result := make(chan struct{}), make(chan error, 1)
			mutator := &fakeEnvoySyncerAndPolicyTrigger{store: make(resourceStore)}
			mutator.beforeUpdate = func(ctx context.Context, _, _ xds.Resources) error {
				close(entered)
				select {
				case err := <-result:
					return err
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			ops := &envoyOps{
				config: CECConfig{EnvoyConfigTimeout: time.Second},
				log:    hivetest.Logger(t), xds: mutator, portAllocator: allocator,
				policyTrigger: &fakeEnvoySyncerAndPolicyTrigger{},
			}
			res := &EnvoyResource{
				Resources:          xds.NewResources(),
				AllocatedListeners: set.NewSet("listener1"),
			}
			res.Resources.Listeners["listener1"] = listenerWithPort("listener1", uint32(port))
			errCh := make(chan error, 1)
			go func() { errCh <- ops.Update(ctx, nil, 0, res) }()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("timed out waiting for xDS update")
			}
			require.Zero(t, allocator.ports["listener1"].cnt)
			select {
			case err := <-errCh:
				t.Fatalf("update returned before LDS ACK: %v", err)
			default:
			}
			result <- tt.err
			require.ErrorIs(t, <-errCh, tt.err)
			if tt.err == nil {
				require.Equal(t, 1, allocator.ports["listener1"].cnt)
			} else {
				require.Zero(t, allocator.ports["listener1"].cnt)
			}
		})
	}
}

func TestIsPortBindingErrorMatchesDuplicateAddress(t *testing.T) {
	// Exact rejection shape Envoy returns in the N/ACK when a dynamically
	// allocated listener port collides with a listener that already owns it.
	err := fmt.Errorf("error adding listener: 'ns/cec/listener' has duplicate address '127.0.0.1:17980' as existing listener")
	if !isPortBindingError(err) {
		t.Fatal("duplicate-address rejection not classified as a port binding error")
	}
}

func TestEnvoyOpsConfirmsPortAllocationsAfterUpdate(t *testing.T) {
	rejected := errors.New("listener or cluster rejected")
	bindError := errors.New("cannot bind: address already in use")
	tests := []struct {
		name       string
		explicit   bool
		reconciled bool
		additional bool
		updateErrs []error
		wantErr    error
		wantCalls  int
		wantRefs   int
	}{
		{name: "new allocation", wantCalls: 1, wantRefs: 1},
		{name: "explicit port", explicit: true, wantCalls: 1},
		{name: "unchanged allocation", reconciled: true, wantCalls: 1, wantRefs: 1},
		{name: "additional addresses retain primary allocation", reconciled: true, additional: true, wantCalls: 1, wantRefs: 1},
		{name: "NACK", updateErrs: []error{rejected}, wantErr: rejected, wantCalls: 1},
		{name: "cancellation", updateErrs: []error{context.Canceled}, wantErr: context.Canceled, wantCalls: 1},
		{name: "deadline", updateErrs: []error{context.DeadlineExceeded}, wantErr: context.DeadlineExceeded, wantCalls: 1},
		{name: "bind retry", updateErrs: []error{bindError, nil}, wantCalls: 2, wantRefs: 1},
		{name: "reallocated confirmed port", reconciled: true, updateErrs: []error{bindError, nil}, wantCalls: 2, wantRefs: 1},
		{name: "failed bind retry", updateErrs: []error{bindError, rejected}, wantErr: rejected, wantCalls: 2},
		{name: "explicit port binding failure", explicit: true, updateErrs: []error{bindError}, wantErr: bindError, wantCalls: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allocator := NewMockPortAllocator()
			port, err := allocator.AllocateCRDProxyPort("listener")
			require.NoError(t, err)
			listener := &envoy_config_listener.Listener{Name: "listener"}
			listener.Address, listener.AdditionalAddresses = envoy.GetLocalListenerAddresses(port, option.Config.IPv4Enabled(), option.Config.IPv6Enabled())
			res := &EnvoyResource{Resources: xds.Resources{
				Listeners: map[string]*envoy_config_listener.Listener{listener.Name: listener},
			}}
			if !tt.explicit {
				res.AllocatedListeners = set.NewSet(listener.Name)
			}
			initialRefs := 0
			if tt.reconciled {
				require.NoError(t, allocator.AckProxyPortWithReference(t.Context(), listener.Name))
				initialRefs = 1
				previous := proto.Clone(listener).(*envoy_config_listener.Listener)
				if tt.additional {
					_, previous.AdditionalAddresses = envoy.GetLocalListenerAddresses(port, true, true)
				}
				res.ReconciledResources = &xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{listener.Name: previous}}
			}
			original := proto.Clone(listener)
			calls := 0
			syncer := &fakeEnvoySyncerAndPolicyTrigger{store: make(resourceStore)}
			syncer.beforeUpdate = func(_ context.Context, _, next xds.Resources) error {
				// A server may ACK some listeners before another resource fails.
				// No new port reference is acquired until its entire update succeeds.
				wantRefs := initialRefs
				if calls > 0 {
					wantRefs = 0 // Reallocation starts a fresh allocation.
				}
				require.Equal(t, wantRefs, allocator.ports[listener.Name].cnt)
				require.Equal(t, uint32(allocator.ports[listener.Name].port), next.Listeners[listener.Name].GetAddress().GetSocketAddress().GetPortValue())
				calls++
				if calls <= len(tt.updateErrs) {
					return tt.updateErrs[calls-1]
				}
				return nil
			}
			ops := &envoyOps{
				config: CECConfig{EnvoyConfigTimeout: time.Second},
				log:    hivetest.Logger(t), xds: syncer, policyTrigger: syncer, portAllocator: allocator,
			}
			previous := res.ReconciledResources
			require.ErrorIs(t, ops.Update(t.Context(), nil, 0, res), tt.wantErr)
			require.Equal(t, tt.wantCalls, calls)
			require.Equal(t, tt.wantRefs, allocator.ports[listener.Name].cnt)
			require.True(t, proto.Equal(original, listener), "parsed listener must remain immutable")
			if tt.wantErr != nil {
				require.Same(t, previous, res.ReconciledResources)
			} else {
				require.NotNil(t, res.ReconciledResources)
				// Reconciliation may run again after retrying on a new port.
				syncer.beforeUpdate = nil
				require.NoError(t, ops.Update(t.Context(), nil, 0, res))
				require.Equal(t, tt.wantRefs, allocator.ports[listener.Name].cnt, "successful repeat must not acquire another reference")
			}
		})
	}
}
