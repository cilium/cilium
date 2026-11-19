// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/job"
	cilium "github.com/cilium/proxy/go/cilium/api"
	"github.com/cilium/statedb"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/cilium/cilium/pkg/container/set"
	iptables "github.com/cilium/cilium/pkg/datapath/iptables/fake"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/envoy/xds"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/proxy/proxyports"
	proxytypes "github.com/cilium/cilium/pkg/proxy/types"
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
		name               string
		previous           string
		explicit           bool
		err                error
		wantPolicyTriggers int
	}{
		{name: "ack", wantPolicyTriggers: 1},
		{name: "nack", err: errors.New("listener rejected")},
		{name: "cancellation", err: context.Canceled},
		{name: "deadline", err: context.DeadlineExceeded},
		{name: "explicit-to-allocated", previous: "explicit", wantPolicyTriggers: 1},
		{name: "explicit-to-allocated-same-port", previous: "same-port", wantPolicyTriggers: 1},
		{name: "unchanged-allocation", previous: "allocated"},
		{name: "explicit-port", explicit: true, wantPolicyTriggers: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
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
				policyTrigger: mutator,
			}
			res := &EnvoyResource{Resources: xds.NewResources()}
			res.Resources.Listeners["listener1"] = listenerWithPort("listener1", uint32(port))
			if !tt.explicit {
				res.AllocatedListeners.Insert("listener1")
			}
			wantAcked := false
			if tt.previous != "" {
				previousPort := uint32(port)
				if tt.previous == "explicit" {
					previousPort = 8080
				}
				res.ReconciledResources = &xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{
					"listener1": listenerWithPort("listener1", previousPort),
				}}
				if tt.previous == "allocated" {
					require.NoError(t, allocator.AckCRDProxyPort(t.Context(), "listener1"))
					res.ReconciledAllocatedListeners.Insert("listener1")
					wantAcked = true
				}
			}
			timeout := time.Second
			if errors.Is(tt.err, context.DeadlineExceeded) {
				timeout = 100 * time.Millisecond
			}
			ctx, cancel := context.WithTimeout(t.Context(), timeout)
			defer cancel()
			errCh := make(chan error, 1)
			go func() { errCh <- ops.Update(ctx, nil, 0, res) }()
			select {
			case <-entered:
			case err := <-errCh:
				t.Fatalf("update returned before the xDS result: %v", err)
			case <-ctx.Done():
				t.Fatal("timed out waiting for xDS update")
			}
			require.Zero(t, mutator.policyTriggerCount, "policy must wait for the xDS update")
			switch {
			case errors.Is(tt.err, context.Canceled):
				cancel()
			case errors.Is(tt.err, context.DeadlineExceeded):
			default:
				result <- tt.err
			}
			if tt.err == nil && !tt.explicit {
				wantAcked = true
			}
			require.ErrorIs(t, <-errCh, tt.err)
			require.Equal(t, wantAcked, allocator.ports["listener1"].acked)
			require.Equal(t, tt.wantPolicyTriggers, mutator.policyTriggerCount)
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
		name               string
		explicit           bool
		reconciled         bool
		confirmedListener  bool
		additional         bool
		updateErrs         []error
		wantErr            error
		wantCalls          int
		wantAcked          bool
		wantPolicyTriggers int
	}{
		{name: "new allocation", wantCalls: 1, wantAcked: true, wantPolicyTriggers: 1},
		{name: "explicit port", explicit: true, wantCalls: 1, wantPolicyTriggers: 1},
		{name: "unchanged allocation", reconciled: true, wantCalls: 1, wantAcked: true},
		{name: "additional addresses retain primary allocation", reconciled: true, additional: true, wantCalls: 1, wantAcked: true},
		{name: "NACK", updateErrs: []error{rejected}, wantErr: rejected, wantCalls: 1},
		{name: "cancellation", updateErrs: []error{context.Canceled}, wantErr: context.Canceled, wantCalls: 1},
		{name: "deadline", updateErrs: []error{context.DeadlineExceeded}, wantErr: context.DeadlineExceeded, wantCalls: 1},
		{name: "bind retry", updateErrs: []error{bindError, nil}, wantCalls: 2, wantAcked: true, wantPolicyTriggers: 1},
		{name: "confirmed port binding failure", reconciled: true, updateErrs: []error{bindError}, wantErr: bindError, wantCalls: 1, wantAcked: true},
		{name: "bind retry preserves confirmed listener", confirmedListener: true, updateErrs: []error{bindError, nil}, wantCalls: 2, wantAcked: true, wantPolicyTriggers: 1},
		{name: "failed bind retry preserves confirmed listener", confirmedListener: true, updateErrs: []error{bindError, rejected}, wantErr: rejected, wantCalls: 2},
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
			metadata, err := anypb.New(&cilium.BpfMetadata{ProxyId: uint32(port)})
			require.NoError(t, err)
			listener.ListenerFilters = []*envoy_config_listener.ListenerFilter{{
				Name:       ciliumBPFMetadataListenerFilterName,
				ConfigType: &envoy_config_listener.ListenerFilter_TypedConfig{TypedConfig: metadata},
			}}
			res := &EnvoyResource{Resources: xds.Resources{
				Listeners: map[string]*envoy_config_listener.Listener{listener.Name: listener},
			}}
			if !tt.explicit {
				res.AllocatedListeners = set.NewSet(listener.Name)
			}
			initialAcked := false
			if tt.reconciled {
				require.NoError(t, allocator.AckCRDProxyPort(t.Context(), listener.Name))
				initialAcked = true
				res.ReconciledAllocatedListeners.Insert(listener.Name)
				previous := proto.Clone(listener).(*envoy_config_listener.Listener)
				if tt.additional {
					_, previous.AdditionalAddresses = envoy.GetLocalListenerAddresses(port, true, true)
				}
				res.ReconciledResources = &xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{listener.Name: previous}}
			}
			var confirmed *envoy_config_listener.Listener
			if tt.confirmedListener {
				confirmedPort, err := allocator.AllocateCRDProxyPort("confirmed")
				require.NoError(t, err)
				require.NoError(t, allocator.AckCRDProxyPort(t.Context(), "confirmed"))
				confirmed = listenerWithPort("confirmed", uint32(confirmedPort))
				res.Resources.Listeners[confirmed.Name] = confirmed
				res.AllocatedListeners.Insert(confirmed.Name)
				res.ReconciledResources = &xds.Resources{Listeners: map[string]*envoy_config_listener.Listener{
					confirmed.Name: proto.Clone(confirmed).(*envoy_config_listener.Listener),
				}}
				res.ReconciledAllocatedListeners.Insert(confirmed.Name)
			}
			original := proto.Clone(listener)
			calls := 0
			syncer := &fakeEnvoySyncerAndPolicyTrigger{store: make(resourceStore)}
			syncer.beforeUpdate = func(_ context.Context, _, next xds.Resources) error {
				// A server may ACK some listeners before another resource fails.
				// New ports remain unavailable until the entire update succeeds.
				require.Equal(t, initialAcked, allocator.ports[listener.Name].acked)
				if confirmed != nil {
					require.True(t, allocator.ports[confirmed.Name].acked, "retry must preserve acknowledged allocations")
					require.Equal(t, confirmed.GetAddress().GetSocketAddress().GetPortValue(), uint32(allocator.ports[confirmed.Name].port))
					require.True(t, proto.Equal(confirmed, next.Listeners[confirmed.Name]))
				}
				require.Equal(t, uint32(allocator.ports[listener.Name].port), next.Listeners[listener.Name].GetAddress().GetSocketAddress().GetPortValue())
				var proxyMetadata cilium.BpfMetadata
				require.NoError(t, next.Listeners[listener.Name].ListenerFilters[0].GetTypedConfig().UnmarshalTo(&proxyMetadata))
				require.Equal(t, uint32(allocator.ports[listener.Name].port), proxyMetadata.ProxyId, "listener proxy ID must match the port used by policy redirects")
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
			require.Equal(t, tt.wantAcked, allocator.ports[listener.Name].acked)
			require.Equal(t, tt.wantPolicyTriggers, syncer.policyTriggerCount)
			if tt.reconciled {
				require.Equal(t, port, allocator.ports[listener.Name].port, "confirmed ports must not be reallocated")
			}
			require.True(t, proto.Equal(original, listener), "parsed listener must remain immutable")
			if tt.wantErr != nil {
				require.Same(t, previous, res.ReconciledResources)
			} else {
				require.NotNil(t, res.ReconciledResources)
				// Reconciliation may run again after retrying on a new port.
				syncer.beforeUpdate = func(_ context.Context, _, next xds.Resources) error {
					var metadata cilium.BpfMetadata
					require.NoError(t, next.Listeners[listener.Name].ListenerFilters[0].GetTypedConfig().UnmarshalTo(&metadata))
					require.Equal(t, uint32(allocator.ports[listener.Name].port), metadata.ProxyId, "repeated reconciliation must retain the current proxy ID")
					return nil
				}
				require.NoError(t, ops.Update(t.Context(), nil, 0, res))
				require.Equal(t, tt.wantAcked, allocator.ports[listener.Name].acked, "successful repeat must retain the acknowledged allocation")
				require.Equal(t, tt.wantPolicyTriggers, syncer.policyTriggerCount, "successful repeat must not trigger another policy update")
			}
		})
	}
}

func TestEnvoyOpsListenerPortLifecycle(t *testing.T) {
	rejected := errors.New("listener rejected")
	clusterRejected := errors.New("cluster rejected")
	bindError := errors.New("cannot bind: address already in use")
	for _, tt := range []struct {
		name               string
		actions            []string
		wantAcked          []bool
		otherUser          bool
		wantOtherAcked     []bool
		wantPolicyTriggers []int
		wantPortReleases   []bool
	}{
		{name: "create-repeat-delete", actions: []string{"allocated", "repeat", "delete", "delete"}, wantAcked: []bool{true, true, false, false}},
		{name: "delete-and-recreate", actions: []string{"allocated", "delete", "allocated", "delete"}, wantAcked: []bool{true, false, true, false}, wantPortReleases: []bool{false, true, false, true}},
		{name: "explicit-delete", actions: []string{"explicit", "delete", "delete"}, wantAcked: []bool{false, false, false}, wantPortReleases: []bool{false, false, false}},
		{name: "explicit-to-allocated", actions: []string{"explicit", "allocated", "repeat", "delete"}, wantAcked: []bool{false, true, true, false}},
		{name: "explicit-to-allocated-same-port", actions: []string{"explicit-allocated-port", "allocated", "delete"}, wantAcked: []bool{false, true, false}},
		{name: "allocated-explicit-round-trip", actions: []string{"allocated", "explicit", "allocated", "delete"}, wantAcked: []bool{true, false, true, false}, wantPolicyTriggers: []int{1, 2, 3, 3}},
		{name: "remove-and-readd", actions: []string{"allocated", "remove", "allocated", "delete"}, wantAcked: []bool{true, false, true, false}},
		{name: "partial-listener-removal", actions: []string{"allocated", "remove-first", "allocated", "delete"}, wantAcked: []bool{true, false, true, false}, wantOtherAcked: []bool{true, true, true, false}},
		{name: "unreconciled-delete", actions: []string{"nack", "delete"}, wantAcked: []bool{false, false}, wantPortReleases: []bool{false, false}},
		{name: "allocation-ack-error-retry", actions: []string{"ack-error", "repeat", "repeat", "delete"}, wantAcked: []bool{false, true, true, false}, wantPolicyTriggers: []int{0, 1, 1, 1}},
		{name: "partial-allocation-ack-error-retry", actions: []string{"partial-ack-error", "repeat", "repeat", "delete"}, wantAcked: []bool{false, true, true, false}, wantOtherAcked: []bool{true, true, true, false}, wantPolicyTriggers: []int{1, 2, 2, 2}},
		{name: "multiple-allocation-ack-errors-retry", actions: []string{"ack-error", "repeat", "repeat", "delete"}, wantAcked: []bool{false, true, true, false}, wantOtherAcked: []bool{false, true, true, false}, wantPolicyTriggers: []int{0, 1, 1, 1}},
		{name: "cancellation", actions: []string{"cancel", "allocated", "delete"}, wantAcked: []bool{false, true, false}},
		{name: "deadline", actions: []string{"deadline", "allocated", "delete"}, wantAcked: []bool{false, true, false}},
		{name: "failed-transition", actions: []string{"allocated", "explicit-nack", "explicit", "delete"}, wantAcked: []bool{true, true, false, false}},
		{name: "new-bind-retry", actions: []string{"bind-retry", "repeat", "delete"}, wantAcked: []bool{true, true, false}, wantPolicyTriggers: []int{1, 1, 1}},
		{name: "confirmed-bind-failure", actions: []string{"allocated", "bind-nack", "repeat", "delete"}, wantAcked: []bool{true, true, true, false}, wantPolicyTriggers: []int{1, 1, 1, 1}},
		{name: "failed-new-bind-retry", actions: []string{"bind-retry-nack", "repeat", "delete"}, wantAcked: []bool{false, true, false}, wantPolicyTriggers: []int{0, 1, 1}},
		{name: "cluster-nack-unchanged-listener-recovery", actions: []string{"cluster-nack", "cluster-fixed", "repeat", "delete"}, wantAcked: []bool{false, true, true, false}, wantPolicyTriggers: []int{0, 1, 1, 1}},
		{name: "delete-after-confirmed-bind-failure", actions: []string{"allocated", "bind-nack", "delete"}, wantAcked: []bool{true, true, false}, wantPolicyTriggers: []int{1, 1, 1}},
		{name: "shared-allocation", actions: []string{"allocated", "bind-nack", "explicit", "allocated", "delete", "delete"}, wantAcked: []bool{true, true, false, true, false, false}, otherUser: true, wantPolicyTriggers: []int{1, 1, 2, 3, 3, 3}, wantPortReleases: []bool{false, false, false, false, true, false}},
		{name: "delete-unreconciled-transition", actions: []string{"allocated", "explicit-nack", "delete"}, wantAcked: []bool{true, true, false}},
	} {
		for _, realAllocator := range []bool{false, true} {
			allocatorName := "mock"
			if realAllocator {
				allocatorName = "real"
			}
			t.Run(tt.name+"/"+allocatorName, func(t *testing.T) {
				log := hivetest.Logger(t)
				mock := NewMockPortAllocator()
				var allocator PortAllocator = mock
				var ports *proxyports.ProxyPorts
				if realAllocator {
					ports = proxyports.NewProxyPorts(log, proxyports.ProxyPortsConfig{
						ProxyPortrangeMin: 10000, ProxyPortrangeMax: 20000,
					}, iptables.NewManager())
					ports.Trigger = job.NewTrigger()
					allocator = ports
				}
				db := statedb.New()
				cecs, err := NewCECTable(db)
				require.NoError(t, err)
				resources, err := NewEnvoyResourcesTable(db)
				require.NoError(t, err)
				processor := &cecProcessor{
					cecs: cecs, envoyResources: resources, featureMetrics: mockFeatureMetrics{},
					watchSets: map[CECName]*statedb.WatchSet{}, portAllocator: allocator, log: log,
				}
				mutator := &fakeEnvoySyncerAndPolicyTrigger{store: make(resourceStore)}
				ops := &envoyOps{
					config: CECConfig{EnvoyConfigTimeout: time.Second},
					log:    log, xds: mutator, portAllocator: allocator,
					policyTrigger: mutator,
				}
				name := CECName{Namespace: "ns", Name: "cec"}
				listenerName := "ns/cec/listener"
				listenerNames := []string{listenerName}
				if tt.wantOtherAcked != nil {
					listenerNames = append(listenerNames, "ns/cec/other-listener")
				}
				resourceName := EnvoyResourceName{Origin: EnvoyResourceOriginCEC, Namespace: name.Namespace, Name: name.Name}
				// Retain the removed object to exercise repeated xDS cleanup.
				var lastDeleted *EnvoyResource
				var otherUser bool
				for i, action := range tt.actions {
					t.Logf("step %d: %s", i, action)
					var wantErr error
					var portsReleased bool
					var updateErrs []error
					ackFailed := action == "ack-error" || action == "partial-ack-error"
					switch action {
					case "nack", "explicit-nack":
						wantErr = rejected
						updateErrs = []error{rejected}
					case "cancel":
						wantErr = context.Canceled
						updateErrs = []error{wantErr}
					case "deadline":
						wantErr = context.DeadlineExceeded
						updateErrs = []error{wantErr}
					case "bind-nack":
						wantErr = bindError
						updateErrs = []error{bindError}
					case "cluster-nack":
						wantErr = clusterRejected
						updateErrs = []error{clusterRejected}
					case "bind-retry":
						updateErrs = []error{bindError, nil}
					case "bind-retry-nack":
						wantErr = rejected
						updateErrs = []error{bindError, rejected}
					}
					if action == "delete" {
						txn := db.WriteTxn(cecs, resources)
						_, _, err = cecs.Delete(txn, &CEC{Name: name})
						require.NoError(t, err)
						deleted, _, found := resources.Get(txn, EnvoyResourceByName(resourceName))
						portsReleased = processor.process(txn, nil, statedb.NewWatchSet())
						txn.Commit()
						if found {
							lastDeleted = deleted
						}
						if lastDeleted != nil {
							original := lastDeleted.Clone()
							require.NoError(t, ops.Delete(t.Context(), db.ReadTxn(), 0, lastDeleted))
							require.Equal(t, original, lastDeleted, "deletion must preserve StateDB snapshots")
						}
					} else {
						if action != "repeat" {
							desired := xds.NewResources()
							var allocated set.Set[string]
							for _, name := range listenerNames {
								if action == "remove" || action == "remove-first" && name == listenerName {
									continue
								}
								port := uint16(8080)
								if action != "explicit" && action != "explicit-nack" {
									port, err = allocator.AllocateCRDProxyPort(name)
									require.NoError(t, err)
									if action != "explicit-allocated-port" {
										allocated.Insert(name)
									}
								}
								desired.Listeners[name] = listenerWithPort(name, uint32(port))
							}
							if action == "cluster-nack" || action == "cluster-fixed" {
								cluster := &envoy_config_cluster.Cluster{Name: "cluster"}
								if action == "cluster-fixed" {
									cluster.ConnectTimeout = durationpb.New(time.Second)
									previousCEC, _, found := cecs.Get(db.ReadTxn(), CECByName(name))
									require.True(t, found)
									require.True(t, proto.Equal(previousCEC.Resources.Listeners[listenerName], desired.Listeners[listenerName]), "fixing the cluster must leave the listener unchanged")
								}
								desired.Clusters[cluster.Name] = cluster
							}
							_, _, watch, _ := cecs.GetWatch(db.ReadTxn(), CECByName(name))
							txn := db.WriteTxn(cecs, resources)
							_, _, err = cecs.Insert(txn, &CEC{
								Name: name, Spec: &ciliumv2.CiliumEnvoyConfigSpec{},
								Resources: desired, AllocatedListeners: allocated, SelectsLocalNode: true,
							})
							require.NoError(t, err)
							processor.process(txn, []<-chan struct{}{watch}, statedb.NewWatchSet())
							txn.Commit()
						}
						stored, _, found := resources.Get(db.ReadTxn(), EnvoyResourceByName(resourceName))
						require.True(t, found)
						res := stored.Clone()
						previous := res.ReconciledResources
						original := proto.Clone(res.Resources.Listeners[listenerName])
						mutator.beforeUpdate = func(_ context.Context, _, next xds.Resources) error {
							for name := range res.AllocatedListeners.Members() {
								var port uint16
								if realAllocator {
									port, err = ports.AllocateCRDProxyPort(name)
									require.NoError(t, err)
								} else {
									port = mock.ports[name].port
								}
								require.Equal(t, uint32(port), next.Listeners[name].GetAddress().GetSocketAddress().GetPortValue())
							}
							if len(updateErrs) > 0 {
								result := updateErrs[0]
								updateErrs = updateErrs[1:]
								return result
							}
							if ackFailed {
								// Invalidate allocations after xDS succeeds so port acknowledgment fails.
								for _, name := range listenerNames {
									if action == "partial-ack-error" && name != listenerName {
										continue
									}
									if realAllocator {
										require.NoError(t, allocator.ReleaseCRDProxyPort(name))
									} else {
										delete(mock.ports, name)
									}
								}
							}
							return nil
						}
						updateErr := ops.Update(t.Context(), db.ReadTxn(), 0, res)
						if wantErr != nil {
							require.ErrorIs(t, updateErr, wantErr)
						} else if ackFailed {
							for _, name := range listenerNames {
								if action == "partial-ack-error" && name != listenerName {
									continue
								}
								require.ErrorContains(t, updateErr, fmt.Sprintf("acknowledging proxy port %q", name))
							}
						} else {
							require.NoError(t, updateErr)
						}
						if wantErr != nil || ackFailed {
							require.Same(t, previous, res.ReconciledResources)
							require.Equal(t, stored.ReconciledAllocatedListeners, res.ReconciledAllocatedListeners)
						}
						require.True(t, proto.Equal(original, res.Resources.Listeners[listenerName]), "parsed resources must remain immutable")
						txn := db.WriteTxn(resources)
						_, _, err = resources.Insert(txn, res)
						require.NoError(t, err)
						txn.Commit()
					}
					if tt.wantPortReleases != nil {
						require.Equal(t, tt.wantPortReleases[i], portsReleased, "CEC removal must invalidate its allocated listener once")
					}
					if tt.wantPolicyTriggers != nil {
						require.Equal(t, tt.wantPolicyTriggers[i], mutator.policyTriggerCount, "policy trigger count after "+action)
					}
					if realAllocator && tt.otherUser && !otherUser && tt.wantAcked[i] {
						foundName, port := ports.FindByTypeWithReference(proxytypes.ProxyTypeCRD, listenerName, false)
						require.Equal(t, listenerName, foundName)
						require.NotNil(t, port)
						otherUser = true
					}
					for _, name := range listenerNames {
						wantAcked := tt.wantAcked[i]
						if name != listenerName {
							wantAcked = tt.wantOtherAcked[i]
						}
						if realAllocator {
							foundName, port := ports.FindByTypeWithReference(proxytypes.ProxyTypeCRD, name, false)
							require.Equal(t, wantAcked, port != nil, "redirect availability for %s after %s", name, action)
							if port != nil {
								require.Equal(t, name, foundName)
								value, _, err := ports.GetProxyPort(name)
								require.NoError(t, err)
								require.NotZero(t, value)
								require.NoError(t, ports.ReleaseProxyPort(name))
							}
						} else {
							acked := false
							if port := mock.ports[name]; port != nil {
								acked = port.acked
							}
							require.Equal(t, wantAcked, acked, "acknowledgment for %s after %s", name, action)
						}
					}
					if realAllocator {
						var wantInUse uint16
						if otherUser {
							wantInUse = 1
						}
						_, _, inUse := ports.GetStatusInfo()
						require.Equal(t, wantInUse, inUse, "only actual redirects may hold references after %s", action)
					}
				}
				if otherUser {
					require.NoError(t, ports.ReleaseProxyPort(listenerName))
					_, _, inUse := ports.GetStatusInfo()
					require.Zero(t, inUse, "CEC updates and deletion must preserve the redirect reference until its owner releases it")
				}
			})
		}
	}
}
