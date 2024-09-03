// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptables

import (
	"context"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"reflect"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"
	"k8s.io/apimachinery/pkg/util/sets"
	baseclocktest "k8s.io/utils/clock/testing"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/time"
)

func TestReconciliationLoop(t *testing.T) {
	defer goleak.VerifyNone(t)

	var (
		clock   = baseclocktest.NewFakeClock(time.Now())
		db      *statedb.DB
		devices statedb.RWTable[*tables.Device]
		store   *node.LocalNodeStore
		health  cell.Health
		params  *reconcilerParams
	)
	h := hive.New(
		cell.Module(
			"iptables-reconciler-test",
			"iptables-reconciler-test",

			cell.Provide(
				tables.NewDeviceTable,
				statedb.RWTable[*tables.Device].ToTable,
				func() *node.LocalNodeStore { return node.NewTestLocalNodeStore(node.LocalNode{}) },
			),
			cell.Invoke(func(
				db_ *statedb.DB,
				devices_ statedb.RWTable[*tables.Device],
				store_ *node.LocalNodeStore,
				health_ cell.Health,
			) {
				db = db_
				devices = devices_
				store = store_
				db.RegisterTable(devices_)
				health = health_.NewScope("iptables-reconciler-test")
				params = &reconcilerParams{
					clock:          clock,
					localNodeStore: store_,
					db:             db_,
					devices:        devices_,
					proxies:        make(chan reconciliationRequest[proxyInfo]),
					addNoTrackPod:  make(chan reconciliationRequest[noTrackPodInfo]),
					delNoTrackPod:  make(chan reconciliationRequest[noTrackPodInfo]),
				}
			}),
		),
	)

	var (
		state desiredState
		mu    lock.Mutex
	)

	updateFunc := func(newState desiredState, firstInit bool) error {
		mu.Lock()
		defer mu.Unlock()

		// copy newState to avoid a race with the reconciler mutating it
		// and the test asserting the expected values with Eventually
		state = newState.deepCopy()

		return nil
	}
	updateProxyFunc := func(proxyPort uint16, name string) error {
		mu.Lock()
		defer mu.Unlock()
		state.proxies[name] = proxyInfo{
			name: name,
			port: proxyPort,
		}
		return nil
	}
	installNoTrackFunc := func(addr netip.Addr, port uint16) error {
		mu.Lock()
		defer mu.Unlock()
		state.noTrackPods.Insert(noTrackPodInfo{
			ip:   addr,
			port: port,
		})
		return nil
	}
	removeNoTrackFunc := func(addr netip.Addr, port uint16) error {
		mu.Lock()
		defer mu.Unlock()
		state.noTrackPods.Delete(noTrackPodInfo{
			ip:   addr,
			port: port,
		})
		return nil
	}

	testCases := []struct {
		name     string
		action   func()
		expected desiredState
	}{
		{
			name: "initial state",
			action: func() {
				store.Update(func(n *node.LocalNode) {
					n.IPAddresses = []types.Address{
						{
							IP:   netip.MustParseAddr("1.1.1.1").AsSlice(),
							Type: addressing.NodeCiliumInternalIP,
						},
					}
					n.IPv4AllocCIDR = cidr.MustParseCIDR("5.5.5.0/24")
					n.IPv6AllocCIDR = cidr.MustParseCIDR("2001:aaaa::/96")
				})

				txn := db.WriteTxn(devices)
				if _, _, err := devices.Insert(txn, &tables.Device{
					Index:    1,
					Name:     "test-1",
					Selected: true,
				}); err != nil {
					t.Fatal(err)
				}
				txn.Commit()
			},
			expected: desiredState{
				installRules: true,
				devices:      sets.New("test-1"),
				localNodeInfo: localNodeInfo{
					internalIPv4:  net.ParseIP("1.1.1.1"),
					ipv4AllocCIDR: cidr.MustParseCIDR("5.5.5.0/24").String(),
					ipv6AllocCIDR: cidr.MustParseCIDR("2001:aaaa::/96").String(),
				},
			},
		},
		{
			name: "devices update",
			action: func() {
				txn := db.WriteTxn(devices)
				devices.Insert(txn, &tables.Device{
					Index:    2,
					Name:     "test-2",
					Selected: true,
				})
				txn.Commit()
			},
			expected: desiredState{
				installRules: true,
				devices:      sets.New("test-1", "test-2"),
				localNodeInfo: localNodeInfo{
					internalIPv4:  net.ParseIP("1.1.1.1"),
					ipv4AllocCIDR: cidr.MustParseCIDR("5.5.5.0/24").String(),
					ipv6AllocCIDR: cidr.MustParseCIDR("2001:aaaa::/96").String(),
				},
			},
		},
		{
			name: "local node update",
			action: func() {
				store.Update(func(n *node.LocalNode) {
					n.IPAddresses = []types.Address{
						{
							IP:   netip.MustParseAddr("2.2.2.2").AsSlice(),
							Type: addressing.NodeCiliumInternalIP,
						},
					}
					n.IPv4AllocCIDR = cidr.MustParseCIDR("6.6.6.0/24")
					n.IPv6AllocCIDR = cidr.MustParseCIDR("3002:bbbb::/96")
				})
			},
			expected: desiredState{
				installRules: true,
				devices:      sets.New("test-1", "test-2"),
				localNodeInfo: localNodeInfo{
					internalIPv4:  net.ParseIP("2.2.2.2"),
					ipv4AllocCIDR: cidr.MustParseCIDR("6.6.6.0/24").String(),
					ipv6AllocCIDR: cidr.MustParseCIDR("3002:bbbb::/96").String(),
				},
			},
		},
		{
			name: "add first proxy",
			action: func() {
				params.proxies <- reconciliationRequest[proxyInfo]{
					info: proxyInfo{
						name: "proxy-test-1",
						port: 9090,
					},
					updated: make(chan struct{}),
				}
			},
			expected: desiredState{
				installRules: true,
				devices:      sets.New("test-1", "test-2"),
				localNodeInfo: localNodeInfo{
					internalIPv4:  net.ParseIP("2.2.2.2"),
					ipv4AllocCIDR: cidr.MustParseCIDR("6.6.6.0/24").String(),
					ipv6AllocCIDR: cidr.MustParseCIDR("3002:bbbb::/96").String(),
				},
				proxies: map[string]proxyInfo{
					"proxy-test-1": {
						name: "proxy-test-1",
						port: 9090,
					},
				},
			},
		},
		{
			name: "add second proxy",
			action: func() {
				params.proxies <- reconciliationRequest[proxyInfo]{
					info: proxyInfo{
						name: "proxy-test-2",
						port: 9091,
					},
					updated: make(chan struct{}),
				}
			},
			expected: desiredState{
				installRules: true,
				devices:      sets.New("test-1", "test-2"),
				localNodeInfo: localNodeInfo{
					internalIPv4:  net.ParseIP("2.2.2.2"),
					ipv4AllocCIDR: cidr.MustParseCIDR("6.6.6.0/24").String(),
					ipv6AllocCIDR: cidr.MustParseCIDR("3002:bbbb::/96").String(),
				},
				proxies: map[string]proxyInfo{
					"proxy-test-1": {
						name: "proxy-test-1",
						port: 9090,
					},
					"proxy-test-2": {
						name: "proxy-test-2",
						port: 9091,
					},
				},
			},
		},
		{
			name: "add no track pods",
			action: func() {
				params.addNoTrackPod <- reconciliationRequest[noTrackPodInfo]{
					info: noTrackPodInfo{
						ip:   netip.MustParseAddr("1.2.3.4"),
						port: 10001,
					},
					updated: make(chan struct{}),
				}
				params.addNoTrackPod <- reconciliationRequest[noTrackPodInfo]{
					info: noTrackPodInfo{
						ip:   netip.MustParseAddr("11.22.33.44"),
						port: 10002,
					},
					updated: make(chan struct{}),
				}
			},
			expected: desiredState{
				installRules: true,
				devices:      sets.New("test-1", "test-2"),
				localNodeInfo: localNodeInfo{
					internalIPv4:  net.ParseIP("2.2.2.2"),
					ipv4AllocCIDR: cidr.MustParseCIDR("6.6.6.0/24").String(),
					ipv6AllocCIDR: cidr.MustParseCIDR("3002:bbbb::/96").String(),
				},
				proxies: map[string]proxyInfo{
					"proxy-test-1": {
						name: "proxy-test-1",
						port: 9090,
					},
					"proxy-test-2": {
						name: "proxy-test-2",
						port: 9091,
					},
				},
				noTrackPods: sets.New(
					noTrackPodInfo{netip.MustParseAddr("1.2.3.4"), 10001},
					noTrackPodInfo{netip.MustParseAddr("11.22.33.44"), 10002},
				),
			},
		},
		{
			name: "remove no track pod",
			action: func() {
				params.delNoTrackPod <- reconciliationRequest[noTrackPodInfo]{
					info: noTrackPodInfo{
						ip:   netip.MustParseAddr("1.2.3.4"),
						port: 10001,
					},
					updated: make(chan struct{}),
				}
			},
			expected: desiredState{
				installRules: true,
				devices:      sets.New("test-1", "test-2"),
				localNodeInfo: localNodeInfo{
					internalIPv4:  net.ParseIP("2.2.2.2"),
					ipv4AllocCIDR: cidr.MustParseCIDR("6.6.6.0/24").String(),
					ipv6AllocCIDR: cidr.MustParseCIDR("3002:bbbb::/96").String(),
				},
				proxies: map[string]proxyInfo{
					"proxy-test-1": {
						name: "proxy-test-1",
						port: 9090,
					},
					"proxy-test-2": {
						name: "proxy-test-2",
						port: 9091,
					},
				},
				noTrackPods: sets.New(
					noTrackPodInfo{netip.MustParseAddr("11.22.33.44"), 10002},
				),
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tlog := hivetest.Logger(t)
	assert.NoError(t, h.Start(tlog, ctx))

	// apply initial state
	testCases[0].action()

	// start the reconciliation loop
	errs := make(chan error)
	go func() {
		defer close(errs)
		errs <- reconciliationLoop(ctx, log, health, true, params, updateFunc, updateProxyFunc, installNoTrackFunc, removeNoTrackFunc)
	}()

	// wait for reconciler to react to the initial state
	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		if err := assertIptablesState(state, testCases[0].expected); err != nil {
			t.Logf("assertIptablesState: %s", err)
			return false
		}
		return true
	}, 10*time.Second, 10*time.Millisecond, "initial state not reconciled. %v", testCases[0].expected)

	// test all the remaining steps
	for _, tc := range testCases[1:] {
		t.Run(tc.name, func(t *testing.T) {
			// apply the action to update the state
			tc.action()

			// wait for reconciler to react to the update
			assert.Eventuallyf(t, func() bool {
				// Advance the clock, to trigger the ticker responsible to perform the update.
				// This is called for every step to prevent the possibility of race conditions
				// caused by the ticker channel being selected before the actual event.
				clock.Step(200 * time.Millisecond)

				mu.Lock()
				defer mu.Unlock()
				if err := assertIptablesState(state, tc.expected); err != nil {
					t.Logf("assertIptablesState: %s", err)
					return false
				}
				return true
			}, 10*time.Second, 10*time.Millisecond, "expected state not reached. %v", tc.expected)
		})
	}

	// Manually reset the current state, and assert that it eventually converges
	// back to the desired one thanks to the periodic refresh logic.
	updateFunc(desiredState{}, false)
	clock.Step(30 * time.Minute)

	// wait for reconciler to react to the update
	expected := testCases[len(testCases)-1].expected
	assert.Eventuallyf(t, func() bool {
		// Advance the clock, to trigger the ticker responsible to perform the update.
		clock.Step(200 * time.Millisecond)

		mu.Lock()
		defer mu.Unlock()
		if err := assertIptablesState(state, expected); err != nil {
			t.Logf("assertIptablesState: %s", err)
			return false
		}
		return true
	}, 10*time.Second, 10*time.Millisecond, "expected state not reached. %v", expected)

	assert.NoError(t, h.Stop(tlog, ctx))

	close(params.proxies)
	close(params.addNoTrackPod)
	close(params.delNoTrackPod)
	cancel()
	assert.NoError(t, <-errs)
}

func assertIptablesState(current, expected desiredState) error {
	if current.installRules != expected.installRules {
		return fmt.Errorf("expected installRules to be %t, found %t",
			expected.installRules, current.installRules)
	}
	if !current.devices.Equal(expected.devices) {
		return fmt.Errorf("expected devices names to be %v, found %v",
			expected.devices.UnsortedList(), current.devices.UnsortedList())
	}
	if !current.localNodeInfo.equal(expected.localNodeInfo) {
		return fmt.Errorf("expected local node info to be %v, found %v",
			expected.localNodeInfo, current.localNodeInfo)
	}
	if len(current.proxies) != 0 && len(expected.proxies) != 0 &&
		!reflect.DeepEqual(current.proxies, expected.proxies) {
		return fmt.Errorf("expected proxies info to be %v, found %v",
			expected.proxies, current.proxies)
	}
	if !current.noTrackPods.Equal(expected.noTrackPods) {
		return fmt.Errorf("expected no tracking pods info to be %v, found %v",
			expected.noTrackPods.UnsortedList(), current.noTrackPods.UnsortedList())
	}
	return nil
}

func (s desiredState) deepCopy() desiredState {
	ipv4 := make(net.IP, len(s.localNodeInfo.internalIPv4))
	copy(ipv4, s.localNodeInfo.internalIPv4)
	ipv6 := make(net.IP, len(s.localNodeInfo.internalIPv6))
	copy(ipv6, s.localNodeInfo.internalIPv6)
	return desiredState{
		installRules: s.installRules,
		devices:      s.devices.Clone(),
		localNodeInfo: localNodeInfo{
			internalIPv4:          ipv4,
			internalIPv6:          ipv6,
			ipv4AllocCIDR:         s.localNodeInfo.ipv4AllocCIDR,
			ipv6AllocCIDR:         s.localNodeInfo.ipv6AllocCIDR,
			ipv4NativeRoutingCIDR: s.localNodeInfo.ipv4NativeRoutingCIDR,
			ipv6NativeRoutingCIDR: s.localNodeInfo.ipv6NativeRoutingCIDR,
		},
		proxies:     maps.Clone(s.proxies),
		noTrackPods: s.noTrackPods.Clone(),
	}
}
