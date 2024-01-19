// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package iptables

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/time"
)

func TestReconciliationLoop(t *testing.T) {
	defer goleak.VerifyNone(t)

	var (
		db      *statedb.DB
		devices statedb.RWTable[*tables.Device]
		store   *node.LocalNodeStore
		health  cell.HealthReporter
		params  *reconcilerParams
	)
	h := hive.New(
		cell.Module(
			"iptables-reconciler-test",
			"iptables-reconciler-test",

			statedb.Cell,
			cell.Provide(
				tables.NewDeviceTable,
				statedb.RWTable[*tables.Device].ToTable,
				func() *node.LocalNodeStore { return node.NewTestLocalNodeStore(node.LocalNode{}) },
			),
			cell.Invoke(func(
				db_ *statedb.DB,
				devices_ statedb.RWTable[*tables.Device],
				store_ *node.LocalNodeStore,
				scope cell.Scope,
			) {
				db = db_
				devices = devices_
				store = store_
				db.RegisterTable(devices_)
				health = cell.GetHealthReporter(scope, "test")
				params = &reconcilerParams{
					localNodeStore: store_,
					db:             db_,
					devices:        devices_,
					proxies:        make(chan proxyInfo),
					addIPInSet:     make(chan netip.Addr),
					delIPFromSet:   make(chan netip.Addr),
					addNoTrackPod:  make(chan noTrackPodInfo),
					delNoTrackPod:  make(chan noTrackPodInfo),
				}
			}),
		),
	)

	var (
		lastState atomic.Pointer[desiredState]
		lastErr   error
	)

	updateFunc := func(ctx context.Context, state desiredState, firstInit bool) error {
		lastState.Store(&state)
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
				params.proxies <- proxyInfo{
					name:        "proxy-test-1",
					port:        9090,
					isIngress:   false,
					isLocalOnly: true,
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
				proxies: sets.New(proxyInfo{
					name:        "proxy-test-1",
					port:        9090,
					isIngress:   false,
					isLocalOnly: true,
				}),
			},
		},
		{
			name: "add second proxy",
			action: func() {
				params.proxies <- proxyInfo{
					name:        "proxy-test-2",
					port:        9091,
					isIngress:   true,
					isLocalOnly: false,
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
				proxies: sets.New(
					proxyInfo{
						name:        "proxy-test-1",
						port:        9090,
						isIngress:   false,
						isLocalOnly: true,
					},
					proxyInfo{
						name:        "proxy-test-2",
						port:        9091,
						isIngress:   true,
						isLocalOnly: false,
					},
				),
			},
		},
		{
			name: "add ips to ipv4 set",
			action: func() {
				params.addIPInSet <- netip.MustParseAddr("10.10.10.10")
				params.addIPInSet <- netip.MustParseAddr("11.11.11.11")
			},
			expected: desiredState{
				installRules: true,
				devices:      sets.New("test-1", "test-2"),
				localNodeInfo: localNodeInfo{
					internalIPv4:  net.ParseIP("2.2.2.2"),
					ipv4AllocCIDR: cidr.MustParseCIDR("6.6.6.0/24").String(),
					ipv6AllocCIDR: cidr.MustParseCIDR("3002:bbbb::/96").String(),
				},
				proxies: sets.New(
					proxyInfo{
						name:        "proxy-test-1",
						port:        9090,
						isIngress:   false,
						isLocalOnly: true,
					},
					proxyInfo{
						name:        "proxy-test-2",
						port:        9091,
						isIngress:   true,
						isLocalOnly: false,
					},
				),
				ipv4Set: sets.New(
					netip.MustParseAddr("10.10.10.10"),
					netip.MustParseAddr("11.11.11.11"),
				),
			},
		},
		{
			name: "remove ip from ipv4 set",
			action: func() {
				params.delIPFromSet <- netip.MustParseAddr("10.10.10.10")
			},
			expected: desiredState{
				installRules: true,
				devices:      sets.New("test-1", "test-2"),
				localNodeInfo: localNodeInfo{
					internalIPv4:  net.ParseIP("2.2.2.2"),
					ipv4AllocCIDR: cidr.MustParseCIDR("6.6.6.0/24").String(),
					ipv6AllocCIDR: cidr.MustParseCIDR("3002:bbbb::/96").String(),
				},
				proxies: sets.New(
					proxyInfo{
						name:        "proxy-test-1",
						port:        9090,
						isIngress:   false,
						isLocalOnly: true,
					},
					proxyInfo{
						name:        "proxy-test-2",
						port:        9091,
						isIngress:   true,
						isLocalOnly: false,
					},
				),
				ipv4Set: sets.New(
					netip.MustParseAddr("11.11.11.11"),
				),
			},
		},
		{
			name: "add ips to ipv6 set",
			action: func() {
				params.addIPInSet <- netip.MustParseAddr("5000:aaaa::")
				params.addIPInSet <- netip.MustParseAddr("5000:bbbb::")
			},
			expected: desiredState{
				installRules: true,
				devices:      sets.New("test-1", "test-2"),
				localNodeInfo: localNodeInfo{
					internalIPv4:  net.ParseIP("2.2.2.2"),
					ipv4AllocCIDR: cidr.MustParseCIDR("6.6.6.0/24").String(),
					ipv6AllocCIDR: cidr.MustParseCIDR("3002:bbbb::/96").String(),
				},
				proxies: sets.New(
					proxyInfo{
						name:        "proxy-test-1",
						port:        9090,
						isIngress:   false,
						isLocalOnly: true,
					},
					proxyInfo{
						name:        "proxy-test-2",
						port:        9091,
						isIngress:   true,
						isLocalOnly: false,
					},
				),
				ipv4Set: sets.New(
					netip.MustParseAddr("11.11.11.11"),
				),
				ipv6Set: sets.New(
					netip.MustParseAddr("5000:aaaa::"),
					netip.MustParseAddr("5000:bbbb::"),
				),
			},
		},
		{
			name: "remove ip from ipv6 set",
			action: func() {
				params.delIPFromSet <- netip.MustParseAddr("5000:aaaa::")
			},
			expected: desiredState{
				installRules: true,
				devices:      sets.New("test-1", "test-2"),
				localNodeInfo: localNodeInfo{
					internalIPv4:  net.ParseIP("2.2.2.2"),
					ipv4AllocCIDR: cidr.MustParseCIDR("6.6.6.0/24").String(),
					ipv6AllocCIDR: cidr.MustParseCIDR("3002:bbbb::/96").String(),
				},
				proxies: sets.New(
					proxyInfo{
						name:        "proxy-test-1",
						port:        9090,
						isIngress:   false,
						isLocalOnly: true,
					},
					proxyInfo{
						name:        "proxy-test-2",
						port:        9091,
						isIngress:   true,
						isLocalOnly: false,
					},
				),
				ipv4Set: sets.New(
					netip.MustParseAddr("11.11.11.11"),
				),
				ipv6Set: sets.New(
					netip.MustParseAddr("5000:bbbb::"),
				),
			},
		},
		{
			name: "add no track pods",
			action: func() {
				params.addNoTrackPod <- noTrackPodInfo{netip.MustParseAddr("1.2.3.4"), 10001}
				params.addNoTrackPod <- noTrackPodInfo{netip.MustParseAddr("11.22.33.44"), 10002}
			},
			expected: desiredState{
				installRules: true,
				devices:      sets.New("test-1", "test-2"),
				localNodeInfo: localNodeInfo{
					internalIPv4:  net.ParseIP("2.2.2.2"),
					ipv4AllocCIDR: cidr.MustParseCIDR("6.6.6.0/24").String(),
					ipv6AllocCIDR: cidr.MustParseCIDR("3002:bbbb::/96").String(),
				},
				proxies: sets.New(
					proxyInfo{
						name:        "proxy-test-1",
						port:        9090,
						isIngress:   false,
						isLocalOnly: true,
					},
					proxyInfo{
						name:        "proxy-test-2",
						port:        9091,
						isIngress:   true,
						isLocalOnly: false,
					},
				),
				ipv4Set: sets.New(
					netip.MustParseAddr("11.11.11.11"),
				),
				ipv6Set: sets.New(
					netip.MustParseAddr("5000:bbbb::"),
				),
				noTrackPods: sets.New(
					noTrackPodInfo{netip.MustParseAddr("1.2.3.4"), 10001},
					noTrackPodInfo{netip.MustParseAddr("11.22.33.44"), 10002},
				),
			},
		},
		{
			name: "remove no track pod",
			action: func() {
				params.delNoTrackPod <- noTrackPodInfo{netip.MustParseAddr("1.2.3.4"), 10001}
			},
			expected: desiredState{
				installRules: true,
				devices:      sets.New("test-1", "test-2"),
				localNodeInfo: localNodeInfo{
					internalIPv4:  net.ParseIP("2.2.2.2"),
					ipv4AllocCIDR: cidr.MustParseCIDR("6.6.6.0/24").String(),
					ipv6AllocCIDR: cidr.MustParseCIDR("3002:bbbb::/96").String(),
				},
				proxies: sets.New(
					proxyInfo{
						name:        "proxy-test-1",
						port:        9090,
						isIngress:   false,
						isLocalOnly: true,
					},
					proxyInfo{
						name:        "proxy-test-2",
						port:        9091,
						isIngress:   true,
						isLocalOnly: false,
					},
				),
				ipv4Set: sets.New(
					netip.MustParseAddr("11.11.11.11"),
				),
				ipv6Set: sets.New(
					netip.MustParseAddr("5000:bbbb::"),
				),
				noTrackPods: sets.New(
					noTrackPodInfo{netip.MustParseAddr("11.22.33.44"), 10002},
				),
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	assert.NoError(t, h.Start(ctx))

	// apply initial state
	testCases[0].action()

	// start the reconciliation loop
	errs := make(chan error)
	go func() {
		defer close(errs)
		errs <- reconciliationLoop(ctx, health, true, params, updateFunc)
	}()

	// wait for reconciler to react to the initial state
	assert.Eventually(t, func() bool {
		curState := lastState.Load()
		if curState == nil {
			// not yet loaded
			return false
		}
		if err := assertState(*curState, testCases[0].expected); err != nil {
			lastErr = err
			return false
		}
		return true
	}, 10*time.Second, 10*time.Millisecond, "assertion failed: %s", lastErr)

	// test all the remaining steps
	for _, tc := range testCases[1:] {
		t.Run(tc.name, func(t *testing.T) {
			// apply the action to update the state
			tc.action()

			// wait for reconciler to react to the update
			assert.Eventuallyf(t, func() bool {
				curState := lastState.Load()
				if err := assertState(*curState, tc.expected); err != nil {
					lastErr = err
					return false
				}
				return true
			}, 10*time.Second, 10*time.Millisecond, "assertion failed: %s", lastErr)
		})
	}

	assert.NoError(t, h.Stop(ctx))

	cancel()
	assert.NoError(t, <-errs)
}

func assertState(current, expected desiredState) error {
	if current.installRules != expected.installRules {
		return fmt.Errorf("expected installRules to be %t, found %t",
			expected.installRules, current.installRules)
	}
	if !current.devices.Equal(expected.devices) {
		return fmt.Errorf("expected devices names to be %v, found %v",
			current.devices.UnsortedList(), expected.devices.UnsortedList())
	}
	if !current.localNodeInfo.equal(expected.localNodeInfo) {
		return fmt.Errorf("expected local node info to be %v, found %v",
			current.localNodeInfo, expected.localNodeInfo)
	}
	if !current.proxies.Equal(expected.proxies) {
		return fmt.Errorf("expected proxies info to be %v, found %v",
			current.proxies.UnsortedList(), expected.proxies.UnsortedList())
	}
	if !current.ipv4Set.Equal(expected.ipv4Set) {
		return fmt.Errorf("expected ipv4 set to be %v, found %v",
			current.ipv4Set.UnsortedList(), expected.ipv4Set.UnsortedList())
	}
	if !current.ipv6Set.Equal(expected.ipv6Set) {
		return fmt.Errorf("expected ipv6 set to be %v, found %v",
			current.ipv6Set.UnsortedList(), expected.ipv6Set.UnsortedList())
	}
	if !current.noTrackPods.Equal(expected.noTrackPods) {
		return fmt.Errorf("expected no tracking pods info to be %v, found %v",
			current.noTrackPods.UnsortedList(), expected.noTrackPods.UnsortedList())
	}
	return nil
}
