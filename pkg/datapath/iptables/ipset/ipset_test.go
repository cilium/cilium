// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipset

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
	"github.com/cilium/cilium/pkg/time"
)

// ipset list output template
const textTmpl = `{{range $name, $addrs := . -}}Name: {{$name}}
Type: hash:ip
Revision: 6
Header: family inet hashsize 1024 maxelem 65536 bucketsize 12 initval 0x4d9d24f1
Size in memory: 216
References: 0
Number of entries: {{len $addrs}}
Members:
{{range $addr, $_ := $addrs -}}{{$addr}}
{{else}}{{end}}{{end}}`

func TestManager(t *testing.T) {
	defer goleak.VerifyNone(t)

	var mgr Manager

	ipsets := make(map[string]AddrSet) // mocked kernel IP sets
	var mu lock.Mutex                  // protect the ipsets map

	tmpl := template.Must(template.New("ipsets").Parse(textTmpl))

	hive := hive.New(
		statedb.Cell,
		job.Cell,
		reconciler.Cell,

		cell.Module(
			"ipset-manager-test",
			"ipset-manager-test",

			cell.Provide(func() config {
				return config{NodeIPSetNeeded: true}
			}),

			cell.Provide(
				newIPSetManager,
				tables.NewIPSetTable,
				reconciler.New[*tables.IPSetEntry],
				newReconcilerConfig,
				newOps,
			),
			cell.Provide(func(ops *ops) reconciler.Operations[*tables.IPSetEntry] {
				return ops
			}),

			cell.Provide(func(logger logrus.FieldLogger) *ipset {
				return &ipset{
					executable: funcExecutable(
						func(ctx context.Context, command string, arg ...string) ([]byte, error) {
							mu.Lock()
							defer mu.Unlock()

							t.Logf("%s %s", command, strings.Join(arg, " "))

							subCommand := arg[0]
							name := arg[1]

							switch subCommand {
							case "create":
								if _, found := ipsets[name]; !found {
									ipsets[name] = AddrSet{}
								}
								return nil, nil
							case "destroy":
								if _, found := ipsets[name]; !found {
									return nil, fmt.Errorf("ipset %s not found", name)
								}
								delete(ipsets, name)
								return nil, nil
							case "list":
								if _, found := ipsets[name]; !found {
									return nil, fmt.Errorf("ipset %s not found", name)
								}
								var bb bytes.Buffer
								if err := tmpl.Execute(&bb, map[string]AddrSet{name: ipsets[name]}); err != nil {
									return nil, err
								}
								b := bb.Bytes()
								return b, nil
							case "add":
								if _, found := ipsets[name]; !found {
									return nil, fmt.Errorf("ipset %s not found", name)
								}
								addr := netip.MustParseAddr(arg[len(arg)-2])
								ipsets[name] = ipsets[name].Insert(addr)
								return nil, nil
							case "del":
								if _, found := ipsets[name]; !found {
									return nil, fmt.Errorf("ipset %s not found", name)
								}
								addr := netip.MustParseAddr(arg[len(arg)-2])
								if !ipsets[name].Has(addr) {
									return nil, nil
								}
								ipsets[name] = ipsets[name].Delete(addr)
								return nil, nil
							default:
								return nil, fmt.Errorf("unexpected ipset subcommand %s", arg[1])
							}
						},
					),
					log: logger,
				}
			}),
			cell.Invoke(reconciler.Register[*tables.IPSetEntry]),
		),

		cell.Invoke(func(m Manager) {
			mgr = m
		}),
	)

	testCases := []struct {
		name     string
		action   func()
		expected map[string]AddrSet
	}{
		{
			name:   "check Cilium ipsets have been created",
			action: func() {},
			expected: map[string]AddrSet{
				CiliumNodeIPSetV4: {},
				CiliumNodeIPSetV6: {},
			},
		},
		{
			name: "add an IPv4 address",
			action: func() {
				mgr.AddToIPSet(CiliumNodeIPSetV4, INetFamily, netip.MustParseAddr("1.1.1.1"))
			},
			expected: map[string]AddrSet{
				CiliumNodeIPSetV4: sets.New(
					netip.MustParseAddr("1.1.1.1"),
				),
				CiliumNodeIPSetV6: {},
			},
		},
		{
			name: "add another IPv4 address",
			action: func() {
				mgr.AddToIPSet(CiliumNodeIPSetV4, INetFamily, netip.MustParseAddr("2.2.2.2"))
			},
			expected: map[string]AddrSet{
				CiliumNodeIPSetV4: sets.New(
					netip.MustParseAddr("1.1.1.1"),
					netip.MustParseAddr("2.2.2.2"),
				),
				CiliumNodeIPSetV6: {},
			},
		},
		{
			name: "add the same IPv4 address",
			action: func() {
				mgr.AddToIPSet(CiliumNodeIPSetV4, INetFamily, netip.MustParseAddr("2.2.2.2"))
			},
			expected: map[string]AddrSet{
				CiliumNodeIPSetV4: sets.New(
					netip.MustParseAddr("1.1.1.1"),
					netip.MustParseAddr("2.2.2.2"),
				),
				CiliumNodeIPSetV6: {},
			},
		},
		{
			name: "remove an IPv4 address",
			action: func() {
				mgr.RemoveFromIPSet(CiliumNodeIPSetV4, netip.MustParseAddr("1.1.1.1"))
			},
			expected: map[string]AddrSet{
				CiliumNodeIPSetV4: sets.New(
					netip.MustParseAddr("2.2.2.2"),
				),
				CiliumNodeIPSetV6: {},
			},
		},
		{
			name: "remove a missing IPv4 address",
			action: func() {
				mgr.RemoveFromIPSet(CiliumNodeIPSetV4, netip.MustParseAddr("3.3.3.3"))
			},
			expected: map[string]AddrSet{
				CiliumNodeIPSetV4: sets.New(
					netip.MustParseAddr("2.2.2.2"),
				),
				CiliumNodeIPSetV6: {},
			},
		},
		{
			name: "add an IPv6 address",
			action: func() {
				mgr.AddToIPSet(CiliumNodeIPSetV6, INet6Family, netip.MustParseAddr("cafe::1"))
			},
			expected: map[string]AddrSet{
				CiliumNodeIPSetV4: sets.New(
					netip.MustParseAddr("2.2.2.2"),
				),
				CiliumNodeIPSetV6: sets.New(
					netip.MustParseAddr("cafe::1"),
				),
			},
		},
		{
			name: "remove an IPv6 address",
			action: func() {
				mgr.RemoveFromIPSet(CiliumNodeIPSetV6, netip.MustParseAddr("cafe::1"))
			},
			expected: map[string]AddrSet{
				CiliumNodeIPSetV4: sets.New(
					netip.MustParseAddr("2.2.2.2"),
				),
				CiliumNodeIPSetV6: {},
			},
		},
	}

	time.MaxInternalTimerDelay = time.Millisecond
	t.Cleanup(func() { time.MaxInternalTimerDelay = 0 })

	assert.NoError(t, hive.Start(context.Background()))

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.action()
			assert.Eventually(t, func() bool {
				mu.Lock()
				defer mu.Unlock()

				if len(ipsets) != len(tc.expected) {
					return false
				}
				for name, expectedAddrs := range tc.expected {
					t.Logf("expected: %#v, actual: %#v", expectedAddrs, ipsets[name])
					addrs, found := ipsets[name]
					if !found || !addrs.Equal(expectedAddrs) {
						return false
					}
				}
				return true
			}, 1*time.Second, 50*time.Millisecond)
		})
	}

	assert.NoError(t, hive.Stop(context.Background()))
}

func TestManagerNodeIpsetNotNeeded(t *testing.T) {
	defer goleak.VerifyNone(t)

	ipsets := make(map[string]AddrSet) // mocked kernel IP sets
	var mu lock.Mutex                  // protect the ipsets map

	hive := hive.New(
		statedb.Cell,
		job.Cell,
		reconciler.Cell,

		cell.Module(
			"ipset-manager-test",
			"ipset-manager-test",

			cell.Provide(func() config {
				return config{NodeIPSetNeeded: false}
			}),

			cell.Provide(
				newIPSetManager,
				tables.NewIPSetTable,
				reconciler.New[*tables.IPSetEntry],
				newReconcilerConfig,
				newOps,
			),
			cell.Provide(func(ops *ops) reconciler.Operations[*tables.IPSetEntry] {
				return ops
			}),
			cell.Provide(func(logger logrus.FieldLogger) *ipset {
				return &ipset{
					executable: funcExecutable(func(ctx context.Context, command string, arg ...string) ([]byte, error) {
						mu.Lock()
						defer mu.Unlock()

						t.Logf("%s %s", command, strings.Join(arg, " "))

						if arg[0] == "destroy" {
							name := arg[1]
							if _, found := ipsets[name]; !found {
								return nil, fmt.Errorf("ipset %s not found", name)
							}
							delete(ipsets, name)
						}
						return nil, nil
					}),
					log: logger,
				}
			}),
			cell.Invoke(reconciler.Register[*tables.IPSetEntry]),

			// force manager instantiation
			cell.Invoke(func(_ Manager) {}),
		),
	)

	time.MaxInternalTimerDelay = time.Millisecond
	t.Cleanup(func() { time.MaxInternalTimerDelay = 0 })

	// create ipv4 and ipv6 node ipsets to simulate stale entries from previous Cilium run
	withLocked(&mu, func() {
		ipsets[CiliumNodeIPSetV4] = sets.New(netip.MustParseAddr("2.2.2.2"))
		ipsets[CiliumNodeIPSetV6] = sets.New(netip.MustParseAddr("cafe::1"))
	})

	assert.NoError(t, hive.Start(context.Background()))

	// Cilium node ipsets should eventually be pruned
	assert.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()

		if _, found := ipsets[CiliumNodeIPSetV4]; found {
			return false
		}
		if _, found := ipsets[CiliumNodeIPSetV6]; found {
			return false
		}

		return true
	}, 1*time.Second, 50*time.Millisecond)

	// create a custom ipset (not managed by Cilium)
	withLocked(&mu, func() {
		ipsets["unmanaged-ipset"] = AddrSet{}
	})

	assert.NoError(t, hive.Stop(context.Background()))

	// ipset managed by Cilium should not have been created again
	withLocked(&mu, func() {
		assert.NotContains(t, ipsets, CiliumNodeIPSetV4)
		assert.NotContains(t, ipsets, CiliumNodeIPSetV6)
	})

	// ipset not managed by Cilium should not have been pruned
	withLocked(&mu, func() {
		assert.Contains(t, ipsets, "unmanaged-ipset")
	})
}

func withLocked(m *lock.Mutex, f func()) {
	m.Lock()
	defer m.Unlock()

	f()
}

func TestOpsPruneEnabled(t *testing.T) {
	fakeLogger := logrus.New()
	fakeLogger.SetOutput(io.Discard)

	db, _ := statedb.NewDB(nil, statedb.NewMetrics())
	table, _ := statedb.NewTable("ipsets", tables.IPSetEntryIndex)
	require.NoError(t, db.RegisterTable(table))

	txn := db.WriteTxn(table)
	table.Insert(txn, &tables.IPSetEntry{
		Name:   CiliumNodeIPSetV4,
		Family: string(INetFamily),
		Addr:   netip.MustParseAddr("1.1.1.1"),
		Status: reconciler.StatusDone(),
	})
	table.Insert(txn, &tables.IPSetEntry{
		Name:   CiliumNodeIPSetV4,
		Family: string(INetFamily),
		Addr:   netip.MustParseAddr("2.2.2.2"),
		Status: reconciler.StatusDone(),
	})
	table.Insert(txn, &tables.IPSetEntry{
		Name:   CiliumNodeIPSetV6,
		Family: string(INet6Family),
		Addr:   netip.MustParseAddr("cafe::1"),
		Status: reconciler.StatusPending(),
	})
	txn.Commit()

	var nCalled atomic.Bool // true if the ipset utility has been called

	ipset := &ipset{
		executable: funcExecutable(func(ctx context.Context, command string, arg ...string) ([]byte, error) {
			nCalled.Store(true)
			t.Logf("%s %s", command, strings.Join(arg, " "))
			return nil, nil
		}),
		log: fakeLogger,
	}

	ops := newOps(fakeLogger, ipset, config{NodeIPSetNeeded: true})

	// prune operation should be skipped when it is not enabled
	iter, _ := table.All(db.ReadTxn())
	assert.NoError(t, ops.Prune(context.TODO(), db.ReadTxn(), iter))
	assert.False(t, nCalled.Load())

	ops.enablePrune()

	// prune operation should now be completed
	iter, _ = table.All(db.ReadTxn())
	assert.NoError(t, ops.Prune(context.TODO(), db.ReadTxn(), iter))
	assert.True(t, nCalled.Load())
}

func TestIPSetList(t *testing.T) {
	testCases := []struct {
		name     string
		ipsets   map[string]AddrSet
		expected AddrSet
	}{
		{
			name: "empty ipset",
			ipsets: map[string]AddrSet{
				"ciliumtest": {},
			},
			expected: AddrSet{},
		},
		{
			name: "ipset with a single IP",
			ipsets: map[string]AddrSet{
				"ciliumtest": sets.New(netip.MustParseAddr("1.1.1.1")),
			},
			expected: sets.New(netip.MustParseAddr("1.1.1.1")),
		},
		{
			name: "ipset with multiple IPs",
			ipsets: map[string]AddrSet{
				"ciliumtest": sets.New(netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2.2.2.2")),
			},
			expected: sets.New(netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2.2.2.2")),
		},
	}

	fakeLogger := logrus.New()
	fakeLogger.SetOutput(io.Discard)

	tmpl := template.Must(template.New("ipsets").Parse(textTmpl))

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var bb bytes.Buffer
			if err := tmpl.Execute(&bb, tc.ipsets); err != nil {
				t.Fatalf("unable to execute ipset list output template: %s", err)
			}
			ipset := &ipset{
				&mockExec{t, bb.Bytes(), nil},
				fakeLogger,
			}
			got, err := ipset.list(context.Background(), "")
			if err != nil {
				t.Fatal(err)
			}
			if !got.Equal(tc.expected) {
				t.Fatalf("expected addresses in ipset to be %v, got %v", tc.expected, got)
			}
		})
	}
}

func TestIPSetListInexistentIPSet(t *testing.T) {
	fakeLogger := logrus.New()
	fakeLogger.SetOutput(io.Discard)

	expectedErr := errors.New("ipset v7.19: The set with the given name does not exist")
	ipset := &ipset{
		&mockExec{t, nil, expectedErr},
		fakeLogger,
	}

	_, err := ipset.list(context.Background(), "")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

type mockExec struct {
	t   *testing.T
	out []byte
	err error
}

func (e *mockExec) exec(ctx context.Context, name string, arg ...string) ([]byte, error) {
	return e.out, e.err
}
