// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipset

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/lock"
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

		cell.Module(
			"ipset-manager-test",
			"ipset-manager-test",

			cell.Provide(func() config {
				return config{NodeIPSetNeeded: true}
			}),

			cell.Provide(
				newIPSetManager,
				tables.NewIPSetTable,
				newOps,
				newReconciler,
			),
			cell.Provide(func(ops *ops) reconciler.Operations[*tables.IPSetEntry] {
				return ops
			}),

			cell.Provide(func(logger *slog.Logger) *ipset {
				return &ipset{
					executable: funcExecutable(
						func(ctx context.Context, command string, stdin string, arg ...string) ([]byte, error) {
							mu.Lock()
							defer mu.Unlock()

							var commands [][]string
							if arg[0] == "restore" {
								for line := range strings.SplitSeq(stdin, "\n") {
									if len(line) > 0 {
										commands = append(commands, strings.Split(line, " "))
									}
								}
							} else {
								commands = [][]string{arg}
							}

							for _, arg := range commands {
								subCommand := arg[0]
								name := arg[1]
								t.Logf("%s %s", subCommand, strings.Join(arg[1:], " "))

								switch subCommand {
								case "create":
									if _, found := ipsets[name]; !found {
										ipsets[name] = AddrSet{}
									}
								case "destroy":
									if _, found := ipsets[name]; !found {
										return nil, fmt.Errorf("ipset %s not found", name)
									}
									delete(ipsets, name)
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
								case "del":
									if _, found := ipsets[name]; !found {
										return nil, fmt.Errorf("ipset %s not found", name)
									}
									addr := netip.MustParseAddr(arg[len(arg)-2])
									if !ipsets[name].Has(addr) {
										return nil, nil
									}
									ipsets[name] = ipsets[name].Delete(addr)
								default:
									return nil, fmt.Errorf("unexpected ipset subcommand %s", arg[1])
								}
							}
							return nil, nil
						},
					),
					log: logger,
				}
			}),
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

	tlog := hivetest.Logger(t)
	assert.NoError(t, hive.Start(tlog, context.Background()))

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

	assert.NoError(t, hive.Stop(tlog, context.Background()))
}

func TestManagerNodeIpsetNotNeeded(t *testing.T) {
	defer goleak.VerifyNone(t)

	ipsets := make(map[string]AddrSet) // mocked kernel IP sets
	var mu lock.Mutex                  // protect the ipsets map

	hive := hive.New(
		cell.Module(
			"ipset-manager-test",
			"ipset-manager-test",

			cell.Provide(func() config {
				return config{NodeIPSetNeeded: false}
			}),

			cell.Provide(
				newIPSetManager,
				tables.NewIPSetTable,
				newOps,
				newReconciler,
			),
			cell.Provide(func(ops *ops) reconciler.Operations[*tables.IPSetEntry] {
				return ops
			}),
			cell.Provide(func(logger *slog.Logger) *ipset {
				return &ipset{
					executable: funcExecutable(func(ctx context.Context, command string, stdin string, arg ...string) ([]byte, error) {
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

	tlog := hivetest.Logger(t)
	assert.NoError(t, hive.Start(tlog, context.Background()))

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

	assert.NoError(t, hive.Stop(tlog, context.Background()))

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
	fakeLogger := slog.New(slog.DiscardHandler)

	db := statedb.New()
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
		executable: funcExecutable(func(ctx context.Context, command string, stdin string, arg ...string) ([]byte, error) {
			nCalled.Store(true)
			t.Logf("%s %s", command, strings.Join(arg, " "))
			return nil, nil
		}),
		log: fakeLogger,
	}

	ops := newOps(fakeLogger, ipset, config{NodeIPSetNeeded: true})

	// prune operation should be skipped when it is not enabled
	iter := table.All(db.ReadTxn())
	assert.NoError(t, ops.Prune(context.TODO(), db.ReadTxn(), iter))
	assert.False(t, nCalled.Load())

	ops.enablePrune()

	// prune operation should now be completed
	iter = table.All(db.ReadTxn())
	assert.NoError(t, ops.Prune(context.TODO(), db.ReadTxn(), iter))
	assert.True(t, nCalled.Load())
}

func TestOpsRetry(t *testing.T) {
	defer goleak.VerifyNone(t)

	var (
		db    *statedb.DB
		table statedb.RWTable[*tables.IPSetEntry]
	)

	shouldFail := true

	hive := hive.New(
		cell.Provide(func() config {
			return config{NodeIPSetNeeded: true}
		}),

		cell.Provide(
			tables.NewIPSetTable,
			newOps,
			newReconciler,
		),
		cell.Provide(func(logger *slog.Logger) *ipset {
			return &ipset{
				executable: funcExecutable(func(ctx context.Context, command string, stdin string, arg ...string) ([]byte, error) {
					// fail the operation at the first attempt
					if shouldFail {
						shouldFail = false
						return nil, errors.New("test error")
					}
					return nil, nil
				}),
				log: logger,
			}
		}),

		cell.Invoke(
			func(db_ *statedb.DB, table_ statedb.RWTable[*tables.IPSetEntry], reconciler_ reconciler.Reconciler[*tables.IPSetEntry]) {
				db = db_
				table = table_
				_ = reconciler_ // to start the reconciler
			},
		),
	)

	log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelError))

	require.NoError(t, hive.Start(log, t.Context()))

	obj := &tables.IPSetEntry{
		Name:   CiliumNodeIPSetV4,
		Family: string(INetFamily),
		Addr:   netip.MustParseAddr("1.1.1.1"),
		Status: reconciler.StatusPending(),
	}

	txn := db.WriteTxn(table)
	_, _, err := table.Insert(txn, obj)
	require.NoError(t, err)
	txn.Commit()

	for {
		queryObj, _, watch, found := table.GetWatch(db.ReadTxn(), tables.IPSetEntryIndex.QueryFromObject(obj))
		require.True(t, found)

		if queryObj.Status.Kind == reconciler.StatusKindDone {
			require.Equal(t, CiliumNodeIPSetV4, queryObj.Name)
			require.Equal(t, netip.MustParseAddr("1.1.1.1"), queryObj.Addr)
			require.Equal(t, string(INetFamily), queryObj.Family)
			break
		}

		<-watch
	}

	require.NoError(t, hive.Stop(log, t.Context()))
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

	fakeLogger := slog.New(slog.DiscardHandler)

	tmpl := template.Must(template.New("ipsets").Parse(textTmpl))

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var bb bytes.Buffer
			if err := tmpl.Execute(&bb, tc.ipsets); err != nil {
				t.Fatalf("unable to execute ipset list output template: %s", err)
			}
			ipset := &ipset{
				log:        fakeLogger,
				executable: &mockExec{t, bb.Bytes(), nil},
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
	fakeLogger := slog.New(slog.DiscardHandler)

	expectedErr := errors.New("ipset v7.19: The set with the given name does not exist")
	ipset := &ipset{
		log:        fakeLogger,
		executable: &mockExec{t, nil, expectedErr},
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

func (e *mockExec) exec(ctx context.Context, name string, stdin string, arg ...string) ([]byte, error) {
	return e.out, e.err
}

func BenchmarkManager(b *testing.B) {

	var (
		mgr         Manager
		initializer Initializer
		addCount    atomic.Int32
		deleteCount atomic.Int32
	)

	hive := hive.New(
		cell.Module(
			"ipset-manager-test",
			"ipset-manager-test",

			cell.Provide(func() config {
				return config{NodeIPSetNeeded: true}
			}),

			cell.Provide(
				newIPSetManager,
				tables.NewIPSetTable,
				newOps,
				newReconciler,
			),
			cell.Provide(func(ops *ops) reconciler.Operations[*tables.IPSetEntry] {
				return ops
			}),

			cell.Provide(func(logger *slog.Logger) *ipset {
				return &ipset{
					executable: funcExecutable(
						func(ctx context.Context, command string, stdin string, arg ...string) ([]byte, error) {
							// exec of ipset add takes about ~0.51ms
							time.Sleep(time.Millisecond)
							if arg[0] == "add" {
								addCount.Add(1)
							} else if arg[0] == "del" {
								deleteCount.Add(1)
							}

							if arg[0] == "restore" {
								count := strings.Count(stdin, "\n")
								if strings.HasPrefix(stdin, "add") {
									addCount.Add(int32(count))
								} else {
									deleteCount.Add(int32(count))
								}
							}
							return nil, nil
						}),
					log: logger,
				}
			}),
		),

		cell.Invoke(func(m Manager) {
			// Add an initializer to stop the pruning
			initializer = m.NewInitializer()
			mgr = m
		}),
	)

	tlog := hivetest.Logger(b)
	assert.NoError(b, hive.Start(tlog, context.Background()))

	numEntries := 1000

	toNetIP := func(i int) netip.Addr {
		var addr1 [4]byte
		binary.BigEndian.PutUint32(addr1[:], 0x02000000+uint32(i))
		return netip.AddrFrom4(addr1)
	}

	for b.Loop() {
		for i := range numEntries {
			ip := toNetIP(i)
			mgr.AddToIPSet(CiliumNodeIPSetV4, INetFamily, ip)
		}

		// Wait for all ops to be done
		for addCount.Load() != int32(numEntries) {
			time.Sleep(time.Millisecond)

		}
		for i := range numEntries {
			ip := toNetIP(i)
			mgr.RemoveFromIPSet(CiliumNodeIPSetV4, ip)
		}

		for deleteCount.Load() != int32(numEntries) {
			time.Sleep(time.Millisecond)
		}

		addCount.Store(0)
		deleteCount.Store(0)
	}

	b.StopTimer()

	b.ReportMetric(float64(2 /*add&delete*/ *b.N*numEntries)/b.Elapsed().Seconds(), "ops/sec")

	initializer.InitDone()

	assert.NoError(b, hive.Stop(tlog, context.Background()))
}
