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
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"

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
Number of entries: {{len $addrs.AsSlice}}
Members:
{{range $idx, $addr := $addrs.AsSlice -}}{{$addr}}
{{else}}{{end}}{{end}}`

func TestManager(t *testing.T) {
	defer goleak.VerifyNone(t)

	var mgr Manager

	ipsets := make(map[string]tables.AddrSet) // mocked kernel IP sets
	var mu lock.Mutex                         // protect the ipsets map

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
				reconciler.New[*tables.IPSet],
				newReconcilerConfig,
				newOps,
			),

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
									ipsets[name] = tables.NewAddrSet()
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
								if err := tmpl.Execute(&bb, map[string]tables.AddrSet{name: ipsets[name]}); err != nil {
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
			cell.Invoke(reconciler.Register[*tables.IPSet]),
		),

		cell.Invoke(func(m Manager) {
			mgr = m
		}),
	)

	testCases := []struct {
		name     string
		action   func()
		expected map[string]tables.AddrSet
	}{
		{
			name:   "check Cilium ipsets have been created",
			action: func() {},
			expected: map[string]tables.AddrSet{
				CiliumNodeIPSetV4: tables.NewAddrSet(),
				CiliumNodeIPSetV6: tables.NewAddrSet(),
			},
		},
		{
			name: "add an IPv4 address",
			action: func() {
				mgr.AddToIPSet(CiliumNodeIPSetV4, INetFamily, netip.MustParseAddr("1.1.1.1"))
			},
			expected: map[string]tables.AddrSet{
				CiliumNodeIPSetV4: tables.NewAddrSet(
					netip.MustParseAddr("1.1.1.1"),
				),
				CiliumNodeIPSetV6: tables.NewAddrSet(),
			},
		},
		{
			name: "add another IPv4 address",
			action: func() {
				mgr.AddToIPSet(CiliumNodeIPSetV4, INetFamily, netip.MustParseAddr("2.2.2.2"))
			},
			expected: map[string]tables.AddrSet{
				CiliumNodeIPSetV4: tables.NewAddrSet(
					netip.MustParseAddr("1.1.1.1"),
					netip.MustParseAddr("2.2.2.2"),
				),
				CiliumNodeIPSetV6: tables.NewAddrSet(),
			},
		},
		{
			name: "add the same IPv4 address",
			action: func() {
				mgr.AddToIPSet(CiliumNodeIPSetV4, INetFamily, netip.MustParseAddr("2.2.2.2"))
			},
			expected: map[string]tables.AddrSet{
				CiliumNodeIPSetV4: tables.NewAddrSet(
					netip.MustParseAddr("1.1.1.1"),
					netip.MustParseAddr("2.2.2.2"),
				),
				CiliumNodeIPSetV6: tables.NewAddrSet(),
			},
		},
		{
			name: "remove an IPv4 address",
			action: func() {
				mgr.RemoveFromIPSet(CiliumNodeIPSetV4, netip.MustParseAddr("1.1.1.1"))
			},
			expected: map[string]tables.AddrSet{
				CiliumNodeIPSetV4: tables.NewAddrSet(
					netip.MustParseAddr("2.2.2.2"),
				),
				CiliumNodeIPSetV6: tables.NewAddrSet(),
			},
		},
		{
			name: "remove a missing IPv4 address",
			action: func() {
				mgr.RemoveFromIPSet(CiliumNodeIPSetV4, netip.MustParseAddr("3.3.3.3"))
			},
			expected: map[string]tables.AddrSet{
				CiliumNodeIPSetV4: tables.NewAddrSet(
					netip.MustParseAddr("2.2.2.2"),
				),
				CiliumNodeIPSetV6: tables.NewAddrSet(),
			},
		},
		{
			name: "add an IPv6 address",
			action: func() {
				mgr.AddToIPSet(CiliumNodeIPSetV6, INet6Family, netip.MustParseAddr("cafe::1"))
			},
			expected: map[string]tables.AddrSet{
				CiliumNodeIPSetV4: tables.NewAddrSet(
					netip.MustParseAddr("2.2.2.2"),
				),
				CiliumNodeIPSetV6: tables.NewAddrSet(
					netip.MustParseAddr("cafe::1"),
				),
			},
		},
		{
			name: "remove an IPv6 address",
			action: func() {
				mgr.RemoveFromIPSet(CiliumNodeIPSetV6, netip.MustParseAddr("cafe::1"))
			},
			expected: map[string]tables.AddrSet{
				CiliumNodeIPSetV4: tables.NewAddrSet(
					netip.MustParseAddr("2.2.2.2"),
				),
				CiliumNodeIPSetV6: tables.NewAddrSet(),
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

	ipsets := make(map[string]tables.AddrSet) // mocked kernel IP sets
	var mu lock.Mutex                         // protect the ipsets map

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
				reconciler.New[*tables.IPSet],
				newReconcilerConfig,
				newOps,
			),
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
			cell.Invoke(reconciler.Register[*tables.IPSet]),

			// force manager instantiation
			cell.Invoke(func(_ Manager) {}),
		),
	)

	time.MaxInternalTimerDelay = time.Millisecond
	t.Cleanup(func() { time.MaxInternalTimerDelay = 0 })

	// create ipv4 and ipv6 node ipsets to simulate stale entries from previous Cilium run
	withLocked(&mu, func() {
		ipsets[CiliumNodeIPSetV4] = tables.NewAddrSet(netip.MustParseAddr("2.2.2.2"))
		ipsets[CiliumNodeIPSetV6] = tables.NewAddrSet(netip.MustParseAddr("cafe::1"))
	})

	assert.NoError(t, hive.Start(context.Background()))

	// Cilium node ipsets should have been pruned
	withLocked(&mu, func() {
		assert.NotContains(t, ipsets, CiliumNodeIPSetV4)
		assert.NotContains(t, ipsets, CiliumNodeIPSetV6)
	})

	// create a custom ipset (not managed by Cilium)
	withLocked(&mu, func() {
		ipsets["unmanaged-ipset"] = tables.NewAddrSet()
	})

	assert.NoError(t, hive.Stop(context.Background()))

	// ipset not managed by Cilium should not been pruned
	withLocked(&mu, func() {
		assert.Contains(t, ipsets, "unmanaged-ipset")
	})
}

func withLocked(m *lock.Mutex, f func()) {
	m.Lock()
	defer m.Unlock()

	f()
}

func TestIPSetList(t *testing.T) {
	testCases := []struct {
		name     string
		ipsets   map[string]tables.AddrSet
		expected tables.AddrSet
	}{
		{
			name: "empty ipset",
			ipsets: map[string]tables.AddrSet{
				"ciliumtest": tables.NewAddrSet(),
			},
			expected: tables.NewAddrSet(),
		},
		{
			name: "ipset with a single IP",
			ipsets: map[string]tables.AddrSet{
				"ciliumtest": tables.NewAddrSet(netip.MustParseAddr("1.1.1.1")),
			},
			expected: tables.NewAddrSet(netip.MustParseAddr("1.1.1.1")),
		},
		{
			name: "ipset with multiple IPs",
			ipsets: map[string]tables.AddrSet{
				"ciliumtest": tables.NewAddrSet(netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2.2.2.2")),
			},
			expected: tables.NewAddrSet(netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2.2.2.2")),
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
