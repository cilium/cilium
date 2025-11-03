// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sysctl

import (
	"context"
	"errors"
	"os"
	"path"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

func TestFullPath(t *testing.T) {
	testCases := []struct {
		name        []string
		expected    string
		expectedErr bool
	}{
		{
			name:     []string{"net", "ipv4", "ip_forward"},
			expected: "/proc/sys/net/ipv4/ip_forward",
		},
		{
			name:     []string{"net", "ipv4", "conf", "all", "forwarding"},
			expected: "/proc/sys/net/ipv4/conf/all/forwarding",
		},
		{
			name:     []string{"net", "ipv6", "conf", "all", "forwarding"},
			expected: "/proc/sys/net/ipv6/conf/all/forwarding",
		},
		{
			name:     []string{"net", "ipv6", "conf", "eth0.100", "forwarding"},
			expected: "/proc/sys/net/ipv6/conf/eth0.100/forwarding",
		},
		{
			name:     []string{"foo", "bar"},
			expected: "/proc/sys/foo/bar",
		},
		{
			name:        []string{"double", "", "dot"},
			expectedErr: true,
		},
		{
			name:        []string{"invalid", "char$"},
			expectedErr: true,
		},
		{
			name:     []string{"Foo", "Bar"},
			expected: "/proc/sys/Foo/Bar",
		},
	}

	for _, tc := range testCases {
		path, err := parameterPath("/proc", tc.name)
		if tc.expectedErr {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, path)
		}
	}
}

func TestWaitForReconciliation(t *testing.T) {
	defer testutils.GoleakVerifyNone(t)

	const paramName = "fake-parameter"

	var (
		db       *statedb.DB
		settings statedb.RWTable[*tables.Sysctl]
	)

	hive := hive.New(
		cell.Provide(tables.NewSysctlTable),
		cell.Invoke(func(statedb *statedb.DB, tb statedb.RWTable[*tables.Sysctl]) {
			db = statedb
			settings = tb
		}),
	)

	tlog := hivetest.Logger(t)
	assert.NoError(t, hive.Start(tlog, context.Background()))

	time.MaxInternalTimerDelay = time.Millisecond
	t.Cleanup(func() { time.MaxInternalTimerDelay = 0 })

	sysctl := &reconcilingSysctl{db, settings, nil, ""}
	sysctl.Enable([]string{paramName})

	// waitForReconciliation should timeout
	assert.Error(t, sysctl.waitForReconciliation([]string{paramName}))

	// fake a successful reconciliation
	txn := db.WriteTxn(settings)
	old, _, found := settings.Get(txn, tables.SysctlNameIndex.Query(paramName))
	_, exist, err := settings.Insert(txn, old.Clone().SetStatus(reconciler.StatusDone()))
	txn.Commit()

	assert.True(t, found)
	assert.Equal(t, reconciler.StatusKindPending, old.Status.Kind)
	assert.True(t, exist)
	assert.NoError(t, err)

	// waitForReconciliation should return without error
	assert.NoError(t, sysctl.waitForReconciliation([]string{paramName}))

	assert.NoError(t, hive.Stop(tlog, context.Background()))
}

func TestSysctl(t *testing.T) {
	defer testutils.GoleakVerifyNone(t)

	settings := [][]string{
		{"net", "ipv4", "ip_forward"},
		{"net", "ipv4", "conf", "all", "forwarding"},
		{"net", "ipv6", "conf", "all", "forwarding"},
	}

	var sysctl SysctlManager
	var table statedb.RWTable[*tables.Sysctl]
	var db *statedb.DB

	hive := hive.New(
		cell.Config(defaultConfig),

		cell.Provide(
			func() afero.Fs {
				return afero.NewMemMapFs()
			},
		),
		cell.Provide(
			newReconcilingSysctl,
			tables.NewSysctlTable,
			newReconciler,
			newOps,
		),

		cell.Invoke(func(s SysctlManager, t statedb.RWTable[*tables.Sysctl],
			d *statedb.DB) {
			sysctl = s
			db = d
			table = t
		}),
		cell.Invoke(func(fs afero.Fs) {
			for _, s := range settings {
				path := sysctlToPath(s)
				if err := fs.MkdirAll(filepath.Dir(path), os.ModeDir); err != nil {
					t.Fatalf("unable to create directory %q: %s", filepath.Dir(path), err)
				}
				f, err := fs.Create(path)
				if err != nil {
					t.Fatalf("unable to create test file %q: %s", path, err)
				}
				if _, err := f.WriteString("0"); err != nil {
					t.Fatalf("unable to write to test file %q: %s", path, err)
				}
				if err := f.Close(); err != nil {
					t.Fatalf("unable to close test file %q: %s", path, err)
				}
			}
		}),
	)

	tlog := hivetest.Logger(t)
	assert.NoError(t, hive.Start(tlog, context.Background()))

	for _, s := range settings {
		assert.NoError(t, sysctl.Write(s, "1"))

		val, err := sysctl.Read(s)
		assert.NoError(t, err)
		assert.Equal(t, "1", val, "unexpected value for parameter %q", s)
	}

	for _, s := range settings {
		assert.NoError(t, sysctl.WriteInt(s, 7))

		val, err := sysctl.ReadInt(s)
		assert.NoError(t, err)
		assert.Equal(t, int64(7), val, "unexpected value for parameter %q", s)
	}

	for _, s := range settings {
		assert.NoError(t, sysctl.Disable(s))

		val, err := sysctl.Read(s)
		assert.NoError(t, err)
		assert.Equal(t, "0", val, "unexpected value for parameter %q", s)
	}

	for _, s := range settings {
		assert.NoError(t, sysctl.Enable(s))

		val, err := sysctl.Read(s)
		assert.NoError(t, err)
		assert.Equal(t, "1", val, "unexpected value for parameter %q", s)
	}

	batch := make([]tables.Sysctl, len(settings))
	for i, s := range settings {
		batch[i].Name = s
		batch[i].Val = "2"
	}
	assert.NoError(t, sysctl.UpsertSettings(batch))
	for _, s := range batch {
		val, err := sysctl.Read(s.Name)
		assert.NoError(t, err)
		assert.Equal(t, s.Val, val, "unexpected value %q for parameter %q", val, s.Name)
	}

	sysctl.DeleteSettings([]tables.Sysctl{batch[0]})

	for _, entry := range table.All(db.ReadTxn()) {
		assert.NotEqual(t, entry, batch[0])
	}

	sysctl.DeleteSettings(batch)

	for range table.All(db.ReadTxn()) {
		assert.Fail(t, "should not have any remaining entries")
	}

	assert.NoError(t, hive.Stop(tlog, context.Background()))
}

func assertCiliumNetNSDir(t *testing.T) {
	err := os.MkdirAll(defaults.NetNsPath, 0755)
	if err != nil {
		if !errors.Is(err, os.ErrExist) {
			return
		}
		assert.NoError(t, err)
	}
}

// createTestNetns cleans up any leftover testns of the same name, and attempts
// to create a new one - also schedules cleanup task to cleanup afterwards.
func createTestNetns(t *testing.T, name string) *netns.NetNS {
	// cleanup old test files
	pin := path.Join(defaults.NetNsPath, name)
	syscall.Unmount(pin, 0)
	os.RemoveAll(pin)

	assertCiliumNetNSDir(t)

	ns, err := netns.NewPinned(pin)
	assert.NoError(t, err)
	t.Cleanup(func() {
		ns.Close()
		syscall.Unmount(pin, 0)
		os.RemoveAll(pin)
	})

	assert.NoError(t, err)

	return ns
}

// TestSysctlNamespaced checks functionality of a namespaced sysctl setting, that is
// to be reconciled inside a netns.
func TestSysctlNamespaced(t *testing.T) {
	defer testutils.GoleakVerifyNone(t)

	reconcilerRefreshTime = time.Millisecond * 250

	direct := NewDirectSysctl(afero.NewOsFs(), "/proc")
	hostNSVal, err := direct.Read([]string{"net", "ipv4", "tcp_mtu_probing"})
	assert.NoError(t, err)

	ns := createTestNetns(t, "cilium_test_sysctl_namespaced")

	nsc, err := ns.GetNetNSCookie()
	assert.NoError(t, err)

	settings := [][]string{
		{"net", "ipv4", "ip_forward"},
		{"net", "ipv4", "conf", "all", "forwarding"},
		{"net", "ipv6", "conf", "all", "forwarding"},
	}

	var sysctl SysctlManager

	hive := hive.New(
		cell.Config(defaultConfig),

		cell.Provide(
			func() afero.Fs {
				//return afero.NewMemMapFs()
				return afero.NewOsFs()
			},
		),
		cell.Provide(
			newReconcilingSysctl,
			tables.NewSysctlTable,
			newReconciler,
			newOps,
		),

		cell.Invoke(func(s SysctlManager, t statedb.RWTable[*tables.Sysctl],
			d *statedb.DB) {
			sysctl = s
		}),
		cell.Invoke(func(fs afero.Fs) {
			for _, s := range settings {
				path := sysctlToPath(s)
				if err := fs.MkdirAll(filepath.Dir(path), os.ModeDir); err != nil {
					t.Fatalf("unable to create directory %q: %s", filepath.Dir(path), err)
				}
				f, err := fs.Create(path)
				if err != nil {
					t.Fatalf("unable to create test file %q: %s", path, err)
				}
				if _, err := f.WriteString("0"); err != nil {
					t.Fatalf("unable to write to test file %q: %s", path, err)
				}
				if err := f.Close(); err != nil {
					t.Fatalf("unable to close test file %q: %s", path, err)
				}
			}
		}),
	)

	tlog := hivetest.Logger(t)
	assert.NoError(t, hive.Start(tlog, context.Background()))

	netNSVal := "2"
	// do something else but what host netns has.
	if hostNSVal == "2" {
		netNSVal = "0"
	}
	assert.NoError(t, sysctl.UpsertSettings([]tables.Sysctl{
		{Name: []string{"net", "ipv4", "tcp_mtu_probing"}, Val: netNSVal, NetNSCookie: nsc},
	}))

	ns.Do(func() error {
		val, err := direct.Read([]string{"net", "ipv4", "tcp_mtu_probing"})
		assert.NoError(t, err)
		assert.Equal(t, val, netNSVal)
		return err
	})

	// Ensure host netns was not affected.
	hostNSVal, err = direct.Read([]string{"net", "ipv4", "tcp_mtu_probing"})
	assert.NoError(t, err)
	assert.NotEqual(t, netNSVal, hostNSVal)

	// Force a out-of-band change and ensure reconciler fixes it.
	ns.Do(func() error {
		err := direct.Write([]string{"net", "ipv4", "tcp_mtu_probing"}, hostNSVal)
		assert.NoError(t, err)
		return nil
	})

	assert.EventuallyWithT(t, func(t *assert.CollectT) {
		ns.Do(func() error {
			val, err := direct.Read([]string{"net", "ipv4", "tcp_mtu_probing"})
			assert.NoError(t, err)
			assert.Equal(t, netNSVal, val)
			return nil
		})
	}, time.Second*5, time.Millisecond*500)

	assert.NoError(t, hive.Stop(tlog, context.Background()))
}

func TestSysctlIgnoreErr(t *testing.T) {
	defer testutils.GoleakVerifyNone(t)

	parameter := tables.Sysctl{Name: []string{"net", "core", "bpf_jit_enable"}, Val: "1", IgnoreErr: true}

	var sysctl SysctlManager

	hive := hive.New(
		cell.Config(defaultConfig),

		cell.Provide(
			func() afero.Fs {
				return afero.NewMemMapFs()
			},
		),
		cell.Provide(
			newReconcilingSysctl,
			tables.NewSysctlTable,
			newReconciler,
			newOps,
		),

		cell.Invoke(func(s SysctlManager) {
			sysctl = s
		}),
	)

	tlog := hivetest.Logger(t)
	assert.NoError(t, hive.Start(tlog, context.Background()))

	// should not return an error since the parameter is marked as IgnoreErr
	assert.NoError(t, sysctl.UpsertSettings([]tables.Sysctl{parameter}))

	assert.NoError(t, hive.Stop(tlog, context.Background()))
}

func sysctlToPath(name []string) string {
	return filepath.Join(append([]string{"/proc", "sys"}, name...)...)
}
