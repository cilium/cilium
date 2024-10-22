// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sysctl

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/reconciler"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/hive"
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
			assert.Equal(t, path, tc.expected)
		}
	}
}

func TestWaitForReconciliation(t *testing.T) {
	defer goleak.VerifyNone(t)

	const paramName = "fake-parameter"

	var (
		db       *statedb.DB
		settings statedb.RWTable[*tables.Sysctl]
	)

	hive := hive.New(
		cell.Module(
			"sysctl-test",
			"sysctl-test",

			cell.Provide(func(db *statedb.DB) (statedb.RWTable[*tables.Sysctl], statedb.Index[*tables.Sysctl, reconciler.StatusKind], error) {
				return tables.NewSysctlTable(db)
			}),
			cell.Invoke(func(db *statedb.DB, settings statedb.RWTable[*tables.Sysctl]) {
				db.RegisterTable(settings)
			}),

			cell.Invoke(func(statedb *statedb.DB, tb statedb.RWTable[*tables.Sysctl]) {
				db = statedb
				settings = tb
			}),
		),
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
	assert.Equal(t, old.Status.Kind, reconciler.StatusKindPending)
	assert.True(t, exist)
	assert.NoError(t, err)

	// waitForReconciliation should return without error
	assert.NoError(t, sysctl.waitForReconciliation([]string{paramName}))

	assert.NoError(t, hive.Stop(tlog, context.Background()))
}

func TestSysctl(t *testing.T) {
	defer goleak.VerifyNone(t)

	settings := [][]string{
		{"net", "ipv4", "ip_forward"},
		{"net", "ipv4", "conf", "all", "forwarding"},
		{"net", "ipv6", "conf", "all", "forwarding"},
	}

	var sysctl Sysctl

	hive := hive.New(
		cell.Module(
			"sysctl-test",
			"sysctl-test",
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
		),

		cell.Invoke(func(s Sysctl) {
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
	assert.NoError(t, sysctl.ApplySettings(batch))
	for _, s := range batch {
		val, err := sysctl.Read(s.Name)
		assert.NoError(t, err)
		assert.Equal(t, s.Val, val, "unexpected value %q for parameter %q", val, s.Name)
	}

	assert.NoError(t, hive.Stop(tlog, context.Background()))
}

func TestSysctlIgnoreErr(t *testing.T) {
	defer goleak.VerifyNone(t)

	parameter := tables.Sysctl{Name: []string{"net", "core", "bpf_jit_enable"}, Val: "1", IgnoreErr: true}

	var sysctl Sysctl

	hive := hive.New(
		cell.Module(
			"sysctl-test",
			"sysctl-test",
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
		),

		cell.Invoke(func(s Sysctl) {
			sysctl = s
		}),
	)

	tlog := hivetest.Logger(t)
	assert.NoError(t, hive.Start(tlog, context.Background()))

	// should not return an error since the parameter is marked as IgnoreErr
	assert.NoError(t, sysctl.ApplySettings([]tables.Sysctl{parameter}))

	assert.NoError(t, hive.Stop(tlog, context.Background()))
}

func sysctlToPath(name []string) string {
	return filepath.Join(append([]string{"/proc", "sys"}, name...)...)
}
