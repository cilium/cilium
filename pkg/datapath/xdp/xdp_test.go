// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdp

import (
	"testing"

	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/hive"
)

func TestConf(t *testing.T) {
	enabler := func(mode Mode, opts ...enablerOpt) any {
		return func() EnablerOut { return NewEnabler(mode, opts...) }
	}

	tests := []struct {
		name       string
		enablers   []any
		givesError bool
		mode       Mode
		tcMode     TCMode
	}{
		{
			name:       "enable generic",
			enablers:   []any{enabler(ModeGeneric)},
			givesError: false,
			mode:       ModeGeneric,
			tcMode:     TCModeLinkGeneric,
		},
		{
			name:       "enable native",
			enablers:   []any{enabler(ModeNative)},
			givesError: false,
			mode:       ModeNative,
			tcMode:     TCModeLinkDriver,
		},
		{
			name:       "enable best effort",
			enablers:   []any{enabler(ModeBestEffort)},
			givesError: false,
			mode:       ModeBestEffort,
			tcMode:     TCModeLinkDriver,
		},
		{
			name:       "disable, single",
			enablers:   []any{enabler(ModeDisabled)},
			givesError: false,
			mode:       ModeDisabled,
			tcMode:     TCModeLinkNone,
		},
		{
			name:       "disable, no enablers",
			enablers:   []any{},
			givesError: false,
			mode:       ModeDisabled,
			tcMode:     TCModeLinkNone,
		},
		{
			name:       "conflicting enablers, native and generic",
			enablers:   []any{enabler(ModeNative), enabler(ModeGeneric)},
			givesError: true,
		},
		{
			name:       "conflicting enablers, best effort and generic",
			enablers:   []any{enabler(ModeBestEffort), enabler(ModeGeneric)},
			givesError: true,
		},
		{
			name:     "native and best effort results in native",
			enablers: []any{enabler(ModeNative), enabler(ModeBestEffort)},
			mode:     ModeNative,
			tcMode:   TCModeLinkDriver,
		},
		{
			name:       "conflicting enablers, native and disabled validator",
			enablers:   []any{enabler(ModeNative, WithEnforceXDPDisabled("test native"))},
			givesError: true,
		},
		{
			name:       "conflicting enablers, best effort and disabled validator",
			enablers:   []any{enabler(ModeBestEffort, WithEnforceXDPDisabled("test best effort"))},
			givesError: true,
		},
		{
			name:       "conflicting enablers, generic and disabled validator",
			enablers:   []any{enabler(ModeGeneric, WithEnforceXDPDisabled("test generic"))},
			givesError: true,
		},
		{
			name:     "disabled validator passes when disabled",
			enablers: []any{enabler(ModeDisabled, WithEnforceXDPDisabled("test generic"))},
			mode:     ModeDisabled,
			tcMode:   TCModeLinkNone,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var result Config

			err := hive.New(
				cell.Provide(newConfig),
				cell.Provide(test.enablers...),
				cell.Invoke(func(cfg Config) { result = cfg }),
			).Populate(hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug)))

			if test.givesError {
				if err == nil {
					t.Error("expected error from hive but got nil")
					t.FailNow()
				}

				return
			}

			if result.Mode() != test.mode {
				t.Errorf("expected mode %s but instead got %s", test.mode, result.Mode())
			}

			if result.TCMode() != test.tcMode {
				t.Errorf("expected tcMode %s but instead got %s", test.tcMode, result.TCMode())
			}
		})
	}
}
