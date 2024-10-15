// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdp

import (
	"log/slog"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/hive"
)

func TestConf(t *testing.T) {
	enabler := func(mode AccelerationMode, opts ...enablerOpt) any {
		return func() EnablerOut { return NewEnabler(mode, opts...) }
	}

	tests := []struct {
		name             string
		accelerationMode AccelerationMode
		mode             Mode
		enablers         []any
		givesError       bool
	}{
		{
			name:             "enable generic",
			enablers:         []any{enabler(AccelerationModeGeneric)},
			givesError:       false,
			accelerationMode: AccelerationModeGeneric,
			mode:             ModeLinkGeneric,
		},
		{
			name:             "enable native",
			enablers:         []any{enabler(AccelerationModeNative)},
			givesError:       false,
			accelerationMode: AccelerationModeNative,
			mode:             ModeLinkDriver,
		},
		{
			name:             "enable best effort",
			enablers:         []any{enabler(AccelerationModeBestEffort)},
			givesError:       false,
			accelerationMode: AccelerationModeBestEffort,
			mode:             ModeLinkDriver,
		},
		{
			name:             "disable, single",
			enablers:         []any{enabler(AccelerationModeDisabled)},
			givesError:       false,
			accelerationMode: AccelerationModeDisabled,
			mode:             ModeLinkNone,
		},
		{
			name:             "disable, no enablers",
			enablers:         []any{},
			givesError:       false,
			accelerationMode: AccelerationModeDisabled,
			mode:             ModeLinkNone,
		},
		{
			name:       "conflicting enablers, native and generic",
			enablers:   []any{enabler(AccelerationModeNative), enabler(AccelerationModeGeneric)},
			givesError: true,
		},
		{
			name:       "conflicting enablers, best effort and generic",
			enablers:   []any{enabler(AccelerationModeBestEffort), enabler(AccelerationModeGeneric)},
			givesError: true,
		},
		{
			name:             "native and best effort results in native",
			enablers:         []any{enabler(AccelerationModeNative), enabler(AccelerationModeBestEffort)},
			accelerationMode: AccelerationModeNative,
			mode:             ModeLinkDriver,
		},
		{
			name:       "conflicting enablers, native and disabled validator",
			enablers:   []any{enabler(AccelerationModeNative, WithEnforceXDPDisabled("test native"))},
			givesError: true,
		},
		{
			name:       "conflicting enablers, best effort and disabled validator",
			enablers:   []any{enabler(AccelerationModeBestEffort, WithEnforceXDPDisabled("test best effort"))},
			givesError: true,
		},
		{
			name:       "conflicting enablers, generic and disabled validator",
			enablers:   []any{enabler(AccelerationModeGeneric, WithEnforceXDPDisabled("test generic"))},
			givesError: true,
		},
		{
			name:             "disabled validator passes when disabled",
			enablers:         []any{enabler(AccelerationModeDisabled, WithEnforceXDPDisabled("test generic"))},
			accelerationMode: AccelerationModeDisabled,
			mode:             ModeLinkNone,
		},
		{
			name: "conflicting enablers, disabled and native validator",
			enablers: []any{
				enabler(AccelerationModeDisabled, WithEnforceXDPDisabled("test disabled")),
				enabler(AccelerationModeNative, WithEnforceXDPNative("test disabled")),
			},
			givesError: true,
		},
		{
			name:       "native overwrites best effort",
			enablers:   []any{enabler(AccelerationModeBestEffort, WithEnforceXDPNative("test best effort"))},
			givesError: true,
		},
		{
			name:       "conflicting enablers, generic and native validator",
			enablers:   []any{enabler(AccelerationModeGeneric, WithEnforceXDPNative("test generic"))},
			givesError: true,
		},
		{
			name:             "native validator passes when native",
			enablers:         []any{enabler(AccelerationModeNative, WithEnforceXDPNative("test native"))},
			accelerationMode: AccelerationModeNative,
			mode:             ModeLinkDriver,
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
					t.Fatal("expected error from hive but got nil")
				}

				return
			} else if err != nil {
				t.Fatalf("unexpected error from hive: %s", err.Error())
			}

			if result.AccelerationMode() != test.accelerationMode {
				t.Errorf("expected acceleration mode %s but instead got %s", test.accelerationMode, result.AccelerationMode())
			}

			if result.Mode() != test.mode {
				t.Errorf("expected mode %s but instead got %s", test.mode, result.Mode())
			}
		})
	}
}
