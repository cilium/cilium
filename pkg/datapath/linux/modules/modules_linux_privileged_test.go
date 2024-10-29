// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package modules

import (
	"context"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestFindOrLoadModules(t *testing.T) {
	testutils.PrivilegedTest(t)

	testCases := []struct {
		skipValidation bool
		modulesToFind  []string
		expectedErr    bool
	}{
		{
			skipValidation: false,
			modulesToFind:  []string{"bridge"},
			expectedErr:    false,
		},
		{
			skipValidation: false,
			modulesToFind:  []string{"foo", "bar"},
			expectedErr:    true,
		},
		{
			skipValidation: true,
			modulesToFind:  []string{"bridge"},
			expectedErr:    false,
		},
		{
			skipValidation: true,
			modulesToFind:  []string{"foo", "bar"},
			expectedErr:    false,
		},
	}

	var manager *Manager

	hive := hive.New(
		Cell,
		cell.Invoke(func(mgr *Manager) {
			manager = mgr
		}),
	)

	tlog := hivetest.Logger(t)
	if err := hive.Start(tlog, context.Background()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}

	for _, tc := range testCases {
		err := manager.FindOrLoadModules(tc.skipValidation, tc.modulesToFind...)
		if tc.expectedErr && err == nil {
			t.Fatal("expected error from FindOrLoadModules but none found")
		}
		if !tc.expectedErr && err != nil {
			t.Fatalf("FindOrLoadModules failed with unexpected error: %s", err)
		}
	}

	if err := hive.Stop(tlog, context.Background()); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}
