// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package modules

import (
	"context"
	"testing"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestFindOrLoadModules(t *testing.T) {
	testutils.PrivilegedTest(t)

	testCases := []struct {
		modulesToFind []string
		expectedErr   bool
	}{
		{
			modulesToFind: []string{"bridge"},
			expectedErr:   false,
		},
		{
			modulesToFind: []string{"foo", "bar"},
			expectedErr:   true,
		},
	}

	var manager *Manager

	hive := hive.New(
		Cell,
		cell.Invoke(func(mgr *Manager) {
			manager = mgr
		}),
	)

	if err := hive.Start(context.Background()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}

	for _, tc := range testCases {
		err := manager.FindOrLoadModules(tc.modulesToFind...)
		if tc.expectedErr && err == nil {
			t.Fatal("expected error from FindOrLoadModules but none found")
		}
		if !tc.expectedErr && err != nil {
			t.Fatalf("FindOrLoadModules failed with unexpected error: %s", err)
		}
	}

	if err := hive.Stop(context.Background()); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}
