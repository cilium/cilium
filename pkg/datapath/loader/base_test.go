// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/tables"
)

func TestBaseSysctlsTimerMigration(t *testing.T) {
	hasTimerMigration := func(settings []tables.Sysctl) bool {
		return slices.ContainsFunc(settings, func(s tables.Sysctl) bool {
			return slices.Equal(s.Name, []string{"kernel", "timer_migration"}) && s.Val == "0"
		})
	}

	require.True(t, hasTimerMigration(baseSysctls(defaultConfig)))
	require.False(t, hasTimerMigration(baseSysctls(loaderConfig{DisableTimerMigration: false})))
}
