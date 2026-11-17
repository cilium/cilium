// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRemoveSysctlConf(t *testing.T) {
	dir := t.TempDir()
	oldPath := sysctlConfPath
	sysctlConfPath = filepath.Join(dir, "99-zzz-override_cilium.conf")
	t.Cleanup(func() { sysctlConfPath = oldPath })

	other := filepath.Join(dir, "10-other.conf")
	require.NoError(t, os.WriteFile(other, []byte("net.ipv4.conf.all.rp_filter = 1\n"), 0644))
	require.NoError(t, os.WriteFile(sysctlConfPath, []byte("net.ipv4.conf.all.rp_filter = 0\n"), 0644))

	line := "sysctl config at " + sysctlConfPath
	require.Contains(t, ciliumCleanup{}.whatWillBeRemoved(), line)
	require.NotContains(t, ciliumCleanup{bpfOnly: true}.whatWillBeRemoved(), line)
	require.True(t, hasCleanupFunc(ciliumCleanup{}.cleanupFuncs(), removeSysctlConf))
	require.False(t, hasCleanupFunc(ciliumCleanup{bpfOnly: true}.cleanupFuncs(), removeSysctlConf))

	require.NoError(t, removeSysctlConf())
	require.NoFileExists(t, sysctlConfPath)
	require.FileExists(t, other)
	require.NotContains(t, ciliumCleanup{}.whatWillBeRemoved(), line)

	// Running the cleanup again with nothing left to remove is not an error.
	require.NoError(t, removeSysctlConf())
}

func hasCleanupFunc(funcs []cleanupFunc, want cleanupFunc) bool {
	for _, f := range funcs {
		if reflect.ValueOf(f).Pointer() == reflect.ValueOf(want).Pointer() {
			return true
		}
	}
	return false
}
