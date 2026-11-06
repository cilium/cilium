// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/logging"
)

func TestCniUninstallConfDirFromEnv(t *testing.T) {
	tests := []struct {
		name         string
		cniConfDir   string
		setConfDir   bool
		hostPrefix   string
		setHostPrefx bool
		expected     string
	}{
		{name: "default", expected: "/host/etc/cni/net.d"},
		{name: "cni conf dir", cniConfDir: "/custom/net.d", setConfDir: true, expected: "/custom/net.d"},
		{name: "cni conf dir wins over host prefix", cniConfDir: "/custom/net.d", setConfDir: true, hostPrefix: "/hp", setHostPrefx: true, expected: "/custom/net.d"},
		{name: "host prefix", hostPrefix: "/hp", setHostPrefx: true, expected: "/hp/etc/cni/net.d"},
		{name: "empty values fall back to default", cniConfDir: "", setConfDir: true, hostPrefix: "", setHostPrefx: true, expected: "/host/etc/cni/net.d"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setConfDir {
				t.Setenv(cniUninstallEnvCNIConfDir, tt.cniConfDir)
			}
			if tt.setHostPrefx {
				t.Setenv(cniUninstallEnvHostPrefix, tt.hostPrefix)
			}
			require.Equal(t, tt.expected, cniUninstallConfDirFromEnv())
		})
	}
}

func TestRemoveCiliumCNIConfigs(t *testing.T) {
	setCniUninstallTestLogger(t)

	t.Run("removes only active Cilium CNI configurations", func(t *testing.T) {
		confDir := t.TempDir()

		create := map[string]string{
			"05-cilium.conflist":            "conf",
			"10-cilium-cni.conf":            "conf",
			"00-other.conflist":             "conf",
			"99-cilium-cni.conf.cilium_bak": "conf",
			"cilium.txt":                    "other",
			"CILIUM.conf":                   "conf",
		}
		for name, content := range create {
			require.NoError(t, os.WriteFile(filepath.Join(confDir, name), []byte(content), 0o644))
		}
		// Nested configurations are outside the top level of the
		// directory and must not be touched.
		nested := filepath.Join(confDir, "cilium-sub")
		require.NoError(t, os.Mkdir(nested, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(nested, "05-cilium.conflist"), []byte("conf"), 0o644))

		require.NoError(t, removeCiliumCNIConfigs(confDir))

		remaining := map[string]bool{}
		entries, err := os.ReadDir(confDir)
		require.NoError(t, err)
		for _, entry := range entries {
			remaining[entry.Name()] = true
		}
		require.False(t, remaining["05-cilium.conflist"])
		require.False(t, remaining["10-cilium-cni.conf"])
		require.True(t, remaining["00-other.conflist"])
		require.True(t, remaining["99-cilium-cni.conf.cilium_bak"])
		require.True(t, remaining["cilium.txt"])
		require.True(t, remaining["CILIUM.conf"], "matching is case-sensitive, as in find -name")
		require.True(t, remaining["cilium-sub"])

		_, err = os.Stat(filepath.Join(nested, "05-cilium.conflist"))
		require.NoError(t, err, "nested configurations must not be removed")
	})

	t.Run("missing directory", func(t *testing.T) {
		err := removeCiliumCNIConfigs(filepath.Join(t.TempDir(), "missing"))
		require.Error(t, err)
	})
}

// confDirFlagSentinel is replaced with the test CNI configuration
// directory so that table-driven tests can point the cni-conf-dir flag
// at it.
const confDirFlagSentinel = "CONFDIR"

// setCniUninstallTestLogger assigns a working logger to the package
// logger, which is normally initialized by initConfig and would
// otherwise be nil in tests.
func setCniUninstallTestLogger(t *testing.T) {
	t.Helper()
	old := log
	log = logging.DefaultSlogLogger
	t.Cleanup(func() { log = old })
}

// setupCniUninstall assigns a working logger and creates a CNI
// configuration directory containing an active Cilium configuration.
func setupCniUninstall(t *testing.T) (confDir string) {
	t.Helper()

	setCniUninstallTestLogger(t)

	confDir = t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(confDir, "05-cilium.conflist"), []byte("conf"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(confDir, "00-other.conflist"), []byte("conf"), 0o644))

	return confDir
}

func TestRunCniUninstall(t *testing.T) {
	tests := []struct {
		name           string
		flags          map[string]string
		env            map[string]string
		wantCiliumGone bool
		wantErr        bool
	}{
		{
			name:           "default removes Cilium configuration",
			wantCiliumGone: true,
		},
		{
			name:           "custom conf env skips removal",
			env:            map[string]string{cniUninstallEnvCustomCNIConf: "true"},
			wantCiliumGone: false,
		},
		{
			name:           "unrecognized custom conf env value does not skip",
			env:            map[string]string{cniUninstallEnvCustomCNIConf: "banana"},
			wantCiliumGone: true,
		},
		{
			name:           "custom conf flag beats env",
			flags:          map[string]string{"custom-cni-conf": "false"},
			env:            map[string]string{cniUninstallEnvCustomCNIConf: "true"},
			wantCiliumGone: true,
		},
		{
			name:           "custom conf flag skips removal",
			flags:          map[string]string{"custom-cni-conf": "true"},
			wantCiliumGone: false,
		},
		{
			name:           "conf dir flag beats env",
			flags:          map[string]string{"cni-conf-dir": confDirFlagSentinel},
			env:            map[string]string{cniUninstallEnvCNIConfDir: "/also/not/used"},
			wantCiliumGone: true,
		},
		{
			name:    "missing conf dir is an error",
			flags:   map[string]string{"cni-conf-dir": "MISSING_DIR"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			confDir := setupCniUninstall(t)

			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			// Point the default (flag-less) resolution at the test
			// directory unless the test overrides it explicitly.
			if _, ok := tt.flags["cni-conf-dir"]; !ok {
				if _, ok := tt.env[cniUninstallEnvCNIConfDir]; !ok {
					t.Setenv(cniUninstallEnvCNIConfDir, confDir)
				}
			}

			cmd := newCniUninstallCmd()
			for name, value := range tt.flags {
				if value == confDirFlagSentinel {
					value = confDir
				}
				require.NoError(t, cmd.Flags().Set(name, value))
			}

			err := runCniUninstall(cmd)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			_, err = os.Stat(filepath.Join(confDir, "05-cilium.conflist"))
			if tt.wantCiliumGone {
				require.True(t, os.IsNotExist(err), "Cilium configuration should have been removed")
			} else {
				require.NoError(t, err, "Cilium configuration should have been kept")
			}
			if _, err := os.Stat(filepath.Join(confDir, "00-other.conflist")); err != nil {
				t.Fatalf("non-Cilium configuration was removed: %s", err)
			}
		})
	}

	t.Run("conf dir from env", func(t *testing.T) {
		confDir := setupCniUninstall(t)
		t.Setenv(cniUninstallEnvCNIConfDir, confDir)

		require.NoError(t, runCniUninstall(newCniUninstallCmd()))

		_, err := os.Stat(filepath.Join(confDir, "05-cilium.conflist"))
		require.True(t, os.IsNotExist(err), "Cilium configuration should have been removed")
	})
}
