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

// setTestLogger assigns a working logger to the package logger, which is
// normally initialized by initConfig and would otherwise be nil in tests.
func setTestLogger(t *testing.T) {
	t.Helper()
	old := log
	log = logging.DefaultSlogLogger
	t.Cleanup(func() { log = old })
}

const (
	testCiliumContent   = "cilium-cni-binary"
	testLoopbackContent = "loopback-binary"
)

func TestCniBinDirFromEnv(t *testing.T) {
	tests := []struct {
		name         string
		cniDir       string
		setCniDir    bool
		hostPrefix   string
		setHostPrefx bool
		expected     string
	}{
		{name: "default", expected: "/host/opt/cni/bin"},
		{name: "cni_dir", cniDir: "/custom/cni", setCniDir: true, expected: "/custom/cni/bin"},
		{name: "cni_dir wins over host_prefix", cniDir: "/custom/cni", setCniDir: true, hostPrefix: "/hp", setHostPrefx: true, expected: "/custom/cni/bin"},
		{name: "host_prefix", hostPrefix: "/hp", setHostPrefx: true, expected: "/hp/opt/cni/bin"},
		{name: "empty values fall back to default", cniDir: "", setCniDir: true, hostPrefix: "", setHostPrefx: true, expected: "/host/opt/cni/bin"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setCniDir {
				t.Setenv(envCNIPath, tt.cniDir)
			}
			if tt.setHostPrefx {
				t.Setenv(envHostPrefix, tt.hostPrefix)
			}
			require.Equal(t, tt.expected, cniBinDirFromEnv())
		})
	}
}

func TestFlagOrEnv(t *testing.T) {
	const envVar = "TEST_FLAG_OR_ENV"
	tests := []struct {
		name      string
		setFlag   bool
		flagValue bool
		setEnv    bool
		envValue  string
		fallback  bool
		expected  bool
	}{
		{name: "unset flag and unset env use fallback", fallback: true, expected: true},
		{name: "unset flag and unset env use fallback false", fallback: false, expected: false},
		{name: "unset flag honors env true", setEnv: true, envValue: "true", fallback: false, expected: true},
		{name: "unset flag honors env false", setEnv: true, envValue: "false", fallback: true, expected: false},
		{name: "unset flag with unrecognized env value is false", setEnv: true, envValue: "banana", fallback: true, expected: false},
		{name: "unset flag with empty env value uses fallback", setEnv: true, envValue: "", fallback: true, expected: true},
		{name: "flag true beats env false", setFlag: true, flagValue: true, setEnv: true, envValue: "false", fallback: false, expected: true},
		{name: "flag false beats env true", setFlag: true, flagValue: false, setEnv: true, envValue: "true", fallback: true, expected: false},
		{name: "flag true beats fallback false", setFlag: true, flagValue: true, fallback: false, expected: true},
		{name: "flag false beats fallback true", setFlag: true, flagValue: false, fallback: true, expected: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setEnv {
				t.Setenv(envVar, tt.envValue)
			}
			cmd := newInstallCNIBinariesCmd()
			if tt.setFlag {
				require.NoError(t, cmd.Flags().Set("overwrite-cilium", boolToString(tt.flagValue)))
			}
			require.Equal(t, tt.expected, flagOrEnv(cmd, "overwrite-cilium", tt.flagValue, envVar, tt.fallback))
		})
	}
}

func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func TestFileExists(t *testing.T) {
	dir := t.TempDir()

	file := filepath.Join(dir, "file")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o755))
	subdir := filepath.Join(dir, "subdir")
	require.NoError(t, os.Mkdir(subdir, 0o755))

	require.True(t, fileExists(file))
	require.False(t, fileExists(subdir), "directories are not regular files")
	require.False(t, fileExists(filepath.Join(dir, "missing")))
}

func TestInstallPlugin(t *testing.T) {
	setTestLogger(t)
	srcDir := t.TempDir()
	dstDir := t.TempDir()

	src := filepath.Join(srcDir, "plugin")
	require.NoError(t, os.WriteFile(src, []byte(testCiliumContent), 0o755))

	t.Run("copies content and mode", func(t *testing.T) {
		dst := filepath.Join(dstDir, "plugin")
		require.NoError(t, installPlugin(src, dst))

		content, err := os.ReadFile(dst)
		require.NoError(t, err)
		require.Equal(t, testCiliumContent, string(content))

		info, err := os.Stat(dst)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o755), info.Mode().Perm())
	})

	t.Run("replaces existing file", func(t *testing.T) {
		dst := filepath.Join(dstDir, "existing")
		require.NoError(t, os.WriteFile(dst, []byte("old"), 0o644))

		require.NoError(t, installPlugin(src, dst))

		content, err := os.ReadFile(dst)
		require.NoError(t, err)
		require.Equal(t, testCiliumContent, string(content))
	})

	t.Run("creates parent directories", func(t *testing.T) {
		dst := filepath.Join(dstDir, "nested", "dirs", "plugin")
		require.NoError(t, installPlugin(src, dst))

		_, err := os.Stat(dst)
		require.NoError(t, err)
	})

	t.Run("no temporary file left behind", func(t *testing.T) {
		dstDir := t.TempDir()
		dst := filepath.Join(dstDir, "clean")
		require.NoError(t, installPlugin(src, dst))

		entries, err := os.ReadDir(dstDir)
		require.NoError(t, err)
		for _, entry := range entries {
			require.NotEqual(t, ".clean.new", entry.Name(), "temporary file was not cleaned up")
		}
		require.Len(t, entries, 1)
	})

	t.Run("missing source", func(t *testing.T) {
		err := installPlugin(filepath.Join(srcDir, "missing"), filepath.Join(dstDir, "x"))
		require.Error(t, err)
	})

	t.Run("read-only destination", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("running as root, file permissions do not apply")
		}
		roDir := t.TempDir()
		require.NoError(t, os.Chmod(roDir, 0o555))
		t.Cleanup(func() { require.NoError(t, os.Chmod(roDir, 0o755)) })

		err := installPlugin(src, filepath.Join(roDir, "plugin"))
		require.Error(t, err)

		// The destination must not have been created and no temporary
		// file may be left behind.
		entries, err := os.ReadDir(roDir)
		require.NoError(t, err)
		require.Empty(t, entries)
	})
}

// setupInstallCNIBinaries creates the source binaries in a temporary
// directory and redirects the image paths to them.
func setupInstallCNIBinaries(t *testing.T) (cniDir string) {
	t.Helper()

	srcDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "cilium-cni"), []byte(testCiliumContent), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "loopback"), []byte(testLoopbackContent), 0o755))

	oldCilium, oldLoopback := ciliumCNIBinaryPath, loopbackBinaryPath
	ciliumCNIBinaryPath = filepath.Join(srcDir, "cilium-cni")
	loopbackBinaryPath = filepath.Join(srcDir, "loopback")
	t.Cleanup(func() {
		ciliumCNIBinaryPath, loopbackBinaryPath = oldCilium, oldLoopback
	})

	cniDir = filepath.Join(t.TempDir(), "opt", "cni", "bin")
	return cniDir
}

func readPlugin(t *testing.T, cniDir, name string) (string, bool) {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(cniDir, name))
	if os.IsNotExist(err) {
		return "", false
	}
	require.NoError(t, err)
	return string(content), true
}

func TestRunInstallCNIBinaries(t *testing.T) {
	setTestLogger(t)
	tests := []struct {
		name         string
		flags        map[string]string
		env          map[string]string
		preExisting  map[string]string // name -> content already in the CNI bin dir
		omitSource   string            // source binary to remove
		wantCilium   string            // expected cilium-cni content, "" means absent
		wantLoopback string
		wantErr      bool
	}{
		{
			name:         "fresh install",
			wantCilium:   testCiliumContent,
			wantLoopback: testLoopbackContent,
		},
		{
			name:         "loopback kept by default, cilium-cni replaced",
			preExisting:  map[string]string{"loopback": "old-loopback", "cilium-cni": "old-cilium"},
			wantCilium:   testCiliumContent,
			wantLoopback: "old-loopback",
		},
		{
			name:         "env overwrite loopback",
			env:          map[string]string{envOverwriteLoopback: "true"},
			preExisting:  map[string]string{"loopback": "old-loopback"},
			wantCilium:   testCiliumContent,
			wantLoopback: testLoopbackContent,
		},
		{
			name:         "env overwrite cilium disabled",
			env:          map[string]string{envOverwriteCilium: "false"},
			preExisting:  map[string]string{"cilium-cni": "old-cilium"},
			wantCilium:   "old-cilium",
			wantLoopback: testLoopbackContent,
		},
		{
			name:         "unrecognized env value does not overwrite",
			env:          map[string]string{envOverwriteCilium: "banana"},
			preExisting:  map[string]string{"cilium-cni": "old-cilium"},
			wantCilium:   "old-cilium",
			wantLoopback: testLoopbackContent,
		},
		{
			name:         "flag beats env",
			flags:        map[string]string{"overwrite-loopback": "false"},
			env:          map[string]string{envOverwriteLoopback: "true"},
			preExisting:  map[string]string{"loopback": "old-loopback"},
			wantCilium:   testCiliumContent,
			wantLoopback: "old-loopback",
		},
		{
			name:         "flag disables cilium overwrite",
			flags:        map[string]string{"overwrite-cilium": "false"},
			preExisting:  map[string]string{"cilium-cni": "old-cilium"},
			wantCilium:   "old-cilium",
			wantLoopback: testLoopbackContent,
		},
		{
			name:         "missing loopback source is not fatal",
			omitSource:   filepath.Base(loopbackBinaryPath),
			wantCilium:   testCiliumContent,
			wantLoopback: "",
		},
		{
			name:       "missing cilium-cni source is fatal",
			omitSource: filepath.Base(ciliumCNIBinaryPath),
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cniDir := setupInstallCNIBinaries(t)

			if tt.omitSource != "" {
				require.NoError(t, os.Remove(filepath.Join(filepath.Dir(ciliumCNIBinaryPath), tt.omitSource)))
			}
			for name, content := range tt.preExisting {
				require.NoError(t, os.MkdirAll(cniDir, 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(cniDir, name), []byte(content), 0o755))
			}
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			cmd := newInstallCNIBinariesCmd()
			require.NoError(t, cmd.Flags().Set("cni-dir", cniDir))
			for name, value := range tt.flags {
				require.NoError(t, cmd.Flags().Set(name, value))
			}

			err := runInstallCNIBinaries(cmd)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			if got, ok := readPlugin(t, cniDir, "cilium-cni"); tt.wantCilium == "" {
				require.False(t, ok, "cilium-cni should not be installed")
			} else {
				require.Equal(t, tt.wantCilium, got, "cilium-cni")
			}
			if got, ok := readPlugin(t, cniDir, "loopback"); tt.wantLoopback == "" {
				require.False(t, ok, "loopback should not be installed")
			} else {
				require.Equal(t, tt.wantLoopback, got, "loopback")
			}
		})
	}
}

func TestRunInstallCNIBinariesDirResolution(t *testing.T) {
	setTestLogger(t)

	t.Run("cni dir flag wins over env", func(t *testing.T) {
		cniDir := setupInstallCNIBinaries(t)
		t.Setenv(envCNIPath, "/should/not/be/used")

		cmd := newInstallCNIBinariesCmd()
		require.NoError(t, cmd.Flags().Set("cni-dir", cniDir))

		require.NoError(t, runInstallCNIBinaries(cmd))
		require.Equal(t, testCiliumContent, readPluginOrFatal(t, cniDir, "cilium-cni"))
	})

	t.Run("cni dir from env", func(t *testing.T) {
		_ = setupInstallCNIBinaries(t)
		base := t.TempDir()
		t.Setenv(envCNIPath, base)

		require.NoError(t, runInstallCNIBinaries(newInstallCNIBinariesCmd()))
		require.Equal(t, testCiliumContent, readPluginOrFatal(t, filepath.Join(base, "bin"), "cilium-cni"))
	})

	t.Run("cni dir from host prefix env", func(t *testing.T) {
		_ = setupInstallCNIBinaries(t)
		base := t.TempDir()
		t.Setenv(envHostPrefix, base)

		require.NoError(t, runInstallCNIBinaries(newInstallCNIBinariesCmd()))
		require.Equal(t, testCiliumContent, readPluginOrFatal(t, filepath.Join(base, "opt", "cni", "bin"), "cilium-cni"))
	})

	t.Run("creates missing destination directory", func(t *testing.T) {
		_ = setupInstallCNIBinaries(t)
		cniDir := filepath.Join(t.TempDir(), "does", "not", "exist", "yet")

		cmd := newInstallCNIBinariesCmd()
		require.NoError(t, cmd.Flags().Set("cni-dir", cniDir))

		require.NoError(t, runInstallCNIBinaries(cmd))
		require.Equal(t, testCiliumContent, readPluginOrFatal(t, cniDir, "cilium-cni"))
	})
}

func readPluginOrFatal(t *testing.T, cniDir, name string) string {
	t.Helper()
	content, ok := readPlugin(t, cniDir, name)
	require.True(t, ok, "%s was not installed in %s", name, cniDir)
	return content
}
