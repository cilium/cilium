// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Locations of the CNI plugin binaries inside the agent image.
var (
	ciliumCNIBinaryPath = "/opt/cni/bin/cilium-cni"
	loopbackBinaryPath  = "/cni/loopback"
)

// Environment variables honored by the install-plugin.sh script that this
// command replaces. An explicitly provided flag always takes precedence.
const (
	envHostPrefix        = "HOST_PREFIX"
	defaultHostPrefix    = "/host"
	envCNIPath           = "CNI_DIR"
	envOverwriteCilium   = "OVERWRITE_CILIUM"
	envOverwriteLoopback = "OVERWRITE_LOOPBACK"
)

var installCNIBinariesCmd = newInstallCNIBinariesCmd()

func newInstallCNIBinariesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install-cni-binaries",
		Short: "Install the CNI plugin binaries into the CNI bin directory on the host",
		Long: `Copy the cilium-cni and loopback CNI plugin binaries from the agent image
into the CNI bin directory on the host.

The cilium-cni binary is always installed (or replaced, which is the
default). The loopback binary is only installed if it is not present yet,
unless instructed to overwrite. The loopback binary is provided as a
fallback for installations that do not ship their own, so a failure to
install it is not fatal.

Binaries are written to a temporary name in the destination directory and
renamed into place, so a concurrent reader never observes a partial binary.

The --cni-dir, --overwrite-cilium and --overwrite-loopback flags may be
omitted, in which case the CNI_DIR, HOST_PREFIX, OVERWRITE_CILIUM and
OVERWRITE_LOOPBACK environment variables are honored, as they were by the
install-plugin.sh script this command replaces. An explicitly provided
flag takes precedence over the corresponding environment variable.`,
		Run: func(cmd *cobra.Command, args []string) {
			common.RequireRootPrivilege("install-cni-binaries")
			if err := runInstallCNIBinaries(cmd); err != nil {
				Fatalf("installing CNI binaries: %s", err)
			}
		},
	}

	cmd.Flags().StringVar(&cniBinDir, "cni-dir", "",
		"CNI bin directory on the host (default: $CNI_DIR/bin or $HOST_PREFIX/opt/cni/bin, where HOST_PREFIX defaults to /host)")
	cmd.Flags().BoolVar(&overwriteCilium, "overwrite-cilium", false,
		"Overwrite an existing cilium-cni binary (default: $OVERWRITE_CILIUM or true)")
	cmd.Flags().BoolVar(&overwriteLoopback, "overwrite-loopback", false,
		"Overwrite an existing loopback binary (default: $OVERWRITE_LOOPBACK or false)")

	return cmd
}

var (
	cniBinDir         string
	overwriteCilium   bool
	overwriteLoopback bool
)

func init() {
	RootCmd.AddCommand(installCNIBinariesCmd)
}

func runInstallCNIBinaries(cmd *cobra.Command) error {
	cniDir := cniBinDir
	if !cmd.Flags().Changed("cni-dir") {
		cniDir = cniBinDirFromEnv()
	}

	overwriteCilium := flagOrEnv(cmd, "overwrite-cilium", overwriteCilium, envOverwriteCilium, true)
	overwriteLoopback := flagOrEnv(cmd, "overwrite-loopback", overwriteLoopback, envOverwriteLoopback, false)

	if err := os.MkdirAll(cniDir, 0o755); err != nil {
		return fmt.Errorf("creating CNI bin directory %s: %w", cniDir, err)
	}

	// The loopback driver is a fallback and is usually not required, so do
	// not fail hard if it cannot be installed.
	if overwriteLoopback || !fileExists(filepath.Join(cniDir, "loopback")) {
		if err := installPlugin(loopbackBinaryPath, filepath.Join(cniDir, "loopback")); err != nil {
			log.Warn("Failed to install loopback CNI plugin, continuing without it",
				logfields.Path, loopbackBinaryPath, logfields.Error, err)
		}
	}

	if overwriteCilium || !fileExists(filepath.Join(cniDir, "cilium-cni")) {
		if err := installPlugin(ciliumCNIBinaryPath, filepath.Join(cniDir, "cilium-cni")); err != nil {
			return fmt.Errorf("installing cilium-cni CNI plugin: %w", err)
		}
	}
	return nil
}

// cniBinDirFromEnv resolves the CNI bin directory from the CNI_DIR and
// HOST_PREFIX environment variables, mirroring install-plugin.sh.
func cniBinDirFromEnv() string {
	if dir := os.Getenv(envCNIPath); dir != "" {
		return filepath.Join(dir, "bin")
	}
	hostPrefix := os.Getenv(envHostPrefix)
	if hostPrefix == "" {
		hostPrefix = defaultHostPrefix
	}
	return filepath.Join(hostPrefix, "opt", "cni", "bin")
}

// flagOrEnv returns the flag value if the flag was explicitly provided,
// otherwise the value of the environment variable, or fallback if the
// variable is unset or empty. As in install-plugin.sh, the variable is
// honored only if it is exactly "true".
func flagOrEnv(cmd *cobra.Command, flag string, flagValue bool, envVar string, fallback bool) bool {
	if cmd.Flags().Changed(flag) {
		return flagValue
	}
	if val := os.Getenv(envVar); val != "" {
		return val == "true"
	}
	return fallback
}

// fileExists reports whether name exists and is a regular file.
func fileExists(name string) bool {
	info, err := os.Stat(name)
	return err == nil && info.Mode().IsRegular()
}

// installPlugin copies src to dst atomically: the binary is first written to
// a temporary name in the destination directory and then renamed into place.
func installPlugin(src string, dst string) (err error) {
	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("opening %s: %w", src, err)
	}
	defer srcFile.Close()

	// Use a hidden temporary name so it is not picked up by tools scanning
	// the CNI bin directory for plugins.
	tmpDst := filepath.Join(filepath.Dir(dst), "."+filepath.Base(dst)+".new")
	defer os.Remove(tmpDst) //nolint:errcheck // best effort, dst replaces tmpDst on success
	if err := os.MkdirAll(filepath.Dir(tmpDst), 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(tmpDst), err)
	}
	dstFile, err := os.OpenFile(tmpDst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("creating %s: %w", tmpDst, err)
	}
	if _, err := io.Copy(dstFile, srcFile); err != nil {
		_ = dstFile.Close()
		return fmt.Errorf("copying %s to %s: %w", src, dst, err)
	}
	if err := dstFile.Close(); err != nil {
		return fmt.Errorf("writing %s: %w", tmpDst, err)
	}
	if err := os.Rename(tmpDst, dst); err != nil {
		return fmt.Errorf("renaming %s to %s: %w", tmpDst, dst, err)
	}

	log.Info("Installed CNI plugin", logfields.Path, dst)
	return nil
}
