// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Environment variables honored by the cni-uninstall.sh script that this
// command replaces. An explicitly provided flag always takes precedence.
const (
	cniUninstallEnvHostPrefix     = "HOST_PREFIX"
	cniUninstallDefaultHostPrefix = "/host"
	cniUninstallEnvCNIConfDir     = "CNI_CONF_DIR"
	cniUninstallEnvCustomCNIConf  = "CILIUM_CUSTOM_CNI_CONF"
)

var cniUninstallCmd = newCniUninstallCmd()

func newCniUninstallCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cni-uninstall",
		Short: "Remove the active Cilium CNI configurations from the host",
		Long: `Remove the active Cilium CNI configuration files from the CNI
configuration directory on the host, so that no Pods are scheduled on the
node while the Cilium agent is down.

This is intended to be run from the preStop hook of the cilium-agent
DaemonSet (which is only rendered when the cni.uninstall option is
enabled), in order to remove the CNI configuration before the agent
stops.

The removal is skipped entirely when the CNI configuration is managed
externally (custom-cni-conf). Configs belonging to other CNI
implementations have already been renamed to *.cilium_bak during agent
startup.`,
		Run: func(cmd *cobra.Command, args []string) {
			common.RequireRootPrivilege("cni-uninstall")
			if err := runCniUninstall(cmd); err != nil {
				Fatalf("uninstalling CNI configuration: %s", err)
			}
		},
	}

	cmd.Flags().StringVar(&cniUninstallConfDir, "cni-conf-dir", "",
		"CNI configuration directory on the host (default: $CNI_CONF_DIR or $HOST_PREFIX/etc/cni/net.d, where HOST_PREFIX defaults to /host)")
	cmd.Flags().BoolVar(&cniUninstallCustomConf, "custom-cni-conf", false,
		"Skip removal when the CNI configuration is managed externally (default: $CILIUM_CUSTOM_CNI_CONF or false)")

	return cmd
}

var (
	cniUninstallConfDir    string
	cniUninstallCustomConf bool
)

func init() {
	RootCmd.AddCommand(cniUninstallCmd)
}

func runCniUninstall(cmd *cobra.Command) error {
	confDir := cniUninstallConfDir
	if !cmd.Flags().Changed("cni-conf-dir") {
		confDir = cniUninstallConfDirFromEnv()
	}

	customConf := cniUninstallCustomConf
	if !cmd.Flags().Changed("custom-cni-conf") {
		if val := os.Getenv(cniUninstallEnvCustomCNIConf); val != "" {
			customConf = val == "true"
		}
	}

	// Do not interact with the host's CNI directory when the user
	// specified they are managing CNI configs externally.
	if customConf {
		log.Info("CNI configuration is managed externally, not removing CNI configuration")
		return nil
	}

	return removeCiliumCNIConfigs(confDir)
}

// cniUninstallConfDirFromEnv resolves the CNI configuration directory from
// the CNI_CONF_DIR and HOST_PREFIX environment variables, mirroring
// cni-uninstall.sh.
func cniUninstallConfDirFromEnv() string {
	if dir := os.Getenv(cniUninstallEnvCNIConfDir); dir != "" {
		return dir
	}
	hostPrefix := os.Getenv(cniUninstallEnvHostPrefix)
	if hostPrefix == "" {
		hostPrefix = cniUninstallDefaultHostPrefix
	}
	return filepath.Join(hostPrefix, "etc", "cni", "net.d")
}

// removeCiliumCNIConfigs removes the active Cilium CNI configuration files
// from confDir. As in cni-uninstall.sh, only regular files in the top level
// of the directory whose name contains "cilium" and that end in .conf or
// .conflist are removed: those are the files read by the kubelet's CNI
// implementation.
func removeCiliumCNIConfigs(confDir string) error {
	entries, err := os.ReadDir(confDir)
	if err != nil {
		return fmt.Errorf("reading CNI configuration directory %s: %w", confDir, err)
	}

	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		name := entry.Name()
		if !strings.Contains(name, "cilium") ||
			(!strings.HasSuffix(name, ".conf") && !strings.HasSuffix(name, ".conflist")) {
			continue
		}

		path := filepath.Join(confDir, name)
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("removing %s: %w", path, err)
		}
		log.Info("Removed CNI configuration", logfields.Path, path)
	}
	return nil
}
