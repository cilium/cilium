// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/cilium/cilium/etcd-init/cmd/completion"
	i "github.com/cilium/cilium/etcd-init/cmd/init"
	"github.com/cilium/cilium/etcd-init/cmd/version"
	"github.com/cilium/cilium/pkg/logging"
	v "github.com/cilium/cilium/pkg/version"
)

func New() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:          "etcd-init",
		Short:        "etcd Init is a tool to initialise a etcd install.",
		Long:         "etcd Init is a tool to initialise an etcd install. It does not require etcd to be running, as it configures an internal etcd library to setup the files on disk.",
		SilenceUsage: true,
		Version:      v.GetCiliumVersion().Version,
	}
	vp := newViper()
	flags := rootCmd.PersistentFlags()
	flags.BoolP("debug", "D", false, "Enable debug messages")
	vp.BindPFlags(flags)

	// We need to check for the debug environment variable or CLI flag before
	// loading the configuration file since on configuration file read failure
	// we will emit a debug log entry.
	if vp.GetBool("debug") {
		logging.SetLogLevelToDebug()
	}

	rootCmd.AddCommand(
		completion.New(),
		i.New(vp),
		version.New(),
	)
	rootCmd.SetVersionTemplate("{{with .Name}}{{printf \"%s \" .}}{{end}}{{printf \"v%s\" .Version}}\n")
	return rootCmd
}

func newViper() *viper.Viper {
	vp := viper.New()
	vp.SetEnvPrefix("etcd_init")
	vp.AutomaticEnv()
	return vp
}
