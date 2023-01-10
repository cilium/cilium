// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/cilium/cilium/hubble-relay/cmd/completion"
	"github.com/cilium/cilium/hubble-relay/cmd/serve"
	"github.com/cilium/cilium/hubble-relay/cmd/version"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	v "github.com/cilium/cilium/pkg/version"
)

// configFilePath defines where the hubble-relay config file should be found.
const configFilePath = "/etc/hubble-relay/config.yaml"

// New creates a new hubble-relay command.
func New() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:          "hubble-relay",
		Short:        "Hubble Relay is a proxy server for the hubble API",
		Long:         "Hubble Relay is a proxy server for the hubble API.",
		SilenceUsage: true,
		Version:      v.GetCiliumVersion().Version,
	}
	logger := logging.DefaultLogger.WithField(logfields.LogSubsys, "hubble-relay")
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

	if err := vp.ReadInConfig(); err != nil {
		logger.WithError(err).Debugf("Failed to read config from file '%s'", configFilePath)
	}

	// Check for the debug flag again now that the configuration file may has
	// been loaded, as it might have changed.
	if vp.GetBool("debug") {
		logging.SetLogLevelToDebug()
	}

	rootCmd.AddCommand(
		completion.New(),
		serve.New(vp),
		version.New(),
	)
	rootCmd.SetVersionTemplate("{{with .Name}}{{printf \"%s \" .}}{{end}}{{printf \"v%s\" .Version}}\n")
	return rootCmd
}

func newViper() *viper.Viper {
	vp := viper.New()
	vp.SetEnvPrefix("relay")
	vp.SetConfigFile(configFilePath)
	vp.AutomaticEnv()
	return vp
}
