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
	"github.com/cilium/cilium/pkg/option"
	v "github.com/cilium/cilium/pkg/version"
)

// configFilePath defines where the hubble-relay config file should be found.
const configFilePath = "/etc/hubble-relay/config.yaml"

// Log option keys for reading from config file.
const (
	keyLogFormat = "log-format"
	keyLogLevel  = "log-level"
)

// New creates a new hubble-relay command.
func New() *cobra.Command {
	vp := newViper()

	rootCmd := &cobra.Command{
		Use:          "hubble-relay",
		Short:        "Hubble Relay is a proxy server for the hubble API",
		Long:         "Hubble Relay is a proxy server for the hubble API.",
		SilenceUsage: true,
		Version:      v.GetCiliumVersion().Version,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Build log options from config file values
			logOpts := make(map[string]string)
			if format := vp.GetString(keyLogFormat); format != "" {
				logOpts[logging.FormatOpt] = format
			}
			if level := vp.GetString(keyLogLevel); level != "" {
				logOpts[logging.LevelOpt] = level
			}
			if err := logging.SetupLogging(nil, logOpts, "hubble-relay", vp.GetBool(option.DebugArg)); err != nil {
				// slogloggercheck: log fatal errors using the default logger before it's initialized.
				logging.Fatal(logging.DefaultSlogLogger, "Unable to set up logging", logfields.Error, err)
			}
			return nil
		},
	}

	flags := rootCmd.PersistentFlags()
	flags.BoolP("debug", "D", false, "Enable debug messages")
	vp.BindPFlags(flags)

	if err := vp.ReadInConfig(); err != nil {
		// slogloggercheck: log debug errors using the default logger before it's initialized.
		logging.DefaultSlogLogger.Debug("Failed to read config from file",
			logfields.Error, err,
			logfields.Path, configFilePath,
		)
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
