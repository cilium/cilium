// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"github.com/cilium/cilium/hubble-relay/cmd/completion"
	"github.com/cilium/cilium/hubble-relay/cmd/serve"
	"github.com/cilium/cilium/hubble-relay/cmd/version"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	v "github.com/cilium/cilium/pkg/version"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// configFilePath defines where the hubble-relay config file should be found.
const configFilePath = "/etc/hubble-relay/config.yaml"

// New creates a new hubble-relay command.
func New() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:          "hubble-relay",
		Short:        "hubble-relay is a proxy server for the hubble API",
		Long:         "hubble-relay is a proxy server for the hubble API.",
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
		logging.SetLogLevel(logrus.DebugLevel)
	}
	if err := vp.ReadInConfig(); err != nil {
		logger.WithError(err).Debugf("Failed to read config from file '%s'", configFilePath)
	}
	// Check for the debug flag again now that the configuration file may has
	// been loaded, as it might have changed.
	if vp.GetBool("debug") {
		logging.SetLogLevel(logrus.DebugLevel)
	} else {
		logging.SetLogLevel(logrus.InfoLevel)
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
