// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package cmd

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	"github.com/cilium/cilium/hubble/cmd/common/config"
	"github.com/cilium/cilium/hubble/cmd/common/conn"
	"github.com/cilium/cilium/hubble/cmd/common/template"
	"github.com/cilium/cilium/hubble/cmd/common/validate"
	cmdConfig "github.com/cilium/cilium/hubble/cmd/config"
	"github.com/cilium/cilium/hubble/cmd/list"
	"github.com/cilium/cilium/hubble/cmd/observe"
	"github.com/cilium/cilium/hubble/cmd/record"
	"github.com/cilium/cilium/hubble/cmd/reflect"
	"github.com/cilium/cilium/hubble/cmd/status"
	"github.com/cilium/cilium/hubble/cmd/version"
	"github.com/cilium/cilium/hubble/cmd/watch"
	"github.com/cilium/cilium/hubble/pkg"
	"github.com/cilium/cilium/hubble/pkg/logger"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// New create a new root command.
func New() *cobra.Command {
	return NewWithViper(config.NewViper())
}

// NewWithViper creates a new root command with the given viper.
func NewWithViper(vp *viper.Viper) *cobra.Command {
	// Initialize must be called after the sub-commands are all added
	defer template.Initialize()

	rootCmd := &cobra.Command{
		Use:           "hubble",
		Short:         "CLI",
		Long:          `Hubble is a utility to observe and inspect recent Cilium routed traffic in a cluster.`,
		SilenceErrors: true, // this is being handled in main, no need to duplicate error messages
		SilenceUsage:  true,
		Version:       pkg.Version,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if err := validate.Flags(cmd, vp); err != nil {
				return err
			}
			return conn.Init(vp)
		},
	}

	cobra.OnInitialize(func() {
		if cfg := vp.GetString(config.KeyConfig); cfg != "" { // enable ability to specify config file via flag
			vp.SetConfigFile(cfg)
		}
		// if a config file is found, read it in.
		err := vp.ReadInConfig()
		// initialize the logger after all the config parameters get loaded to viper.
		logger.Initialize(newLogHandler(vp))
		if err == nil {
			logger.Logger.Debug("Using config file", logfields.ConfigFile, vp.ConfigFileUsed())
		}

		username := vp.GetString(config.KeyBasicAuthUsername)
		password := vp.GetString(config.KeyBasicAuthPassword)
		if username != "" && password != "" {
			optFunc := func(*viper.Viper) (grpc.DialOption, error) {
				return conn.WithBasicAuth(username, password), nil
			}
			conn.GRPCOptionFuncs = append(conn.GRPCOptionFuncs, optFunc)
		}
	})

	flags := rootCmd.PersistentFlags()
	// config.GlobalFlags can be used with any command
	flags.AddFlagSet(config.GlobalFlags)
	// config.ServerFlags is added to the root command's persistent flags
	// so that "hubble --server foo observe" still works
	flags.AddFlagSet(config.ServerFlags)
	vp.BindPFlags(flags)

	// config.ServerFlags is only useful to a subset of commands so do not
	// add it by default in the help template
	// config.GlobalFlags is always added to the help template as it's global
	// to all commands
	template.RegisterFlagSets(rootCmd)
	rootCmd.SetUsageTemplate(template.Usage)

	rootCmd.SetErr(os.Stderr)
	rootCmd.SetVersionTemplate("{{with .Name}}{{printf \"%s \" .}}{{end}}{{printf \"%s\" .Version}}\r\n")

	rootCmd.AddCommand(
		cmdConfig.New(vp),
		list.New(vp),
		observe.New(vp),
		record.New(vp),
		reflect.New(vp),
		status.New(vp),
		version.New(),
		watch.New(vp),
	)

	return rootCmd
}

// Execute creates the root command and executes it.
func Execute() error {
	return New().Execute()
}

func newLogHandler(vp *viper.Viper) slog.Handler {
	level := slog.LevelInfo
	if vp.GetBool(config.KeyDebug) {
		level = slog.LevelDebug
	}
	return slog.NewTextHandler(
		os.Stderr,
		&slog.HandlerOptions{
			Level: level,
		},
	)
}
