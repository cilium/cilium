// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/cmdref"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/version"
)

func NewAgentCmd(hfn func() *hive.Hive) *cobra.Command {
	bootstrapStats.overall.Start()
	h := hfn()

	rootCmd := &cobra.Command{
		Use:   "cilium-agent",
		Short: "Run the cilium agent",
		Run: func(cobraCmd *cobra.Command, args []string) {
			if v, _ := cobraCmd.Flags().GetBool("version"); v {
				fmt.Printf("%s %s\n", cobraCmd.Name(), version.Version)
				os.Exit(0)
			}

			// Initialize working directories and validate the configuration.
			// slogloggercheck: the logger has been initialized in the cobra.OnInitialize
			initEnv(logging.DefaultSlogLogger, h.Viper())

			// Create a new logger for the daemon after we have initialized the
			// configuration in initEnv().
			// slogloggercheck: the logger has been initialized in the cobra.OnInitialize
			daemonLogger := logging.DefaultSlogLogger.With(logfields.LogSubsys, daemonSubsys)

			// Validate the daemon-specific global options.
			if err := option.Config.Validate(h.Viper()); err != nil {
				logging.Fatal(daemonLogger, fmt.Sprintf("invalid daemon configuration: %s", err))
			}

			// Initialize the daemon configuration and logging with the
			// DefaultSlogLogger without any logfields.
			// slogloggercheck: the logger has been initialized in the cobra.OnInitialize
			if err := h.Run(logging.DefaultSlogLogger, hive.GetOptions(option.Config.HiveConfig)...); err != nil {
				logging.Fatal(daemonLogger, fmt.Sprintf("unable to run agent: %s", err))
			} else {
				// If h.Run() exits with no errors, it means the agent gracefully shut down.
				// (There is a CI job that ensures this is the case)
				daemonLogger.Info("All stop hooks executed successfully.")
			}
		},
	}

	setupSleepBeforeFatal(rootCmd)

	h.RegisterFlags(rootCmd.Flags())

	rootCmd.AddCommand(
		cmdref.NewCmd(rootCmd),
		hive.CiliumShellCmd,
		h.Command(),
	)

	// slogloggercheck: using default logger for initializing global flags
	InitGlobalFlags(logging.DefaultSlogLogger, rootCmd, h.Viper())

	cobra.OnInitialize(
		// slogloggercheck: using default logger for configuration initialization
		option.InitConfig(logging.DefaultSlogLogger, rootCmd, "cilium-agent", "cilium", h.Viper()),

		// Populate the config and initialize the logger early as these
		// are shared by all commands.
		func() {
			initDaemonConfigAndLogging(h.Viper())
		},
	)

	return rootCmd
}

func Execute(cmd *cobra.Command) {
	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func setupSleepBeforeFatal(cmd *cobra.Command) {
	cmd.SetFlagErrorFunc(
		func(_ *cobra.Command, e error) error {
			time.Sleep(fatalSleep)
			return e
		})
	logging.RegisterExitHandler(func() {
		time.Sleep(fatalSleep)
	})
}
