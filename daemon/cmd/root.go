// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/version"
)

func NewAgentCmd(h *hive.Hive) *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "cilium-agent",
		Short: "Run the cilium agent",
		Run: func(cobraCmd *cobra.Command, args []string) {
			bootstrapStats.overall.Start()

			if v, _ := cobraCmd.Flags().GetBool("version"); v {
				fmt.Printf("%s %s\n", cobraCmd.Name(), version.Version)
				os.Exit(0)
			}

			// Initialize working directories and validate the configuration.
			initEnv(h.Viper())

			// Validate the daemon-specific global options.
			if err := option.Config.Validate(h.Viper()); err != nil {
				log.Fatalf("invalid daemon configuration: %s", err)
			}

			if err := h.Run(); err != nil {
				log.Fatal(err)
			}
		},
	}

	setupSleepBeforeFatal(rootCmd)

	h.RegisterFlags(rootCmd.Flags())

	cmdrefCmd := &cobra.Command{
		Use:    "cmdref [output directory]",
		Short:  "Generate command reference for cilium-agent to given output directory",
		Args:   cobra.ExactArgs(1),
		Hidden: true,
		Run: func(cmd *cobra.Command, args []string) {
			genMarkdown(rootCmd, args[0])
		},
	}
	rootCmd.AddCommand(
		cmdrefCmd,
		h.Command(),
	)

	InitGlobalFlags(rootCmd, h.Viper())

	cobra.OnInitialize(
		option.InitConfig(rootCmd, "cilium-agent", "cilium", h.Viper()),

		// Populate the config and initialize the logger early as these
		// are shared by all commands.
		func() {
			initDaemonConfig(h.Viper())
		},
		initLogging,
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
	logrus.RegisterExitHandler(func() {
		time.Sleep(fatalSleep)
	})
}
