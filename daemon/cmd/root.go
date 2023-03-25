// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/version"
)

var (
	RootCmd = &cobra.Command{
		Use:   "cilium-agent",
		Short: "Run the cilium agent",
		Run:   runApp,
	}

	cmdrefCmd = &cobra.Command{
		Use:    "cmdref [output directory]",
		Short:  "Generate command reference for cilium-agent to given output directory",
		Args:   cobra.ExactArgs(1),
		Hidden: true,
		Run: func(cmd *cobra.Command, args []string) {
			genMarkdown(RootCmd, args[0])
		},
	}

	agentHive = hive.New(Agent)
)

func init() {
	setupSleepBeforeFatal()

	Vp = agentHive.Viper()
	agentHive.RegisterFlags(RootCmd.Flags())

	cobra.OnInitialize(
		option.InitConfig(RootCmd, "cilium-agent", "cilium", Vp),

		// Populate the config and initialize the logger early as these
		// are shared by all commands.
		initDaemonConfig,
		initLogging,
	)
	initializeFlags()
}

func runApp(cmd *cobra.Command, args []string) {
	bootstrapStats.overall.Start()

	if v, _ := cmd.Flags().GetBool("version"); v {
		fmt.Printf("%s %s\n", cmd.Name(), version.Version)
		os.Exit(0)
	}

	// Initialize working directories and validate the configuration.
	initEnv()

	if err := agentHive.Run(); err != nil {
		log.Fatal(err)
	}
}

func Execute() error {
	RootCmd.AddCommand(
		cmdrefCmd,
		agentHive.Command(),
	)

	return RootCmd.Execute()
}

func setupSleepBeforeFatal() {
	RootCmd.SetFlagErrorFunc(
		func(_ *cobra.Command, e error) error {
			time.Sleep(fatalSleep)
			return e
		})
	logrus.RegisterExitHandler(func() {
		time.Sleep(fatalSleep)
	})
}
