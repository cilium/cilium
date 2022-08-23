// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"go.uber.org/fx"

	"github.com/cilium/cilium/pkg/gops"
	"github.com/cilium/cilium/pkg/hive"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
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
		Use:   "cmdref [output directory]",
		Short: "Generate command reference for cilium-agent to given output directory",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			genMarkdown(RootCmd, args[0])
		},
	}

	dotGraphCmd = &cobra.Command{
		Use:   "dot-graph",
		Short: "Output the internal dependencies of cilium-agent in graphviz dot format",
		Run:   func(cmd *cobra.Command, args []string) { agentHive.PrintDotGraph() },
	}

	objectsCmd = &cobra.Command{
		Use:   "objects",
		Short: "Print the objects, constructors and lifecycle hooks",
		Run:   func(cmd *cobra.Command, args []string) { agentHive.PrintObjects() },
	}

	agentHive *hive.Hive
)

type DaemonCellConfig struct {
	SkipDaemon bool
}

func (DaemonCellConfig) CellFlags(flags *pflag.FlagSet) {
	flags.Bool("skip-daemon", false, "Skip running of the daemon, only start normal cells")
	flags.MarkHidden("skip-daemon")
}

func init() {
	cobra.OnInitialize(option.InitConfig(RootCmd, "cilium-agent", "cilium", Vp))
	setupSleepBeforeFatal()
	registerBootstrapMetrics()
	initializeFlags()

	flags := pflag.NewFlagSet("hive", pflag.ContinueOnError)
	agentHive = hive.New(
		Vp,
		flags,

		gops.Cell,
		k8sClient.Cell,

		hive.NewCellWithConfig[DaemonCellConfig]("daemon", fx.Invoke(registerDaemonHooks)),
	)
	// Add the flags to commands that use them. Would use PersistentFlags(), but cmdref
	// command should not inherit them.
	RootCmd.Flags().AddFlagSet(flags)
	dotGraphCmd.Flags().AddFlagSet(flags)
	objectsCmd.Flags().AddFlagSet(flags)
}

func runApp(cmd *cobra.Command, args []string) {
	bootstrapStats.overall.Start()

	if v, _ := cmd.Flags().GetBool("version"); v {
		fmt.Printf("%s %s\n", cmd.Name(), version.Version)
		os.Exit(0)
	}

	agentHive.Run()
}

func Execute() error {
	RootCmd.AddCommand(
		cmdrefCmd,
		dotGraphCmd,
		objectsCmd,
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
