package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	rootCmd = &cobra.Command{
		Use:                "cilium-agent",
		Short:              "Run the cilium agent",
		Run:                runApp,
		DisableFlagParsing: true, // Flags are parsed by option.Module.
	}

	cmdrefCmd = &cobra.Command{
		Use:   "cmdref [output directory]",
		Short: "Generate command reference for cilium-agent to given output directory",
		Args:  cobra.ExactArgs(1),
		RunE:  runCmdref,
	}

	dumpDotGraphCmd = &cobra.Command{
		Use:   "dump-dot-graph",
		Short: "Output the internal dependencies of cilium-agent in graphviz dot format to stdout",
		Run:   runDumpDotGraph,
	}

	dumpObjectsCmd = &cobra.Command{
		Use:   "dump-objects",
		Short: "Print the objects available in the application dependency graph",
		Run:   runDumpObjects,
	}
)

func init() {
	viper.SetEnvPrefix("cilium")
	registerBootstrapMetrics()
	rootCmd.InitDefaultHelpFlag()
	initializeFlags()
	initApp()
}

func Execute() error {
	rootCmd.AddCommand(
		cmdrefCmd,
		dumpDotGraphCmd,
		dumpObjectsCmd,
	)

	return rootCmd.Execute()
}
