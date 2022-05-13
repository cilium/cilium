// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/fx"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/version"
)

// AgentModules is the collection of modules that make up the cilium-agent.
//
// Separated from initApp() to provide the set of agent modules without
// infrastructure modules (logger, configuration, etc.) for embedding and
// testing purposes.
func AgentModules() fx.Option {
	return fx.Options(
		GopsModule(),
	)
}

var (
	agentDotGraph fx.DotGraph
	agentApp      *fx.App
)

// initApp constructs the cilium-agent application.
func initApp() {
	agentApp = fx.New(
		fx.WithLogger(newAppLogger),
		fx.Populate(&agentDotGraph),

		// Register start and stop hooks for the unmodularized legacy part of the cilium-agent.
		fx.Invoke(registerDaemonHooks),

		// The option module provides a modular configuration system for the agent.
		fx.Supply(rootCmd.Flags(), option.CommandLineArguments(os.Args)),
		option.Module(),

		AgentModules(),
	)
	if err := agentApp.Err(); err != nil {
		log.WithError(err).Fatal("Failed to initialize agent application")
	}
}

func runApp(cmd *cobra.Command, args []string) {
	if v, _ := cmd.Flags().GetBool("version"); v {
		fmt.Printf("%s %s\n", cmd.Name(), version.Version)
		os.Exit(0)
	}

	bootstrapStats.overall.Start()
	agentApp.Run()
}

func runDumpDotGraph(cmd *cobra.Command, args []string) {
	fmt.Print(agentDotGraph)
	os.Exit(0)
}
