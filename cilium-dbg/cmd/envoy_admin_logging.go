// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"strings"

	"github.com/spf13/cobra"
)

func init() {
	EnvoyAdminCmd.AddCommand(EnvoyAdminLoggingCmd)
	EnvoyAdminLoggingCmd.AddCommand(EnvoyAdminLoggingListCmd)
	EnvoyAdminLoggingCmd.AddCommand(EnvoyAdminLoggingSetCmd)
	EnvoyAdminLoggingSetCmd.AddCommand(EnvoyAdminLoggingSetGlobalCmd)
	EnvoyAdminLoggingSetCmd.AddCommand(EnvoyAdminLoggingSetLoggersCmd)
}

var EnvoyAdminLoggingCmd = &cobra.Command{
	Use:   "logging",
	Short: "List and change logging levels of Envoy Proxy",
}

var EnvoyAdminLoggingListCmd = &cobra.Command{
	Use:   "list",
	Short: "List logging levels of Envoy Proxy",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		envoyAdminClient := newEnvoyAdminClient()

		loggingLevels, err := envoyAdminClient.ListLoggingLevels()
		if err != nil {
			Fatalf("failed to get logging levels: %s\n", err)
		}
		cmd.Println(loggingLevels)
	},
}

var EnvoyAdminLoggingSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Change logging levels of Envoy Proxy",
}

var EnvoyAdminLoggingSetGlobalCmd = &cobra.Command{
	Use:   "global <level>",
	Short: "Change global logging level for all loggers of Envoy Proxy",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		envoyAdminClient := newEnvoyAdminClient()

		response, err := envoyAdminClient.SetLoggingLevelForAllLoggers(args[0])
		if err != nil {
			Fatalf("failed to set global logging level: %s\n", err)
		}
		cmd.Println(response)
	},
}

var EnvoyAdminLoggingSetLoggersCmd = &cobra.Command{
	Use:   "loggers <logger_name>=<level>...",
	Short: "Change logging level of a list of loggers of Envoy Proxy",
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		envoyAdminClient := newEnvoyAdminClient()

		loggingLevels := map[string]string{}

		for _, arg := range args {
			s := strings.Split(arg, "=")
			if len(s) == 2 {
				loggingLevels[s[0]] = s[1]
			}
		}

		if _, globalKeyExists := loggingLevels["level"]; globalKeyExists {
			Fatalf("please use logger set global to change the global log level\n")
		}

		response, err := envoyAdminClient.SetLoggingLevelForLoggers(loggingLevels)
		if err != nil {
			Fatalf("failed to set logging levels: %s\n", err)
		}
		cmd.Println(response)
	},
}
