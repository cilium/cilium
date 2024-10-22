// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package template

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/hubble/cmd/common/config"
)

var (
	commandFlagSets     = map[*cobra.Command][]*pflag.FlagSet{}
	commandPathFlagSets = map[string][]*pflag.FlagSet{}
)

func init() {
	cobra.AddTemplateFunc("title", strings.Title)
	cobra.AddTemplateFunc("getFlagSets", getFlagSets)
}

// Initialize goes through the registered commands, and their flagsets and
// initializes the help template command registry.
//
// This must be called after all commands are added as sub-commands, because
// cmd.CommandPath relies on the commands having parents.
func Initialize() {
	for cmd, fs := range commandFlagSets {
		commandPathFlagSets[cmd.CommandPath()] = fs
	}
}

// RegisterFlagSets registers flags to be included in a commands usage text (--help).
func RegisterFlagSets(cmd *cobra.Command, flagsets ...*pflag.FlagSet) {
	commandFlagSets[cmd] = append(commandFlagSets[cmd], flagsets...)
}

func getFlagSets(cmd *cobra.Command) []*pflag.FlagSet {
	flagsets, ok := commandPathFlagSets[cmd.CommandPath()]
	if !ok {
		return []*pflag.FlagSet{config.GlobalFlags}
	}
	newFlagSet := make([]*pflag.FlagSet, len(flagsets), len(flagsets)+1)
	copy(newFlagSet, flagsets)
	newFlagSet = append(newFlagSet, config.GlobalFlags)
	return newFlagSet
}

const (
	// Usage is the cobra UsageTemplate for Hubble CLI.
	Usage = `Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}

Available Commands:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}

{{range getFlagSets . }}{{ title .Name}} Flags:
{{ .FlagUsages }}
{{end}}Get help:
  -h, --help	Help for any command or subcommand
{{- if .HasHelpSubCommands}}Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`
)
