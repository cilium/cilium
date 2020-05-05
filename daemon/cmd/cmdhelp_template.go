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
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/cilium/pkg/option"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Reset the help function to also exit, as we block elsewhere in interrupts
// and would not exit when called with -h.
func ResetHelpandExit(appCmd *cobra.Command) {
	oldHelpFunc := appCmd.HelpFunc()
	appCmd.SetHelpFunc(func(c *cobra.Command, a []string) {
		oldHelpFunc(c, a)
		os.Exit(0)
	})
}

// CustomCommandHelp is a function which sets the Usage Template for any
// command by providing separation of sections for the 'Flags:'.
func CustomCommandHelpFormat(appCmd *cobra.Command, customtemplate []option.FlagsSection) {
	origTemplate := appCmd.UsageTemplate()
	appCmd.SetUsageTemplate(CustomCommandHelpTemplate(origTemplate, appCmd, customtemplate))
}

// CommandCustomHelpTemplate provides a custom Help template for any command
func CustomCommandHelpTemplate(orig string, cmd *cobra.Command, sections []option.FlagsSection) string {
	fi := strings.Index(orig, "Flags:")
	gfi := strings.Index(orig, "Global Flags:")

	var b bytes.Buffer
	var seen []string // what flags have already been processed

	// go through all sections defined in the config in order
	for _, s := range sections {
		fmt.Fprintf(&b, "%s:\n", s.Name)
		if s.Desc != "" {
			fmt.Fprintf(&b, "\n%s\n\n", s.Desc)
		}

		fs := &pflag.FlagSet{SortFlags: true}
		for _, f := range s.Flags {
			// extract the actual command flag by name and add to the set
			flag := cmd.Flags().Lookup(f)
			if flag == nil {
				continue
			}
			fs.AddFlag(flag)
			seen = append(seen, f)
		}

		// print the usages in the section
		fmt.Fprintln(&b, fs.FlagUsagesWrapped(120))
	}

	haveSeen := func(f string) bool {
		for _, s := range seen {
			if s == f {
				return true
			}
		}
		return false
	}

	// go through the rest of the flags and include them down at the bottom
	rest := &pflag.FlagSet{SortFlags: true}
	cmd.LocalFlags().VisitAll(func(f *pflag.Flag) {
		if haveSeen(f.Name) {
			return // ignore seen flags
		}
		rest.AddFlag(f)
	})
	if rest.HasFlags() {
		fmt.Fprintln(&b, "Other common flags:")
		fmt.Fprintln(&b, rest.FlagUsagesWrapped(120))
	}

	return orig[:fi] + b.String() + orig[gfi:]
}
