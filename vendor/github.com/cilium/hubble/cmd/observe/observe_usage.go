// Copyright 2019 Authors of Hubble
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

package observe

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type flagsSection struct {
	name  string   // short one-liner to describe the section
	desc  string   // optional paragraph to preface and deeper explain a section
	flags []string // names of flags to include in the section
}

// customObserverHelp is a function which modifies the usage template
// **specifically** for the `hubble observe` command by providing separation of
// sections for the `Flags:`.
func customObserverHelp(observerCmd *cobra.Command) {
	origTpl := observerCmd.UsageTemplate()
	observerCmd.SetUsageTemplate(modifyTemplate(origTpl, observerCmd))
}

func modifyTemplate(orig string, cmd *cobra.Command) string {
	// prepare to take out the `Flags:` section completely
	fi := strings.Index(orig, "Flags:")
	gfi := strings.Index(orig, "Global Flags:")

	sections := []flagsSection{
		{
			name: "Selectors (retrieve data from hubble)",
			flags: []string{
				"last", "since", "until", "follow",
			},
		},
		{
			name: "Filters (limit result set, not all are compatible with each other)",
			flags: []string{
				"not",
				"ip", "to-ip", "from-ip",
				"pod", "to-pod", "from-pod",
				"fqdn", "to-fqdn", "from-fqdn",
				"label", "to-label", "from-label",
				"namespace", "to-namespace", "from-namespace",
				"service", "to-service", "from-service",
				"port", "to-port", "from-port",
				"type", "verdict", "http-status", "protocol",
				"identity", "to-identity", "from-identity",
			},
		},
	}

	var b bytes.Buffer
	var seen []string // what flags have already been processed

	// go through all sections defined in the config in order
	for _, s := range sections {
		fmt.Fprintf(&b, "%s:\n", s.name)
		if s.desc != "" {
			fmt.Fprintf(&b, "\n%s\n\n", s.desc)
		}

		fs := &pflag.FlagSet{SortFlags: true}
		for _, f := range s.flags {
			// extract the actual command flag by name and add to the set
			flag := cmd.Flags().Lookup(f)
			if flag == nil {
				continue
			}
			fs.AddFlag(flag)
			seen = append(seen, f)
		}

		// print the usages in the section
		fmt.Fprintln(&b, fs.FlagUsages())
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
		fmt.Fprintln(&b, "Other Flags:")
		fmt.Fprintln(&b, rest.FlagUsages())
	}

	return orig[:fi] + b.String() + orig[gfi:]
}
