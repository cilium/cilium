// Copyright 2021 Authors of Cilium
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
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// The following variables are set at compile time via LDFLAGS.
var (
	// Version is the software version.
	Version string
	// GitBranch is the name of the git branch HEAD points to.
	GitBranch string
	// GitHash is the git checksum of the most recent commit in HEAD.
	GitHash string
)

func newCmdVersion() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Display detailed version information",
		Long:  `Displays information about the version of this software.`,
		Run: func(cmd *cobra.Command, _ []string) {
			var gitInfo string
			switch {
			case GitBranch != "" && GitHash != "":
				gitInfo = fmt.Sprintf("@%s-%s", GitBranch, GitHash)
			case GitHash != "":
				gitInfo = fmt.Sprintf("@%s", GitHash)
			}
			// TODO: add support for reporting the Cilium version
			fmt.Printf("cilium-cli: v%s%s compiled with %v on %v/%v\n", Version, gitInfo, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		},
	}
}
