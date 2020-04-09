// Copyright 2020 Authors of Hubble
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

package version

import (
	"fmt"
	"runtime"

	"github.com/cilium/hubble/pkg"

	"github.com/spf13/cobra"
)

// New version command.
func New() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Display detailed version information",
		Long:  `Displays information about the version of this software.`,
		Run: func(cmd *cobra.Command, _ []string) {
			var gitInfo string
			switch {
			case pkg.GitBranch != "" && pkg.GitHash != "":
				gitInfo = fmt.Sprintf("@%s-%s", pkg.GitBranch, pkg.GitHash)
			case pkg.GitHash != "":
				gitInfo = fmt.Sprintf("@%s", pkg.GitHash)
			}
			fmt.Printf("%s v%s%s compiled with %v on %v/%v\n", cmd.Root().Name(), pkg.Version, gitInfo, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		},
	}
}
