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

package version

import (
	"context"
	"fmt"
	"runtime"

	cmdContext "github.com/cilium/cilium/hubble-proxy/cmd/context"
	"github.com/cilium/cilium/pkg/hubble/proxy"

	"github.com/spf13/cobra"
)

// New creates a new version command.
func New(ctx context.Context, cctx *cmdContext.Context) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Display detailed version information",
		Long:  `Displays information about the version of this software.`,
		Run: func(cmd *cobra.Command, _ []string) {
			runVersion(ctx, cctx, cmd)
		},
	}
}

func runVersion(_ context.Context, cctx *cmdContext.Context, cmd *cobra.Command) {
	var gitInfo string
	switch {
	case proxy.GitBranch != "" && proxy.GitHash != "":
		gitInfo = fmt.Sprintf("@%s-%s", proxy.GitBranch, proxy.GitHash)
	case proxy.GitHash != "":
		gitInfo = fmt.Sprintf("@%s", proxy.GitHash)
	}
	fmt.Fprintf(cctx.Stdout, "%s v%s%s compiled with %v on %v/%v\n", cmd.Root().Name(), proxy.Version, gitInfo, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
