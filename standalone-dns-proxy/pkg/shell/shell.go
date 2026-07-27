// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package shell

import (
	"fmt"
	"io"
	"os"

	"github.com/cilium/hive/shell"

	"github.com/cilium/cilium/pkg/version"
	sdpDefaults "github.com/cilium/cilium/standalone-dns-proxy/pkg/defaults"
)

var (
	// Cmd is the shell command for the standalone DNS proxy
	Cmd = shell.ShellCmd(
		sdpDefaults.ShellSockPath,
		shellPrompt(),
		shellGreeting,
	)

	// DefaultConfig is the shell configuration for the standalone DNS proxy
	DefaultConfig = shell.Config{
		ShellSockPath: sdpDefaults.ShellSockPath,
	}
)

func shellPrompt() string {
	name, err := os.Hostname()
	if err == nil {
		return name + "> "
	}
	return "standalone-dns-proxy> "
}

func shellGreeting(w io.Writer) {
	const (
		Red     = "\033[31m"
		Yellow  = "\033[33m"
		Blue    = "\033[34m"
		Green   = "\033[32m"
		Magenta = "\033[35m"
		Cyan    = "\033[36m"
		Reset   = "\033[0m"
	)
	fmt.Fprint(w, Yellow+"    /¯¯\\\n")
	fmt.Fprint(w, Cyan+" /¯¯"+Yellow+"\\__/"+Green+"¯¯\\"+Reset+"\n")
	fmt.Fprintf(w, Cyan+" \\__"+Red+"/¯¯\\"+Green+"__/"+Reset+"  Cilium %s\n", version.Version)
	fmt.Fprint(w, Green+" /¯¯"+Red+"\\__/"+Magenta+"¯¯\\"+Reset+"  Standalone DNS Proxy Shell. Type 'help' for commands.\n")
	fmt.Fprint(w, Green+" \\__"+Blue+"/¯¯\\"+Magenta+"__/"+Reset+"\n")
	fmt.Fprint(w, Blue+Blue+Blue+"    \\__/"+Reset+"\n")
	fmt.Fprint(w, "\n")
}
