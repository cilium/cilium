// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"fmt"
	"io"
	"os"

	"github.com/cilium/hive/shell"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/version"
)

var (
	CiliumShellCmd = shell.ShellCmd(
		defaults.ShellSockPath,
		shellPrompt(),
		shellGreeting,
	)

	DefaultShellConfig = shell.Config{
		ShellSockPath: defaults.ShellSockPath,
	}
)

func shellPrompt() string {
	name, err := os.Hostname()
	if err == nil {
		return name + "> "
	}
	return "cilium> "
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
	fmt.Fprint(w, Green+" /¯¯"+Red+"\\__/"+Magenta+"¯¯\\"+Reset+"  Welcome to the Cilium Shell! Type 'help' for list of commands.\n")
	fmt.Fprint(w, Green+" \\__"+Blue+"/¯¯\\"+Magenta+"__/"+Reset+"\n")
	fmt.Fprint(w, Blue+Blue+Blue+"    \\__/"+Reset+"\n")
	fmt.Fprint(w, "\n")
}
