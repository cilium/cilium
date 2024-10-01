// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"io"
	"net"
	"os"

	"github.com/spf13/cobra"
)

var shellCmd = &cobra.Command{
	Use:   "shell",
	Short: "Connect to shell",
	Run:   shell,
}

func init() {
	RootCmd.AddCommand(shellCmd)
}

func shell(cmd *cobra.Command, args []string) {
	conn, err := net.Dial("unix", "/tmp/ciliumshell.sock")
	if err != nil {
		panic(err)
	}
	go io.Copy(conn, os.Stdin)
	io.Copy(os.Stdout, conn)
}
