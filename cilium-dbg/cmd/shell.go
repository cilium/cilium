// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/cilium/hive/script"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/version"
)

var shellCmd = &cobra.Command{
	Use:   "shell [command] [args]...",
	Short: "Connect to the Cilium shell",
	Run:   shell,
}

var stdReadWriter = struct {
	io.Reader
	io.Writer
}{
	Reader: os.Stdin,
	Writer: os.Stdout,
}

func init() {
	RootCmd.AddCommand(shellCmd)
}

func dialShell(w io.Writer) (net.Conn, error) {
	var conn net.Conn
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for {
		var err error
		var d net.Dialer
		conn, err = d.DialContext(ctx, "unix", defaults.ShellSockPath)
		if err == nil {
			break
		}
		// Dialing failed. Agent might not be fully up yet. Wait a bit and retry.
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("dialing timed out: %w", err)
		case <-time.After(time.Second):
			fmt.Fprintf(w, "Dialing failed: %s. Retrying...\n", err)
		}
	}
	return conn, nil
}

func shellExchange(w io.Writer, format string, args ...any) error {
	conn, err := dialShell(os.Stderr)
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = fmt.Fprintf(conn, format+"\nexit\n", args...)
	if err != nil {
		return err
	}
	bio := bufio.NewReader(conn)
	for {
		line, _, err := bio.ReadLine()
		if err != nil {
			return nil
		}
		switch string(line) {
		case "<<end>>":
			return nil
		case "[stdout]":
		default:
			if _, err := w.Write(line); err != nil {
				return err
			}
			if _, err := w.Write(newline); err != nil {
				return err
			}
		}
	}

}

func shell(_ *cobra.Command, args []string) {
	if len(args) > 0 {
		err := shellExchange(os.Stdout, "%s", strings.Join(args, " "))
		if err != nil {
			fmt.Fprintf(os.Stdout, "error: %s\n", err)
		}
	} else {
		interactiveShell()
	}
}

func interactiveShell() {
	// Try to set the terminal to raw mode (so that cursor keys work etc.)
	restore, err := script.MakeRaw(0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error setting terminal to raw mode: %s\n", err)
	} else {
		defer restore()
	}

	// Listen for SIGINT to break.
	sigs := make(chan os.Signal, 1)
	defer signal.Stop(sigs)
	signal.Notify(sigs, os.Interrupt)

	console := term.NewTerminal(stdReadWriter, "cilium> ")
	printShellGreeting(console)

	for {
		// Try to dial the shell.sock. Since it takes a moment for the agent to come up and this
		// is meant for interactive use we'll try to be helpful and retry the dialing until
		// agent comes up.
		conn, err := dialShell(console)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			os.Exit(1)
		}

		stop := make(chan struct{})

		go func() {
			select {
			case <-stop:
			case <-sigs:
				// On interrupt close the connection.
				conn.Close()
			}
		}()

		bio := bufio.NewReader(conn)

		// Read commands from the console and send them to the agent for execution.
		// Stop on errors reading from the connection and redial. This allows interrupting
		// long running commands with ctrl-c.
		closed := false
		for !closed {
			line, err := console.ReadLine()
			if err != nil {
				close(stop)
				return
			}
			if _, err = fmt.Fprintln(conn, line); err != nil {
				close(stop)
				return
			}

			// Read until the command finishes with <<end>>.
			for {
				line, _, err := bio.ReadLine()
				if err != nil {
					// Connection closed!
					closed = true
					break
				}
				if string(line) == "<<end>>" {
					break
				}
				console.Write(line)
				console.Write(newline)
			}
		}
		close(stop)
	}
}

func printShellGreeting(term *term.Terminal) {
	var (
		Red     = string(term.Escape.Red)
		Yellow  = string(term.Escape.Yellow)
		Blue    = string(term.Escape.Blue)
		Green   = string(term.Escape.Green)
		Magenta = string(term.Escape.Magenta)
		Cyan    = string(term.Escape.Cyan)
		Reset   = string(term.Escape.Reset)
	)
	fmt.Fprint(term, Yellow+"    /¯¯\\\n")
	fmt.Fprint(term, Cyan+" /¯¯"+Yellow+"\\__/"+Green+"¯¯\\"+Reset+"\n")
	fmt.Fprintf(term, Cyan+" \\__"+Red+"/¯¯\\"+Green+"__/"+Reset+"  Cilium %s\n", version.Version)
	fmt.Fprint(term, Green+" /¯¯"+Red+"\\__/"+Magenta+"¯¯\\"+Reset+"  Welcome to the Cilium Shell! Type 'help' for list of commands.\n")
	fmt.Fprint(term, Green+" \\__"+Blue+"/¯¯\\"+Magenta+"__/"+Reset+"\n")
	fmt.Fprint(term, Blue+Blue+Blue+"    \\__/"+Reset+"\n")
	fmt.Fprint(term, "\n")
}
