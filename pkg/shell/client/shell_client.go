// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package shell

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"

	"github.com/cilium/hive/script"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/version"
)

var ShellCmd = &cobra.Command{
	Use:   "shell [command] [args]...",
	Short: "Connect to the Cilium shell",
	Run:   executeShell,
}

var stdReadWriter = struct {
	io.Reader
	io.Writer
}{
	Reader: os.Stdin,
	Writer: os.Stdout,
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
		// Dialing failed. Server might not be fully up yet. Wait a bit and retry.
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("dialing timed out: %w", err)
		case <-time.After(time.Second):
			fmt.Fprintf(w, "Dialing failed: %s. Retrying...\n", err)
		}
	}
	return conn, nil
}

func ShellExchange(w io.Writer, format string, args ...any) error {
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
		lineBytes, isPrefix, err := bio.ReadLine()
		if err != nil {
			return nil
		}
		line := string(lineBytes)
		if line == "[stdout]" || line == "[stderr]" {
			// Commands that write to "stdout" instead of the log show the [stdout] as
			// the first line. This is useful information in tests, but not useful in
			// the shell, so just skip this.
			continue
		}
		line, ended := strings.CutSuffix(line, endMarker)
		if isPrefix {
			// Partial line, don't print \n yet.
			_, err = fmt.Fprint(w, line)
		} else {
			_, err = fmt.Fprintln(w, line)
		}
		if err != nil {
			return err
		}
		if ended {
			return nil
		}
	}
}

func executeShell(_ *cobra.Command, args []string) {
	if len(args) > 0 {
		err := ShellExchange(os.Stdout, "%s", strings.Join(args, " "))
		if err != nil {
			fmt.Fprintf(os.Stdout, "error: %s\n", err)
		}
	} else {
		interactiveShell()
	}
}

var endMarker = "<<end>>"

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

	// Use the node's name as the prompt.
	hostName, err := os.Hostname()
	if err != nil {
		hostName = "cilium"
	}

	console := term.NewTerminal(stdReadWriter, hostName+"> ")
	if width, height, err := term.GetSize(0); err == nil {
		console.SetSize(width, height)
	}
	printShellGreeting(console)

	for {
		// Try to dial the shell.sock. Since it takes a moment for the server to come up and this
		// is meant for interactive use we'll try to be helpful and retry the dialing until
		// server comes up.
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

		// Read commands from the console and send them to the server for execution.
		// Stop on errors reading from the connection and redial. This allows interrupting
		// long running commands with ctrl-c.
		closed := false
		for !closed {
			line, err := console.ReadLine()
			if err != nil {
				close(stop)
				return
			}

			// Send the command to the server.
			if _, err = fmt.Fprintln(conn, line); err != nil {
				close(stop)
				return
			}

			// Pipe the response to the console until a line ends with the end
			// marker (<<end>>).
			for {
				lineBytes, isPrefix, err := bio.ReadLine()
				if err != nil {
					// Connection closed!
					closed = true
					break
				}
				line := string(lineBytes)

				if line == "[stdout]" || line == "[stderr]" {
					// Commands that write to "stdout" instead of the log show the [stdout] as
					// the first line. This is useful information in tests, but not useful in
					// the shell, so just skip this.
					continue
				}

				line, ended := strings.CutSuffix(line, endMarker)
				if isPrefix {
					fmt.Fprint(console, line)
				} else {
					fmt.Fprintln(console, line)
				}
				if ended {
					break
				}
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
