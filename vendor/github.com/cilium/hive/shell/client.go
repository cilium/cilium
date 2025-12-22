// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package shell

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cilium/hive/script"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// ShellCmd constructs a cobra command for dialing a shell server.
func ShellCmd(defaultSockPath string, prompt string, printGreeting func(w io.Writer)) *cobra.Command {
	var sockPath *string
	cmd := &cobra.Command{
		Use:   "shell [command] [args]...",
		Short: "Connect to the shell",
		Run: func(cmd *cobra.Command, args []string) {
			cfg := Config{
				ShellSockPath: *sockPath,
			}
			executeShell(cfg, prompt, printGreeting, args)
		},
	}
	sockPath = cmd.Flags().String(ShellSockPathName, defaultSockPath, "Path to the shell UNIX socket")
	return cmd
}

var stdReadWriter = struct {
	io.Reader
	io.Writer
}{
	Reader: os.Stdin,
	Writer: os.Stdout,
}

func dialShell(c Config, sigs <-chan os.Signal, w io.Writer) (net.Conn, error) {
	var conn net.Conn
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for {
		var err error
		var d net.Dialer
		conn, err = d.DialContext(ctx, "unix", c.ShellSockPath)
		if err == nil {
			break
		}
		// Dialing failed. Server might not be fully up yet. Wait a bit and retry.
		select {
		case <-sigs:
			return nil, fmt.Errorf("interrupted")
		case <-ctx.Done():
			return nil, fmt.Errorf("dialing timed out: %w", err)
		case <-time.After(time.Second):
			fmt.Fprintf(w, "Dialing failed: %s. Retrying...\n", err)
		}
	}
	return conn, nil
}

// ShellExchange sends a single command to the shell. Output is written
// to the given writer [w].
func ShellExchange(c Config, w io.Writer, format string, args ...any) error {
	conn, err := dialShell(c, nil, os.Stderr)
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
		if line == stdoutMarker || line == stderrMarker {
			// Commands that write to "stdout" instead of the log show the [stdout] as
			// the first line. This is useful information in tests, but not useful in
			// the shell, so just skip this.
			continue
		}
		line, ended := strings.CutSuffix(line, endMarker)
		line, errored := strings.CutSuffix(line, errorMarker)
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
		if errored {
			return errors.New(line)
		}
	}
}

func executeShell(cfg Config, prompt string, printGreeting func(io.Writer), args []string) {
	if len(args) > 0 {
		err := ShellExchange(cfg, os.Stdout, "%s", strings.Join(args, " "))
		if err != nil {
			fmt.Fprintf(os.Stdout, "error: %s\n", err)
			os.Exit(1)
		}
	} else {
		os.Exit(interactiveShell(cfg, prompt, printGreeting))
	}
}

func interactiveShell(cfg Config, prompt string, printGreeting func(w io.Writer)) int {
	// Try to set the terminal to raw mode (so that cursor keys work etc.)
	restore, err := script.MakeRaw(0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error setting terminal to raw mode: %s\n", err)
	} else {
		defer restore()
	}

	console := term.NewTerminal(stdReadWriter, prompt)
	if width, height, err := term.GetSize(0); err == nil {
		console.SetSize(width, height)
	}
	if printGreeting != nil {
		printGreeting(console)
	}

	// Listen for SIGINT to stop.
	sigs := make(chan os.Signal, 1)
	defer func() {
		signal.Stop(sigs)
		close(sigs)
	}()
	signal.Notify(sigs, os.Interrupt)

	// Try to dial the shell.sock. Since it takes a moment for the server to come up and this
	// is meant for interactive use we'll try to be helpful and retry the dialing until
	// server comes up.
	conn, err := dialShell(cfg, sigs, console)
	if err != nil {
		fmt.Fprintf(console, "Error dialing: %s\n", err)
		return 1
	}

	// Use a boolean to decide whether to redial the connection on error or whether to stop.
	// This allows interrupting a long-running command with Ctrl-C and dropping back to
	// the prompt.
	var redial atomic.Bool

	go func() {
		for range sigs {
			// Ask for a redial and close the connection
			redial.Store(true)
			conn.Close()
		}
	}()

	bio := bufio.NewReader(conn)
	console.AutoCompleteCallback = autocomplete(conn, bio)

	// Read commands from the console and send them to the server for execution.
repl:
	for {
		line, err := console.ReadLine()
		if err != nil {
			break
		}

		// Send the command to the server.
		if _, err = fmt.Fprintln(conn, line); err != nil {
			// Failed to send. See if should try reconnecting or whether we should
			// print the error and stop.
			if redial.Load() {
				redial.Store(false)
				conn, err = dialShell(cfg, sigs, console)
				if err != nil {
					fmt.Fprintf(console, "Error dialing: %s\n", err)
					return 1
				}
				bio = bufio.NewReader(conn)
				console.AutoCompleteCallback = autocomplete(conn, bio)

				// Try again with the new connection.
				if _, err = fmt.Fprintln(conn, line); err != nil {
					fmt.Fprintf(console, "Error sending: %s\n", err)
					break repl
				}
			} else {
				fmt.Fprintf(console, "Error: %s\n", err)
				break repl
			}
		}

		// Pipe the response to the console until a line ends with the
		// [endMarker].
		for {
			lineBytes, isPrefix, err := bio.ReadLine()
			if err != nil {
				if redial.Load() {
					// Redialing requested, drop back to prompt.
					continue repl
				}
				if !errors.Is(err, io.EOF) {
					fmt.Fprintf(console, "Error reading: %s\n", err)
				}
				break repl
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
	conn.Close()
	return 0
}

func autocomplete(conn net.Conn, bio *bufio.Reader) func(line string, pos int, key rune) (newLine string, newPos int, ok bool) {
	var (
		suggestionIndex int
		suggestionPos   int = -1
	)
	return func(line string, pos int, key rune) (string, int, bool) {
		switch key {
		case '\t':
		default:
			suggestionIndex = 0
			suggestionPos = -1

			// Only handle tab completion.
			return line, pos, false
		}

		// If we have not queried the server yet, or the line has changed, we need to
		// query the server for suggestions.
		if suggestionPos == -1 {
			suggestionPos = pos
		}

		if suggestionPos > len(line) {
			suggestionPos = len(line)
		}

		line = line[:suggestionPos]

		// If the line does not contain a space, we are still typing out the initial command.
		if !strings.Contains(line, " ") {
			// Ask server for suggestions of root commands.
			if _, err := fmt.Fprintln(conn, "help -a "+line); err != nil {
				return "", 0, false
			}
		} else {
			cmd, args, _ := strings.Cut(line, " ")
			args = strings.Replace(args, "'", "\\'", -1) // Escape single quotes for the shell.
			// Ask server for suggestions for the specific command.
			if _, err := fmt.Fprintf(conn, "%s --autocomplete='%s'\n", cmd, args); err != nil {
				return "", 0, false
			}
		}

		var suggestions []string
		suggestion := ""
		for {
			lineBytes, isPrefix, err := bio.ReadLine()
			if err != nil {
				// Connection closed!
				return "", 0, false
			}
			line := string(lineBytes)

			if line == "[stdout]" || line == "[stderr]" {
				// Commands that write to "stdout" instead of the log show the [stdout] as
				// the first line. This is useful information in tests, but not useful in
				// the shell, so just skip this.
				continue
			}

			line, ended := strings.CutSuffix(line, endMarker)
			suggestion += line
			if !isPrefix {
				if suggestion != "" {
					suggestions = append(suggestions, suggestion)
				}
				suggestion = ""
			}
			if ended {
				break
			}
		}

		slices.Sort(suggestions)

		if suggestionIndex > len(suggestions)-1 {
			suggestionIndex = 0
		}

		if len(suggestions) == 0 {
			// No suggestions available.
			return line, pos, false
		}

		currentSuggestion := suggestions[suggestionIndex]
		suggestionIndex++
		return currentSuggestion, len(currentSuggestion), true
	}
}
