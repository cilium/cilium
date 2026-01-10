// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package shell

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"runtime"
	"sync"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/hive/script"
)

func ServerCell(defaultSocketPath string) cell.Cell {
	return cell.Module(
		"shell",
		"Hive debug shell",

		cell.Config(Config{ShellSockPath: defaultSocketPath}),
		cell.Invoke(registerShell),
	)
}

// defaultCmdsToInclude specify which default script commands to include.
// Most of them are for testing, so no need to clutter the shell
// with them.
var defaultCmdsToInclude = []string{
	"cat", "exec", "help",
}

func registerShell(in hive.ScriptCmds, log *slog.Logger, lc cell.Lifecycle, jobs job.Registry, health cell.Health, c Config) {
	jg := jobs.NewGroup(health, lc)

	if c.ShellSockPath == "" {
		log.Info("Shell socket path not set, not starting shell server")
		return
	}

	cmds := in.Map()
	defCmds := script.DefaultCmds()
	for _, name := range defaultCmdsToInclude {
		cmds[name] = defCmds[name]
	}
	e := script.Engine{
		Cmds:  cmds,
		Conds: nil,
	}
	jg.Add(job.OneShot("listener", shell{jg, log, &e, c}.listener))
}

type shell struct {
	jg     job.Group
	log    *slog.Logger
	engine *script.Engine
	config Config
}

func (sh shell) listener(ctx context.Context, health cell.Health) error {
	// Remove any old UNIX sock file from previous runs.
	os.Remove(sh.config.ShellSockPath)

	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "unix", sh.config.ShellSockPath)
	if err != nil {
		return fmt.Errorf("failed to listen on %q: %w", sh.config.ShellSockPath, err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		<-ctx.Done()
		l.Close()
		wg.Done()
	}()
	defer wg.Wait()

	health.OK(fmt.Sprintf("Listening on %s", sh.config.ShellSockPath))
	sh.log.Info("Shell listening", "socket", sh.config.ShellSockPath)
	connCount := 0
	for ctx.Err() == nil {
		conn, err := l.Accept()
		if err != nil {
			// If context is cancelled, the listener was closed gracefully
			if errors.Is(ctx.Err(), context.Canceled) {
				return nil
			}
			return fmt.Errorf("accept failed: %w", err)
		}
		connID := connCount
		connCount++

		sh.jg.Add(job.OneShot(
			fmt.Sprintf("shell-%d", connID),
			func(ctx context.Context, h cell.Health) error {
				sh.handleConn(ctx, connID, conn)
				h.Close() // remove from health list
				return nil
			}))
	}
	return nil
}

func (sh shell) handleConn(ctx context.Context, clientID int, conn net.Conn) {
	sh.log.Debug("Client connected", "id", clientID)
	defer sh.log.Debug("client disconnected", "id", clientID)

	ctx, cancel := context.WithCancel(ctx)

	// Wait for context cancellation in the background and close
	// the connection if that happens. This allows teardown on
	// errors or when parent context cancels.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		<-ctx.Done()
		conn.Close()
		wg.Done()
	}()
	defer wg.Wait()
	defer cancel()

	// Catch panics to make sure the script commands can't bring the runtime down.
	defer func() {
		if err := recover(); err != nil {
			// Log the panic and also write it to client. We keep processing
			// more commands after this.
			stack := make([]byte, 1024)
			stack = stack[:runtime.Stack(stack, false)]
			sh.log.Error("Panic in the shell handler",
				"error", err,
				"stacktrace", stack,
			)
			fmt.Fprintf(conn, "PANIC: %s\n%s\n%s\n", err, stack, endMarker)
		}
	}()

	s, err := script.NewState(ctx, "/tmp", nil)
	if err != nil {
		sh.log.Error("NewState", "error", err)
		return
	}

	bio := bufio.NewReader(conn)

	// Wrap the connection into a writer that cancels the context we use to execute
	// commands. This allows interrupting the command without having to have the commands
	// handle write errors.
	writer := interceptingWriter{
		conn: conn,
		onError: func(error) {
			cancel()
		},
	}

	for {
		bline, _, err := bio.ReadLine()
		if err != nil {
			break
		}
		line := string(bline)
		switch line {
		case "stop", "exit", "quit":
			return
		}
		err = sh.engine.ExecuteLine(s, line, writer)
		if err != nil {
			// Send the error and the error marker
			_, err = fmt.Fprintf(writer, "%s%s\n", err, errorMarker)
			if err != nil {
				break
			}
		} else {
			// Send the "end of command output" marker
			_, err = fmt.Fprintln(writer, endMarker)
			if err != nil {
				break
			}
		}
	}
}

type interceptingWriter struct {
	conn    net.Conn
	onError func(error)
}

func (iw interceptingWriter) Write(buf []byte) (int, error) {
	n, err := iw.conn.Write(buf)
	if err != nil {
		iw.onError(err)
	}
	return n, err
}
