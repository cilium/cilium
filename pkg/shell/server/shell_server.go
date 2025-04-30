// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package shell

import (
	"bufio"
	"context"
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

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var Cell = cell.Module(
	"shell",
	"Cilium debug shell",
	cell.Invoke(registerShell),
)

// defaultCmdsToInclude specify which default script commands to include.
// Most of them are for testing, so no need to clutter the shell
// with them.
var defaultCmdsToInclude = []string{
	"cat", "exec", "help",
}

func registerShell(in hive.ScriptCmds, log *slog.Logger, jg job.Group) {
	cmds := in.Map()
	defCmds := script.DefaultCmds()
	for _, name := range defaultCmdsToInclude {
		cmds[name] = defCmds[name]
	}
	e := script.Engine{
		Cmds:  cmds,
		Conds: nil,
	}
	jg.Add(job.OneShot("listener", shell{jg, log, &e}.listener))
}

type shell struct {
	jg     job.Group
	log    *slog.Logger
	engine *script.Engine
}

func (sh shell) listener(ctx context.Context, health cell.Health) error {
	// Remove any old UNIX sock file from previous runs.
	os.Remove(defaults.ShellSockPath)

	if _, err := os.Stat(defaults.RuntimePath); os.IsNotExist(err) {
		if err := os.MkdirAll(defaults.RuntimePath, defaults.RuntimePathRights); err != nil {
			return fmt.Errorf("could not create default runtime directory: %w", err)
		}
	}

	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "unix", defaults.ShellSockPath)
	if err != nil {
		return fmt.Errorf("failed to listen on %q: %w", defaults.ShellSockPath, err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		<-ctx.Done()
		l.Close()
		wg.Done()
	}()
	defer wg.Wait()

	health.OK(fmt.Sprintf("Listening on %s", defaults.ShellSockPath))
	connCount := 0
	for ctx.Err() == nil {
		conn, err := l.Accept()
		if err != nil {
			return fmt.Errorf("accept failed: %w", err)
		}
		sh.jg.Add(job.OneShot(
			fmt.Sprintf("shell-%d", connCount),
			func(ctx context.Context, h cell.Health) error {
				sh.handleConn(ctx, conn)
				h.Close() // remove from health list
				sh.log.Info("exited")
				return nil
			}))
		connCount++
	}
	return nil
}

func (sh shell) handleConn(ctx context.Context, conn net.Conn) {
	const endMarker = "<<end>>"
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
			// Log the panic and also write it to cilium-dbg. We keep processing
			// more commands after this.
			stack := make([]byte, 1024)
			stack = stack[:runtime.Stack(stack, false)]
			sh.log.Error("Panic in the shell handler",
				logfields.Error, err,
				logfields.Stacktrace, stack,
			)
			fmt.Fprintf(conn, "PANIC: %s\n%s\n%s\n", err, stack, endMarker)
		}
	}()

	s, err := script.NewState(ctx, "/tmp", nil)
	if err != nil {
		sh.log.Error("NewState", logfields.Error, err)
		return
	}

	bio := bufio.NewReader(conn)
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
		err = sh.engine.ExecuteLine(s, line, conn)
		if err != nil {
			_, err = fmt.Fprintln(conn, err)
			if err != nil {
				break
			}
		}
		// Send the "end of command output" marker
		_, err = fmt.Fprintln(conn, endMarker)
		if err != nil {
			break
		}
	}
}
