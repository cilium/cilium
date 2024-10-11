// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"

	upstreamHive "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/hive/script"

	"github.com/cilium/cilium/pkg/defaults"
)

var shellCell = cell.Module(
	"shell",
	"Cilium debug shell",
	cell.Invoke(registerShell),
)

func registerShell(in upstreamHive.ScriptCmds, log *slog.Logger, jg job.Group) {
	cmds := in.Map()
	for k, cmd := range script.DefaultCmds() {
		cmds[k] = cmd
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
	// Remove any old UNIX sock file from previous agent run.
	os.Remove(defaults.ShellSockPath)

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
			func(ctx context.Context, _ cell.Health) error {
				sh.handleConn(ctx, conn)
				sh.log.Info("exited")
				return nil
			}))
		connCount++
	}
	return nil
}

func (sh shell) handleConn(ctx context.Context, conn net.Conn) {
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

	s, err := script.NewState(ctx, "/tmp", nil)
	if err != nil {
		sh.log.Error("NewState", "error", err)
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
		_, err = fmt.Fprintln(conn, "<<end>>")
		if err != nil {
			break
		}
	}
}
