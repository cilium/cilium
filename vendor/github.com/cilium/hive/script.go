// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"
	"golang.org/x/term"
)

func NewScriptCmd(name string, cmd script.Cmd) ScriptCmdOut {
	return ScriptCmdOut{ScriptCmd: ScriptCmd{name, cmd}}
}

func NewScriptCmds(cmds map[string]script.Cmd) (out ScriptCmdsOut) {
	out.ScriptCmds = make([]ScriptCmd, 0, len(cmds))
	for name, cmd := range cmds {
		out.ScriptCmds = append(out.ScriptCmds, ScriptCmd{name, cmd})
	}
	return out
}

type ScriptCmd struct {
	Name string
	Cmd  script.Cmd
}

type ScriptCmds struct {
	cell.In

	ScriptCmds []ScriptCmd `group:"script-commands"`
}

func (sc ScriptCmds) Map() map[string]script.Cmd {
	m := make(map[string]script.Cmd, len(sc.ScriptCmds))
	for _, c := range sc.ScriptCmds {
		if c.Name != "" {
			m[c.Name] = c.Cmd
		}
	}
	return m
}

type ScriptCmdOut struct {
	cell.Out

	ScriptCmd ScriptCmd `group:"script-commands"`
}

type ScriptCmdsOut struct {
	cell.Out

	ScriptCmds []ScriptCmd `group:"script-commands,flatten"`
}

const defaultScriptTimeout = time.Minute

func hiveScriptCmd(h *Hive, log *slog.Logger) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "show the hive",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			switch {
			// For backwards compatibility.
			case len(args) >= 1 && args[0] == "start":
				ctx, cancel := context.WithTimeout(context.Background(), defaultScriptTimeout)
				defer cancel()
				return nil, h.Start(log, ctx)
			case len(args) >= 1 && args[0] == "stop":
				ctx, cancel := context.WithTimeout(context.Background(), defaultScriptTimeout)
				defer cancel()
				return nil, h.Stop(log, ctx)
			default:
				err := h.PrintObjects(s.LogWriter(), log)
				return nil, err
			}
		},
	)
}

func hiveStartCmd(h *Hive, log *slog.Logger) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "start the hive",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultScriptTimeout)
			defer cancel()
			return nil, h.Start(log, ctx)
		},
	)
}

func hiveStopCmd(h *Hive, log *slog.Logger) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "stop the hive",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			ctx, cancel := context.WithTimeout(context.Background(), defaultScriptTimeout)
			defer cancel()
			return nil, h.Stop(log, ctx)
		},
	)
}

func RunRepl(h *Hive, in *os.File, out *os.File, prompt string) {
	// Try to set the input into raw mode.
	restore, err := script.MakeRaw(int(in.Fd()))
	defer restore()

	inout := struct {
		io.Reader
		io.Writer
	}{in, out}
	terminal := term.NewTerminal(inout, prompt)
	log := slog.New(slog.NewTextHandler(terminal, nil))
	if width, height, err := term.GetSize(int(in.Fd())); err == nil {
		if err := terminal.SetSize(width, height); err != nil {
			log.Error("Failed to set terminal size", "error", err)
		}
	}

	cmds, err := h.ScriptCommands(log)
	if err != nil {
		log.Error("ScriptCommands()", "error", err)
		return
	}
	for name, cmd := range script.DefaultCmds() {
		cmds[name] = cmd
	}

	e := script.Engine{
		Cmds:  cmds,
		Conds: nil,
	}

	stop := make(chan struct{})
	defer close(stop)

	sigs := make(chan os.Signal, 1)
	defer signal.Stop(sigs)
	signal.Notify(sigs, os.Interrupt)

	newState := func() *script.State {
		ctx, cancel := context.WithCancel(context.Background())
		s, err := script.NewState(ctx, "/tmp", nil)
		if err != nil {
			panic(err)
		}
		go func() {
			select {
			case <-stop:
				cancel()
			case <-sigs:
				cancel()
			}
		}()
		return s
	}

	s := newState()

	for {
		line, err := terminal.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			} else {
				panic(err)
			}
		}

		err = e.ExecuteLine(s, line, terminal)
		if err != nil {
			fmt.Fprintln(terminal, err.Error())
		}

		if s.Context().Err() != nil {
			// Context was cancelled due to interrupt. Re-create the state
			// to run more commands.
			s = newState()
			fmt.Fprintln(terminal, "^C (interrupted)")
		}
	}
}
