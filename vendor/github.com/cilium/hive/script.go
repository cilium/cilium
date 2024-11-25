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

func hiveScriptCmd(h *Hive, log *slog.Logger) script.Cmd {
	const defaultTimeout = time.Minute
	return script.Command(
		script.CmdUsage{
			Summary: "manipulate the hive",
			Args:    "cmd args...",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 1 {
				return nil, fmt.Errorf("hive cmd args...\n'cmd' is one of: start, stop, jobs")
			}
			switch args[0] {
			case "start":
				ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
				defer cancel()
				return nil, h.Start(log, ctx)
			case "stop":
				ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
				defer cancel()
				return nil, h.Stop(log, ctx)
			}
			return nil, fmt.Errorf("unknown hive command %q, expected one of: start, stop, jobs", args[0])
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
	term := term.NewTerminal(inout, prompt)
	log := slog.New(slog.NewTextHandler(term, nil))

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
		line, err := term.ReadLine()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			} else {
				panic(err)
			}
		}

		err = e.ExecuteLine(s, line, term)
		if err != nil {
			fmt.Fprintln(term, err.Error())
		}

		if s.Context().Err() != nil {
			// Context was cancelled due to interrupt. Re-create the state
			// to run more commands.
			s = newState()
			fmt.Fprintln(term, "^C (interrupted)")
		}
	}
}
