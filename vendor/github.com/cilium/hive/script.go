package hive

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"
)

func NewScriptCmd(name string, cmd script.Cmd) ScriptCmdOut {
	return ScriptCmdOut{ScriptCmd: ScriptCmd{name, cmd}}
}

func NewScriptCmds(cmds map[string]script.Cmd) ScriptCmdsOut {
	var out ScriptCmdsOut
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
		m[c.Name] = c.Cmd
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

func hiveScriptCmd(h *Hive) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "inspect the hive",
			Args:    "",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return nil, h.printObjects(s.LogWriter())
		},
	)
}
