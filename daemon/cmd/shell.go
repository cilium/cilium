package cmd

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"text/tabwriter"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/version"
	upstreamHive "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/hive/script"
)

var shellCell = cell.Module(
	"shell",
	"Debug shell",
	cell.Invoke(registerShell),
)

func registerShell(in upstreamHive.ScriptCmds, log *slog.Logger, jg job.Group) {
	cmds := in.Map()
	cmds["maps"] = bpfMapsCommand
	// Add a subset of the default commands.
	defCmds := []string{"cat", "help", "exec", "stop"}
	for k, cmd := range script.DefaultCmds() {
		if slices.Contains(defCmds, k) {
			cmds[k] = cmd
		}
		if k == "stop" {
			cmds["exit"] = cmd
			cmds["quit"] = cmd
		}
	}
	jg.Add(job.OneShot("shell", shell{log, cmds}.run))
}

var bpfMapsCommand = script.Command(
	script.CmdUsage{Summary: "List open BPF maps"},
	func(s *script.State, args ...string) (script.WaitFunc, error) {
		w := tabwriter.NewWriter(s.LogWriter(), 5, 4, 3, ' ', 0)
		defer w.Flush()
		fmt.Fprintf(w, "Name\tType\tMaxEntries\tFlags\tPath\n")
		for _, m := range bpf.GetMaps() {
			p, _ := m.Path()
			fmt.Fprintf(w, "%s\t%s\t%d\t%x\t%s\t\n",
				m.Name(),
				m.Type(),
				m.MaxEntries(),
				m.Flags(),
				p,
			)
		}
		return nil, nil
	},
)

type shell struct {
	log  *slog.Logger
	cmds map[string]script.Cmd
}

func (sh shell) run(ctx context.Context, _ cell.Health) error {
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "unix", "/tmp/ciliumshell.sock")
	if err != nil {
		return err
	}
	for ctx.Err() == nil {
		conn, err := l.Accept()
		if err == nil {
			go sh.handleConn(ctx, conn)
		}
	}
	return nil
}

func (sh shell) handleConn(ctx context.Context, conn net.Conn) {
	e := script.Engine{
		Cmds:        sh.cmds,
		Conds:       nil,
		Interactive: true,
		Prompt:      "cilium> ",
	}
	defer conn.Close()

	const (
		Red     = "\033[31m"
		Yellow  = "\033[33m"
		Blue    = "\033[34m"
		Green   = "\033[32m"
		Magenta = "\033[35m"
		Cyan    = "\033[36m"
		Reset   = "\033[0m"
	)

	fmt.Fprint(conn, Yellow+"    /¯¯\\\n")
	fmt.Fprint(conn, Cyan+" /¯¯"+Yellow+"\\__/"+Green+"¯¯\\"+Reset+"\n")
	fmt.Fprintf(conn, Cyan+" \\__"+Red+"/¯¯\\"+Green+"__/"+Reset+" Cilium %s\n", version.Version)
	fmt.Fprint(conn, Green+" /¯¯"+Red+"\\__/"+Magenta+"¯¯\\"+Reset+"\n")
	fmt.Fprint(conn, Green+" \\__"+Blue+"/¯¯\\"+Magenta+"__/"+Reset+"\n")
	fmt.Fprint(conn, Blue+Blue+Blue+"    \\__/"+Reset+"\n")
	fmt.Fprint(conn, "\n")
	fmt.Fprint(conn, "Welcome to the Cilium Shell! Type 'help' for list of supported commands\n")

	s, err := script.NewState(ctx, "/tmp", nil)
	if err != nil {
		sh.log.Error("NewState", "error", err)
		return
	}
	// FIXME: conn io.Reader should be context aware.
	// FIXME: catch the ^D and terminate. might want to not pass
	// directly to the engine but parse input first.
	bio := bufio.NewReader(conn)
	for {
		err := e.Execute(s, "", bio, conn)
		sh.log.Info("execute error", "error", err)

		if err != nil {
			// Continue processing on errors.
			if _, err := fmt.Fprintln(conn, err); err != nil {
				return
			}
		} else {
			break
		}
	}
	sh.log.Info("stopping")
}
