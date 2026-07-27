package script

import (
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"
	"github.com/spf13/pflag"
)

// Cell defines our example module that provides the [Example] object
// and script commands to interact with it.
var Cell = cell.Module(
	"example",
	"Example module",

	cell.Provide(
		New,
		ExampleCommands,
	),
)

type Example struct {
	log   *slog.Logger
	count atomic.Int32
}

func New(log *slog.Logger) *Example {
	return &Example{log: log}
}

func (e *Example) SayHello(name, greeting string) string {
	e.log.Info("SayHello() called", "name", name, "greeting", greeting)
	e.count.Add(1)
	return fmt.Sprintf("%s %s\n", greeting, name)
}

func ExampleCommands(e *Example) hive.ScriptCmdsOut {
	return hive.NewScriptCmds(map[string]script.Cmd{
		// example/hello command says a greeting to the stdout buffer.
		"example/hello": script.Command(
			script.CmdUsage{
				Summary: "Say hello",
				Args:    "name",
				Flags: func(fs *pflag.FlagSet) {
					fs.String("greeting", "Hello,", "Greeting to use")
				},
			},

			// Define the function for executing the command.  The function takes
			// [script.State] that provides logging, flags and utilities, and the
			// command arguments that are left over from parsing [CmdUsage.Flags].
			//
			// The function can either directly execute the command and return a
			// nil [script.WaitFunc] or if the command should run in the background
			// ([script.CmdUsage.Async] is true) or the if the command needs to write
			// to stdout/stderr buffers, then a [script.WaitFunc] should be returned.
			//
			// It is preferable to return output in stdout and not Logf'd so it
			// can be matched against.  In "cilium-dbg shell" the output looks the
			// same regardless of whether Logf() or stdout is used (the "[stdout]"
			// banner is stripped).
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				if len(args) != 1 {
					return nil, fmt.Errorf("%w: expected name", script.ErrUsage)
				}
				name := args[0]
				return func(s *script.State) (stdout, stderr string, err error) {
					greeting, err := s.Flags.GetString("greeting")
					if err != nil {
						return "", "", err
					}
					// In addition to [stdout] and [stderr] the command can also write to
					// a separate log buffer. The logs however are not matchable in tests.
					s.Logf("calling SayHello(%s, %s)\n", name, greeting)
					stdout = e.SayHello(name, greeting)
					return
				}, nil
			},
		),

		// example/counts command writes the number of times SayHello() has been called to
		// stdout.
		"example/counts": script.Command(
			script.CmdUsage{
				Summary: "Show the call counts of the example module",
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				return func(s *script.State) (stdout, stderr string, err error) {
					stdout = fmt.Sprintf("%d SayHello()\n", e.count.Load())
					return
				}, nil
			},
		),
	})
}
