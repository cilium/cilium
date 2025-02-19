// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package scripttest adapts the script engine for use in tests.
package scripttest

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cilium/hive/script"
	"golang.org/x/exp/slices"
	"golang.org/x/tools/txtar"
)

var (
	updateFlag = flag.Bool("scripttest.update", false, "Update scripttest files")
	breakFlag  = flag.Bool("scripttest.break", false, "Break on error")
)

// DefaultCmds returns a set of broadly useful script commands.
//
// This set includes all of the commands in script.DefaultCmds,
// as well as a "skip" command that halts the script and causes the
// testing.TB passed to Run to be skipped.
func DefaultCmds() map[string]script.Cmd {
	cmds := script.DefaultCmds()
	cmds["skip"] = Skip()
	return cmds
}

// DefaultConds returns a set of broadly useful script conditions.
//
// This set includes all of the conditions in script.DefaultConds,
// as well as:
//
//   - Conditions of the form "exec:foo" are active when the executable "foo" is
//     found in the test process's PATH, and inactive when the executable is
//     not found.
//
//   - "short" is active when testing.Short() is true.
//
//   - "verbose" is active when testing.Verbose() is true.
func DefaultConds() map[string]script.Cond {
	conds := script.DefaultConds()
	conds["exec"] = CachedExec()
	conds["short"] = script.BoolCondition("testing.Short()", testing.Short())
	conds["verbose"] = script.BoolCondition("testing.Verbose()", testing.Verbose())
	return conds
}

type logBuffer struct {
	strings.Builder
	t testing.TB
}

func (lb *logBuffer) Flush() error {
	if lb.Len() > 0 {
		lb.t.Log(strings.TrimSuffix(lb.String(), "\n"))
	}
	lb.Reset()
	return nil
}

// Run runs the script from the given filename starting at the given initial state.
// When the script completes, Run closes the state.
func Run(t testing.TB, e *script.Engine, s *script.State, filename string, testScript io.Reader) {
	t.Helper()
	err := func() (err error) {
		log := &logBuffer{t: t}
		log.WriteString("\n") // Start output on a new line for consistent indentation.

		// Defer writing to the test log in case the script engine panics during execution,
		// but write the log before we write the final "skip" or "FAIL" line.
		t.Helper()
		defer func() {
			t.Helper()

			if closeErr := s.CloseAndWait(log); err == nil {
				err = closeErr
			}

			if *breakFlag && err != nil && !errors.Is(err, script.ParseError) {
				fmt.Fprintf(log, "Breaking on error: %s\n", err)
				e.ExecuteLine(s, "break", log)
			}

			log.Flush()
		}()

		if testing.Verbose() {
			// Add the environment to the start of the script log.
			wait, err := script.Env().Run(s)
			if err != nil {
				t.Fatal(err)
			}
			if wait != nil {
				stdout, stderr, err := wait(s)
				if err != nil {
					t.Fatalf("env: %v\n%s", err, stderr)
				}
				if len(stdout) > 0 {
					s.Logf("%s\n", stdout)
				}
			}
		}

		return e.Execute(s, filename, bufio.NewReader(testScript), log)
	}()

	if skip := (skipError{}); errors.As(err, &skip) {
		if skip.msg == "" {
			t.Skip("SKIP")
		} else {
			t.Skipf("SKIP: %v", skip.msg)
		}
	}
	if err != nil {
		t.Errorf("FAIL: %v", err)
	}
}

// Skip returns a sentinel error that causes Run to mark the test as skipped.
func Skip() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "skip the current test",
			Args:    "[msg]",
		},
		func(_ *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) > 1 {
				return nil, script.ErrUsage
			}
			if len(args) == 0 {
				return nil, skipError{""}
			}
			return nil, skipError{args[0]}
		})
}

type skipError struct {
	msg string
}

func (s skipError) Error() string {
	if s.msg == "" {
		return "skip"
	}
	return s.msg
}

// CachedExec returns a Condition that reports whether the PATH of the test
// binary itself (not the script's current environment) contains the named
// executable.
func CachedExec() script.Cond {
	return script.CachedCondition(
		"<suffix> names an executable in the test binary's PATH",
		func(name string) (bool, error) {
			_, err := exec.LookPath(name)
			return err == nil, nil
		})
}

func Test(t *testing.T, ctx context.Context, newEngine func(tb testing.TB, args []string) *script.Engine, env []string, pattern string) {
	gracePeriod := 100 * time.Millisecond
	if deadline, ok := t.Deadline(); ok {
		timeout := time.Until(deadline)

		// If time allows, increase the termination grace period to 5% of the
		// remaining time.
		if gp := timeout / 20; gp > gracePeriod {
			gracePeriod = gp
		}

		// When we run commands that execute subprocesses, we want to reserve two
		// grace periods to clean up. We will send the first termination signal when
		// the context expires, then wait one grace period for the process to
		// produce whatever useful output it can (such as a stack trace). After the
		// first grace period expires, we'll escalate to os.Kill, leaving the second
		// grace period for the test function to record its output before the test
		// process itself terminates.
		timeout -= 2 * gracePeriod

		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		t.Cleanup(cancel)
	}

	files, _ := filepath.Glob(pattern)
	if len(files) == 0 {
		t.Fatal("no testdata")
	}
	for _, file := range files {
		file := file
		wd, _ := os.Getwd()
		absFile := filepath.Join(wd, file)
		dataDir := filepath.Dir(absFile)
		env = slices.Clone(env)
		env = append(env, fmt.Sprintf("DATADIR=%s", dataDir))
		name := strings.TrimSuffix(filepath.Base(file), ".txt")
		t.Run(name, func(t *testing.T) {
			if !*breakFlag {
				// The break-on-error flag is set. This will open /dev/tty and set it to raw mode
				// which will mess up logs from other parallel tests. To avoid that, run the tests
				// sequentially when -scripttest.break is set.
				t.Parallel()
			}

			workdir := t.TempDir()
			s, err := script.NewState(ctx, workdir, env)
			if err != nil {
				t.Fatal(err)
			}
			s.DoUpdate = *updateFlag
			s.BreakOnError = *breakFlag

			// Unpack archive.
			a, err := txtar.ParseFile(file)
			if err != nil {
				t.Fatal(err)
			}

			// Extract args from a shebang line, e.g.:
			// #! -foo=1 -bar=true
			// => ["-foo=1", "-bar=true"]
			var args []string
			if shebang, found := strings.CutPrefix(string(a.Comment), "#!"); found {
				shebang, _, _ = strings.Cut(shebang, "\n")
				shebang = strings.TrimSpace(shebang)
				args = strings.Split(shebang, " ")
			}

			initScriptDirs(t, s)
			if err := s.ExtractFiles(a); err != nil {
				t.Fatal(err)
			}

			t.Log(time.Now().UTC().Format(time.RFC3339))
			work, _ := s.LookupEnv("WORK")
			t.Logf("$WORK=%s", work)

			// Note: Do not use filepath.Base(file) here:
			// editors that can jump to file:line references in the output
			// will work better seeing the full path relative to cmd/go
			// (where the "go test" command is usually run).
			Run(t, newEngine(t, args), s, file, bytes.NewReader(a.Comment))

			if *updateFlag {
				updated := false
				for name, contents := range s.FileUpdates {
					idx := slices.IndexFunc(a.Files, func(f txtar.File) bool { return f.Name == name })
					if idx < 0 {
						continue
					}
					a.Files[idx].Data = []byte(contents)
					t.Logf("Updated %q", name)
					updated = true
				}
				if updated {
					err := os.WriteFile(absFile, txtar.Format(a), 0644)
					if err != nil {
						t.Fatal(err)
					}
					t.Logf("Wrote %q", absFile)
				}
			}
		})
	}
}

func initScriptDirs(t testing.TB, s *script.State) {
	must := func(err error) {
		if err != nil {
			t.Helper()
			t.Fatal(err)
		}
	}

	work := s.Getwd()
	must(s.Setenv("WORK", work))
	must(os.MkdirAll(filepath.Join(work, "tmp"), 0777))
	must(s.Setenv(tempEnvName(), filepath.Join(work, "tmp")))
}

func tempEnvName() string {
	switch runtime.GOOS {
	case "windows":
		return "TMP"
	case "plan9":
		return "TMPDIR" // actually plan 9 doesn't have one at all but this is fine
	default:
		return "TMPDIR"
	}
}
