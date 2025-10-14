// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	flag "github.com/spf13/pflag"

	"github.com/cilium/cilium/tools/testowners/codeowners"
)

func fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}

// TestEvent corresponds to the same structure from stdlib test2json.
type TestEvent struct {
	Time    time.Time // encodes as an RFC3339-format string
	Action  string
	Package string
	Test    string
	Elapsed float64 // seconds
	Output  string
}

var (
	CodeOwners []string
	Format     string
)

func init() {
	flag.StringSliceVar(&CodeOwners, "code-owners", []string{}, "Use the code owners defined in these files for --log-code-owners")
	flag.StringVar(&Format, "format", "gotest", "The format of the input. One of 'gotest' (default) or 'plain'")
}

func fromGotest(owners *codeowners.Ruleset) int {
	// Example JSON for failed test:
	// {"Time":"2025-01-31T07:35:57.837543016+01:00","Action":"start","Package":"github.com/cilium/cilium/test/fail"}
	// {"Time":"2025-01-31T07:35:57.840861715+01:00","Action":"run","Package":"github.com/cilium/cilium/test/fail","Test":"TestFailure"}
	// {"Time":"2025-01-31T07:35:57.840923716+01:00","Action":"output","Package":"github.com/cilium/cilium/test/fail","Test":"TestFailure","Output":"=== RUN   TestFailure\n"}
	// {"Time":"2025-01-31T07:35:57.841037505+01:00","Action":"output","Package":"github.com/cilium/cilium/test/fail","Test":"TestFailure","Output":"--- FAIL: TestFailure (0.00s)\n"}
	// {"Time":"2025-01-31T07:35:57.841053472+01:00","Action":"fail","Package":"github.com/cilium/cilium/test/fail","Test":"TestFailure","Elapsed":0}
	// {"Time":"2025-01-31T07:35:57.841070189+01:00","Action":"output","Package":"github.com/cilium/cilium/test/fail","Output":"FAIL\n"}
	// {"Time":"2025-01-31T07:35:57.841542486+01:00","Action":"output","Package":"github.com/cilium/cilium/test/fail","Output":"FAIL\tgithub.com/cilium/cilium/test/fail\t0.004s\n"}
	// {"Time":"2025-01-31T07:35:57.841580354+01:00","Action":"fail","Package":"github.com/cilium/cilium/test/fail","Elapsed":0.004}

	failedPackages := make(map[string]struct{})
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var event TestEvent

		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			fatal(" Failed to unmarshal test results. Is the input malformed?\n")
		}

		if event.Action == "fail" {
			failedPackages[event.Package] = struct{}{}
		}
	}

	w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)
	if len(failedPackages) > 0 {
		fmt.Fprintln(w, "⛑️ The following owners are responsible for reliability of the failing test(s): ")
		fmt.Fprintln(w, "Package\tOwner")
	}
	exitCode := 0
	reportedLines := map[string]struct{}{}
	for pkg := range failedPackages {
		relPath := strings.TrimPrefix(pkg, "github.com/cilium/cilium/") + "/"
		rule, err := owners.Match(relPath)
		if err != nil || rule == nil || rule.Owners == nil {
			exitCode = 1
			line := "Failed to locate owner for package " + relPath
			if err != nil {
				line = line + ":" + err.Error()
			}
			if _, reported := reportedLines[line]; !reported {
				slog.Error(line)
				reportedLines[line] = struct{}{}
			}
			continue
		}
		owners := make([]string, 0, len(rule.Owners))
		for _, o := range rule.Owners {
			owners = append(owners, o.String())
		}
		fmt.Fprintln(w, pkg+"\t"+strings.Join(owners, ", "))
	}
	w.Flush()

	return exitCode
}

func fromPlain(owners *codeowners.Ruleset) int {
	exitCode := 0
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		filepath := strings.TrimSpace(scanner.Text())
		rule, err := owners.Match(filepath)
		if err != nil {
			fmt.Printf("❗ Error matching filepath %q: %s\n", filepath, err)
			exitCode = 1
			continue
		}
		if rule == nil || rule.Owners == nil {
			fmt.Printf("❗ No owners found for filepath %q\n", filepath)
			exitCode = 1
			continue
		}

		fmt.Printf("⛑️ The following owners are responsible for %s:\n", filepath)
		for _, o := range rule.Owners {
			fmt.Printf(" - %s\n", o.String())
		}
	}
	return exitCode
}

func main() {
	flag.Parse()

	exitCode := 0

	owners, err := codeowners.Load(CodeOwners)
	if err != nil {
		fatal("❗ Failed to load code owners", "error", err)
	}

	switch Format {
	case "gotest":
		exitCode = fromGotest(owners)
	case "plain":
		exitCode = fromPlain(owners)
	default:
		fmt.Printf("❗ Unknown format %q. Supported formats are 'gotest' and 'plain'\n", Format)
		exitCode = 1
	}

	os.Exit(exitCode)
}
