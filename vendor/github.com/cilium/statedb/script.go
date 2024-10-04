// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"bufio"
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"iter"
	"maps"
	"os"
	"regexp"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/cilium/hive"
	"github.com/cilium/hive/script"
	"gopkg.in/yaml.v3"
)

func ScriptCommands(db *DB) hive.ScriptCmdOut {
	subCmds := map[string]script.Cmd{
		"tables":      TablesCmd(db),
		"show":        ShowCmd(db),
		"export":      ExportCmd(db),
		"cmp":         CompareCmd(db),
		"insert":      InsertCmd(db),
		"delete":      DeleteCmd(db),
		"prefix":      PrefixCmd(db),
		"lowerbound":  LowerBoundCmd(db),
		"initialized": InitializedCmd(db),
	}
	subCmdsList := strings.Join(slices.Collect(maps.Keys(subCmds)), ", ")
	return hive.NewScriptCmd(
		"db",
		script.Command(
			script.CmdUsage{
				Summary: "Inspect and manipulate StateDB",
				Args:    "cmd args...",
				Detail: []string{
					"Supported commands: " + subCmdsList,
				},
				// TODO detail to list the sub commands
			},
			func(s *script.State, args ...string) (script.WaitFunc, error) {
				if len(args) < 1 {
					return nil, fmt.Errorf("expected command (%s)", subCmdsList)
				}
				cmd, ok := subCmds[args[0]]
				if !ok {
					return nil, fmt.Errorf("command not found, expected one of %s", subCmdsList)
				}
				wf, err := cmd.Run(s, args[1:]...)
				if errors.Is(err, errUsage) {
					s.Logf("usage: db %s %s\n", args[0], cmd.Usage().Args)
				}
				return wf, err
			},
		),
	)
}

var errUsage = errors.New("bad arguments")

func TablesCmd(db *DB) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Show StateDB tables",
			Args:    "table",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			txn := db.ReadTxn()
			tbls := db.GetTables(txn)
			w := tabwriter.NewWriter(s.LogWriter(), 5, 4, 3, ' ', 0)
			fmt.Fprintf(w, "Name\tObject count\tGraveyard count\tIndexes\tInitializers\tGo type\n")
			for _, tbl := range tbls {
				idxs := strings.Join(tbl.Indexes(), ", ")
				fmt.Fprintf(w, "%s\t%d\t%d\t%s\t%v\t%T\n",
					tbl.Name(), tbl.NumObjects(txn), tbl.numDeletedObjects(txn), idxs, tbl.PendingInitializers(txn), tbl.proto())
			}
			w.Flush()
			return nil, nil
		},
	)
}

func InitializedCmd(db *DB) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Wait until all or specific tables have been initialized",
			Args:    "(-timeout=<duration>) table...",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			txn := db.ReadTxn()
			allTbls := db.GetTables(txn)
			tbls := allTbls

			var flags flag.FlagSet
			timeout := flags.Duration("timeout", 5*time.Second, "Maximum amount of time to wait for the table contents to match")
			if err := flags.Parse(args); err != nil {
				return nil, fmt.Errorf("%w: %s", errUsage, err)
			}
			timeoutChan := time.After(*timeout)
			args = flags.Args()

			if len(args) > 0 {
				tbls = make([]TableMeta, 0, len(allTbls))
				for _, tableName := range args {
					found := false
					for _, tbl := range allTbls {
						if tableName == tbl.Name() {
							tbls = append(tbls, tbl)
							break
						}
					}
					if !found {
						return nil, fmt.Errorf("table %q not found", tableName)
					}
				}
			}

			for _, tbl := range tbls {
				init, watch := tbl.Initialized(txn)
				if init {
					s.Logf("%s initialized\n", tbl.Name())
					continue
				}
				s.Logf("Waiting for %s to initialize (%v)...\n", tbl.Name(), tbl.PendingInitializers(txn))
				select {
				case <-s.Context().Done():
					return nil, s.Context().Err()
				case <-timeoutChan:
					return nil, fmt.Errorf("timed out")
				case <-watch:
					s.Logf("%s initialized\n", tbl.Name())
				}
			}
			return nil, nil
		},
	)
}

func ShowCmd(db *DB) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Show StateDB table",
			Args:    "table",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("%w: expected table name", errUsage)
			}
			err := showTable(s.LogWriter(), db, args[0])
			return nil, err
		},
	)
}

func ExportCmd(db *DB) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Export table",
			Args:    "table (-o=<file>) (-columns=col1,...) (-format={table,yaml,json})",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			var flags flag.FlagSet
			file := flags.String("o", "", "File to write to instead of stdout")
			columns := flags.String("columns", "", "Comma-separated list of columns to write")
			format := flags.String("format", "table", "Format to write in")

			// Sort the args to allow the table name at any position.
			slices.SortFunc(args, func(a, b string) int {
				switch {
				case a[0] == '-':
					return 1
				case b[0] == '-':
					return -1
				default:
					return cmp.Compare(a, b)
				}
			})

			if err := flags.Parse(args[1:]); err != nil {
				return nil, fmt.Errorf("%w: %s", errUsage, err)
			}
			tableName := args[0]

			var w *bufio.Writer
			if *file == "" {
				w = bufio.NewWriter(s.LogWriter())
			} else {
				f, err := os.OpenFile(s.Path(*file), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
				if err != nil {
					return nil, fmt.Errorf("OpenFile(%s): %w", *file, err)
				}
				defer f.Close()
				w = bufio.NewWriter(f)
			}
			defer w.Flush()

			var err error
			switch *format {
			case "yaml", "json":
				if len(*columns) > 0 {
					return nil, fmt.Errorf("-columns not supported with -format=yaml/json")
				}

				txn := db.ReadTxn()
				meta := db.GetTable(txn, tableName)
				if meta == nil {
					return nil, fmt.Errorf("table %q not found", tableName)
				}
				tbl := AnyTable{Meta: meta}
				count := tbl.Meta.NumObjects(txn)
				for obj := range tbl.All(txn) {
					if *format == "yaml" {
						out, err := yaml.Marshal(obj)
						if err != nil {
							return nil, fmt.Errorf("yaml.Marshal: %w", err)
						}
						w.Write(out)
						if count > 1 {
							w.WriteString("---\n")
						}
					} else {
						out, err := json.Marshal(obj)
						if err != nil {
							return nil, err
						}
						w.Write(out)
						w.WriteByte('\n')
					}
					count--
				}
			case "table":
				var cols []string
				if len(*columns) > 0 {
					cols = strings.Split(*columns, ",")
				}
				err = showTable(w, db, tableName, cols...)
				return nil, err
			default:
				return nil, fmt.Errorf("unknown format %q", *format)
			}
			return nil, nil
		})
}

func CompareCmd(db *DB) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Compare table",
			Args:    "table file (-timeout=<dur>) (-grep=<pattern>)",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			var flags flag.FlagSet
			timeout := flags.Duration("timeout", time.Second, "Maximum amount of time to wait for the table contents to match")
			grep := flags.String("grep", "", "Grep the result rows and only compare matching ones")

			err := flags.Parse(args)
			args = args[len(args)-flags.NArg():]
			if err != nil || len(args) != 2 {
				return nil, fmt.Errorf("%w: %s", errUsage, err)
			}

			var grepRe *regexp.Regexp
			if *grep != "" {
				grepRe, err = regexp.Compile(*grep)
				if err != nil {
					return nil, fmt.Errorf("bad grep: %w", err)
				}
			}

			tableName := args[0]

			txn := db.ReadTxn()
			meta := db.GetTable(txn, tableName)
			if meta == nil {
				return nil, fmt.Errorf("table %q not found", tableName)
			}
			tbl := AnyTable{Meta: meta}
			header := tbl.TableHeader()

			data, err := os.ReadFile(s.Path(args[1]))
			if err != nil {
				return nil, fmt.Errorf("ReadFile(%s): %w", args[1], err)
			}
			lines := strings.Split(string(data), "\n")
			lines = slices.DeleteFunc(lines, func(line string) bool {
				return strings.TrimSpace(line) == ""
			})
			if len(lines) < 1 {
				return nil, fmt.Errorf("%q missing header line, e.g. %q", args[1], strings.Join(header, " "))
			}

			columnNames, columnPositions := splitHeaderLine(lines[0])
			columnIndexes, err := getColumnIndexes(columnNames, header)
			if err != nil {
				return nil, err
			}
			lines = lines[1:]
			origLines := lines
			tryUntil := time.Now().Add(*timeout)

			for {
				lines = origLines

				// Create the diff between 'lines' and the rows in the table.
				equal := true
				var diff bytes.Buffer
				w := tabwriter.NewWriter(&diff, 5, 4, 3, ' ', 0)
				fmt.Fprintf(w, "  %s\n", joinByPositions(columnNames, columnPositions))

				objs, watch := tbl.AllWatch(db.ReadTxn())
				for obj := range objs {
					rowRaw := takeColumns(obj.(TableWritable).TableRow(), columnIndexes)
					row := joinByPositions(rowRaw, columnPositions)
					if grepRe != nil && !grepRe.Match([]byte(row)) {
						continue
					}

					if len(lines) == 0 {
						equal = false
						fmt.Fprintf(w, "- %s\n", row)
						continue
					}
					line := lines[0]
					splitLine := splitByPositions(line, columnPositions)

					if slices.Equal(rowRaw, splitLine) {
						fmt.Fprintf(w, "  %s\n", row)
					} else {
						fmt.Fprintf(w, "- %s\n", row)
						fmt.Fprintf(w, "+ %s\n", line)
						equal = false
					}
					lines = lines[1:]
				}
				for _, line := range lines {
					fmt.Fprintf(w, "+ %s\n", line)
					equal = false
				}
				if equal {
					return nil, nil
				}
				w.Flush()

				if time.Now().After(tryUntil) {
					return nil, fmt.Errorf("table mismatch:\n%s", diff.String())
				}
				select {
				case <-s.Context().Done():
					return nil, s.Context().Err()
				case <-watch:
				}
			}
		})
}

func InsertCmd(db *DB) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Insert object into a table",
			Args:    "table path...",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return insertOrDelete(true, db, s, args...)
		},
	)
}

func DeleteCmd(db *DB) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Delete an object from the table",
			Args:    "table path...",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return insertOrDelete(false, db, s, args...)
		},
	)
}

func getTable(db *DB, tableName string) (*AnyTable, ReadTxn, error) {
	txn := db.ReadTxn()
	meta := db.GetTable(txn, tableName)
	if meta == nil {
		return nil, nil, fmt.Errorf("table %q not found", tableName)
	}
	return &AnyTable{Meta: meta}, txn, nil
}

func insertOrDelete(insert bool, db *DB, s *script.State, args ...string) (script.WaitFunc, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("%w: expected table and path(s)", errUsage)
	}

	tbl, _, err := getTable(db, args[0])
	if err != nil {
		return nil, err
	}

	wtxn := db.WriteTxn(tbl.Meta)
	defer wtxn.Commit()

	for _, arg := range args[1:] {
		data, err := os.ReadFile(s.Path(arg))
		if err != nil {
			return nil, fmt.Errorf("ReadFile(%s): %w", arg, err)
		}
		parts := strings.Split(string(data), "---")
		for _, part := range parts {
			obj, err := tbl.UnmarshalYAML([]byte(part))
			if err != nil {
				return nil, fmt.Errorf("Unmarshal(%s): %w", arg, err)
			}
			if insert {
				_, _, err = tbl.Insert(wtxn, obj)
				if err != nil {
					return nil, fmt.Errorf("Insert(%s): %w", arg, err)
				}
			} else {
				_, _, err = tbl.Delete(wtxn, obj)
				if err != nil {
					return nil, fmt.Errorf("Delete(%s): %w", arg, err)
				}

			}
		}
	}
	return nil, nil
}

func PrefixCmd(db *DB) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Query table by prefix",
			Args:    "table key (-o=<file>)",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return prefixOrLowerbound(false, db, s, args)
		},
	)
}

func LowerBoundCmd(db *DB) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Query table by lower bound search",
			Args:    "table key (-o=<file>)",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return prefixOrLowerbound(true, db, s, args)
		},
	)
}

func prefixOrLowerbound(lowerbound bool, db *DB, s *script.State, args []string) (script.WaitFunc, error) {
	var flags flag.FlagSet
	file := flags.String("o", "", "File to write results to instead of log")
	if err := flags.Parse(args); err != nil {
		return nil, fmt.Errorf("%w: %s", errUsage, err)
	}
	args = flags.Args()
	if len(args) < 2 {
		return nil, fmt.Errorf("%w: expected table and key", errUsage)
	}

	tbl, txn, err := getTable(db, args[0])
	if err != nil {
		return nil, err
	}

	var w io.Writer
	if *file == "" {
		w = s.LogWriter()
	} else {
		f, err := os.OpenFile(s.Path(*file), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("WriteFile(%s): %s", *file, err)
		}
		defer f.Close()
		w = f
	}

	tw := tabwriter.NewWriter(w, 5, 4, 3, ' ', 0)
	header := tbl.TableHeader()
	fmt.Fprintf(tw, "%s\n", strings.Join(header, "\t"))

	var it iter.Seq2[any, uint64]
	if lowerbound {
		it = tbl.LowerBound(txn, args[1])
	} else {
		it = tbl.Prefix(txn, args[1])
	}

	for obj := range it {
		row := obj.(TableWritable).TableRow()
		fmt.Fprintf(tw, "%s\n", strings.Join(row, "\t"))
	}
	tw.Flush()

	return nil, nil
}

func showTable(w io.Writer, db *DB, tableName string, columns ...string) error {
	txn := db.ReadTxn()
	meta := db.GetTable(txn, tableName)
	if meta == nil {
		return fmt.Errorf("table %q not found", tableName)
	}
	tbl := AnyTable{Meta: meta}

	header := tbl.TableHeader()
	if header == nil {
		return fmt.Errorf("objects in table %q not TableWritable", meta.Name())
	}
	var idxs []int
	var err error
	if len(columns) > 0 {
		idxs, err = getColumnIndexes(columns, header)
		header = columns
	} else {
		idxs, err = getColumnIndexes(header, header)
	}
	if err != nil {
		return err
	}

	tw := tabwriter.NewWriter(w, 5, 4, 3, ' ', 0)
	fmt.Fprintf(tw, "%s\n", strings.Join(header, "\t"))
	for obj := range tbl.All(db.ReadTxn()) {
		row := takeColumns(obj.(TableWritable).TableRow(), idxs)
		fmt.Fprintf(tw, "%s\n", strings.Join(row, "\t"))
	}
	tw.Flush()
	return nil
}

func takeColumns[T any](xs []T, idxs []int) []T {
	// Invariant: idxs is sorted so can set in-place.
	for i, idx := range idxs {
		xs[i] = xs[idx]
	}
	return xs[:len(idxs)]
}

func getColumnIndexes(names []string, header []string) ([]int, error) {
	columnIndexes := make([]int, 0, len(header))
loop:
	for _, name := range names {
		for i, name2 := range header {
			if strings.EqualFold(name, name2) {
				columnIndexes = append(columnIndexes, i)
				continue loop
			}
		}
		return nil, fmt.Errorf("column %q not part of %v", name, header)
	}
	return columnIndexes, nil
}

// splitHeaderLine takes a header of column names separated by any
// number of whitespaces and returns the names and their starting positions.
// e.g. "Foo  Bar Baz" would result in ([Foo,Bar,Baz],[0,5,9]).
// With this information we can take a row in the database and format it
// the same way as our test data.
func splitHeaderLine(line string) (names []string, pos []int) {
	start := 0
	skip := true
	for i, r := range line {
		switch r {
		case ' ', '\t':
			if !skip {
				names = append(names, line[start:i])
				pos = append(pos, start)
				start = -1
			}
			skip = true
		default:
			skip = false
			if start == -1 {
				start = i
			}
		}
	}
	if start >= 0 && start < len(line) {
		names = append(names, line[start:])
		pos = append(pos, start)
	}
	return
}

// splitByPositions takes a "row" line and the positions of the header columns
// and extracts the values.
// e.g. if we have the positions [0,5,9] (from header "Foo  Bar Baz") and
// line is "1    a   b", then we'd extract [1,a,b].
// The whitespace on the right of the start position (e.g. "1  \t") is trimmed.
// This of course requires that the table is properly formatted in a way that the
// header columns are indented to fit the data exactly.
func splitByPositions(line string, positions []int) []string {
	out := make([]string, 0, len(positions))
	start := 0
	for _, pos := range positions[1:] {
		if start >= len(line) {
			out = append(out, "")
			start = len(line)
			continue
		}
		out = append(out, strings.TrimRight(line[start:min(pos, len(line))], " \t"))
		start = pos
	}
	out = append(out, strings.TrimRight(line[min(start, len(line)):], " \t"))
	return out
}

// joinByPositions is the reverse of splitByPositions, it takes the columns of a
// row and the starting positions of each and joins into a single line.
// e.g. [1,a,b] and positions [0,5,9] expands to "1    a   b".
// NOTE: This does not deal well with mixing tabs and spaces. The test input
// data should preferably just use spaces.
func joinByPositions(row []string, positions []int) string {
	var w strings.Builder
	prev := 0
	for i, pos := range positions {
		for pad := pos - prev; pad > 0; pad-- {
			w.WriteByte(' ')
		}
		w.WriteString(row[i])
		prev = pos + len(row[i])
	}
	return w.String()
}
