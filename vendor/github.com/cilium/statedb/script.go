// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statedb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/cilium/hive"
	"github.com/cilium/hive/script"
	"github.com/liggitt/tabwriter"
	"github.com/spf13/pflag"
	"golang.org/x/time/rate"
	"gopkg.in/yaml.v3"
)

func ScriptCommands(db *DB) hive.ScriptCmdsOut {
	return hive.NewScriptCmds(map[string]script.Cmd{
		"db":             DBCmd(db),
		"db/show":        ShowCmd(db),
		"db/cmp":         CompareCmd(db),
		"db/empty":       EmptyCmd(db),
		"db/insert":      InsertCmd(db),
		"db/delete":      DeleteCmd(db),
		"db/get":         GetCmd(db),
		"db/prefix":      PrefixCmd(db),
		"db/list":        ListCmd(db),
		"db/lowerbound":  LowerBoundCmd(db),
		"db/watch":       WatchCmd(db),
		"db/initialized": InitializedCmd(db),
	})
}

func DBCmd(db *DB) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Describe StateDB configuration",
			Detail: []string{
				"The 'db' command describes the StateDB configuration, showing",
				"all registered tables and brief summary of their state.",
				"",
				"The following details are shown:",
				"- Name: The name of the table as given to 'NewTable'",
				"- Object count: Objects in the table",
				"- Zombie objects: Deleted, but not observed objects",
				"- Indexes: The indexes specified for the table",
				"- Initializers: Pending table initializers",
				"- Go type: The Go type, the T in Table[T]",
				"- Last WriteTxn: The current/last write against the table",
				"",
				"The individual tables can be manipulated and inspected with the",
				"other commands. See 'help -v db/show' etc. for detailed help.",
				"Here is some examples to get you statred:",
				"",
				"> db/show example",
				"Name   X",
				"one    1",
				"two    2",
				"",
				"> db/prefix -index=id example o",
				"Name   X",
				"one    1",
				"",
				"> db/insert example three.yaml four.yaml",
				"",
				"> db/delete example three.yaml",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			txn := db.ReadTxn()
			tbls := db.GetTables(txn)
			w := newTabWriter(s.LogWriter())
			fmt.Fprintf(w, "Name\tObject count\tZombie objects\tIndexes\tInitializers\tGo type\tLast WriteTxn\n")
			for _, tbl := range tbls {
				idxs := strings.Join(tbl.Indexes(), ", ")
				fmt.Fprintf(w, "%s\t%d\t%d\t%s\t%v\t%T\t%s\n",
					tbl.Name(), tbl.NumObjects(txn), tbl.numDeletedObjects(txn), idxs, tbl.PendingInitializers(txn), tbl.proto(), tbl.getAcquiredInfo())
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
			Args:    "table...",
			Flags: func(fs *pflag.FlagSet) {
				fs.Duration("timeout", 5*time.Second, "Maximum amount of time to wait for the table contents to match")
			},
			Detail: []string{
				"Waits until all or specific tables have been marked",
				"initialized. The default timeout is 5 seconds.",
				"",
				"This command is useful in tests where you might need to wait",
				"for e.g. a background reflector to have started watching before",
				"inserting objects.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			timeout, err := s.Flags.GetDuration("timeout")
			if err != nil {
				return nil, err
			}

			txn := db.ReadTxn()
			timeoutChan := time.After(timeout)
			allTbls := db.GetTables(txn)
			tbls := allTbls

			if len(args) > 0 {
				// Specific tables requested, look them up.
				tbls = make([]TableMeta, 0, len(args))
				for _, tableName := range args {
					found := false
					for _, tbl := range allTbls {
						if tableName == tbl.Name() {
							tbls = append(tbls, tbl)
							found = true
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
			Summary: "Show the contents of a table",
			Args:    "table",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP("out", "o", "", "File to write to instead of stdout")
				fs.StringSlice("columns", nil, "Columns to write")
				fs.StringP("format", "f", "table", "Format to write in (table, yaml or json)")
			},
			Detail: []string{
				"The contents are written to stdout, but can be written to",
				"a file instead with the -o flag.",
				"",
				"By default the table is shown in the table format.",
				"For YAML use '-format=yaml' and for JSON use '-format=json'",
				"",
				"To only show specific columns use the '-columns' flag. The",
				"columns are as specified by 'TableHeader()' method.",
				"This flag is only supported with 'table' formatting.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			file, err := s.Flags.GetString("out")
			if err != nil {
				return nil, err
			}
			columns, err := s.Flags.GetStringSlice("columns")
			if err != nil {
				return nil, err
			}
			format, err := s.Flags.GetString("format")
			if err != nil {
				return nil, err
			}

			if len(args) < 1 {
				return nil, fmt.Errorf("missing table name")
			}
			tableName := args[0]
			return func(*script.State) (stdout, stderr string, err error) {
				var buf strings.Builder
				var w io.Writer
				if file == "" {
					w = &buf
				} else {
					f, err := os.OpenFile(s.Path(file), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
					if err != nil {
						return "", "", fmt.Errorf("OpenFile(%s): %w", file, err)
					}
					defer f.Close()
					w = f
				}
				tbl, txn, err := getTable(db, tableName)
				if err != nil {
					return "", "", err
				}
				err = writeObjects(tbl, tbl.All(txn), w, columns, format)
				return buf.String(), "", err
			}, nil
		})
}

func CompareCmd(db *DB) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Compare table",
			Args:    "table file",
			Flags: func(fs *pflag.FlagSet) {
				fs.Duration("timeout", 5*time.Second, "Maximum amount of time to wait for the table contents to match")
				fs.String("grep", "", "Grep the result rows and only compare matching ones")
			},
			Detail: []string{
				"Compare the contents of a table against a file.",
				"The comparison is retried until a timeout (1s default).",
				"",
				"The file should be formatted in the same style as",
				"the output from 'db/show -format=table'. Indentation",
				"does not matter as long as header is aligned with the data.",
				"",
				"Not all columns need to be specified. Remove the columns",
				"from the file you do not want compared.",
				"",
				"The rows can be filtered with the -grep flag.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			timeout, err := s.Flags.GetDuration("timeout")
			if err != nil {
				return nil, err
			}
			grep, err := s.Flags.GetString("grep")
			if err != nil {
				return nil, err
			}

			if len(args) != 2 {
				return nil, fmt.Errorf("expected table and filename")
			}

			var grepRe *regexp.Regexp
			if grep != "" {
				grepRe, err = regexp.Compile(grep)
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
			timeoutChan := time.After(timeout)

			for {
				lines = origLines

				// Create the diff between 'lines' and the rows in the table.
				equal := true
				var diff bytes.Buffer
				w := newTabWriter(&diff)
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

				select {
				case <-s.Context().Done():
					return nil, s.Context().Err()

				case <-timeoutChan:
					return nil, fmt.Errorf("table mismatch:\n%s", diff.String())

				case <-watch:
				}
			}
		})
}

func EmptyCmd(db *DB) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Assert that given table(s) are empty",
			Args:    "table",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			txn := db.ReadTxn()
			for _, tableName := range args {
				meta := db.GetTable(txn, tableName)
				if meta == nil {
					return nil, fmt.Errorf("table %q not found", tableName)
				}
				tbl := AnyTable{Meta: meta}
				if n := tbl.NumObjects(txn); n != 0 {
					return nil, fmt.Errorf("table %q not empty, found %d obects", tableName, n)
				}
			}
			return nil, nil
		})
}

func InsertCmd(db *DB) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Insert object into a table",
			Args:    "table path...",
			Detail: []string{
				"Insert one or more objects into a table. The input files",
				"are expected to be YAML.",
			},
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
			Detail: []string{
				"Delete one or more objects from the table. The input files",
				"are expected to be YAML and need to specify enough of the",
				"object to construct the primary key",
			},
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
		return nil, fmt.Errorf("expected table and path(s)")
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
	return queryCmd(db,
		queryCmdPrefix,
		"Query table by prefix",
		[]string{
			"Show all objects that start with the given " + underline("key") + ".",
		},
	)
}

func LowerBoundCmd(db *DB) script.Cmd {
	return queryCmd(db,
		queryCmdLowerBound,
		"Query table by lower bound search",
		[]string{
			"Show all objects that have a matching key equal or higher",
			"than the query " + underline("key") + ".",
		},
	)
}

func ListCmd(db *DB) script.Cmd {
	return queryCmd(db,
		queryCmdList,
		"List objects in the table",
		[]string{
			"Show all objects matching the query key.",
		},
	)
}

func GetCmd(db *DB) script.Cmd {
	return queryCmd(db,
		queryCmdGet,
		"Get the first matching object",
		[]string{
			"Show the first object that matches the query key.",
		},
	)
}

const (
	queryCmdList = iota
	queryCmdPrefix
	queryCmdLowerBound
	queryCmdGet
)

func queryCmd(db *DB, query int, summary string, detail []string) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: summary,
			Args:    "table key",
			Flags: func(fs *pflag.FlagSet) {
				fs.StringP("out", "o", "", "File to write to instead of stdout")
				fs.StringSlice("columns", nil, "Columns to write")
				fs.StringP("format", "f", "table", "Format to write in (table, yaml or json)")
				fs.StringP("index", "i", "", "Index to query")
				fs.Bool("delete", false, "Delete all matching objects")
			},
			Detail: detail,
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return runQueryCmd(query, db, s, args)
		},
	)
}

func runQueryCmd(query int, db *DB, s *script.State, args []string) (script.WaitFunc, error) {
	file, err := s.Flags.GetString("out")
	if err != nil {
		return nil, err
	}
	columns, err := s.Flags.GetStringSlice("columns")
	if err != nil {
		return nil, err
	}
	format, err := s.Flags.GetString("format")
	if err != nil {
		return nil, err
	}
	index, err := s.Flags.GetString("index")
	if err != nil {
		return nil, err
	}
	delete, err := s.Flags.GetBool("delete")
	if err != nil {
		return nil, err
	}

	if len(args) < 2 {
		return nil, fmt.Errorf("expected table and key")
	}

	return func(*script.State) (stdout, stderr string, err error) {
		tbl, txn, err := getTable(db, args[0])
		if err != nil {
			return "", "", err
		}

		var buf strings.Builder
		var w io.Writer
		if file == "" {
			w = &buf
		} else {
			f, err := os.OpenFile(s.Path(file), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
			if err != nil {
				return "", "", fmt.Errorf("OpenFile(%s): %s", file, err)
			}
			defer f.Close()
			w = f
		}

		var it iter.Seq2[any, uint64]
		switch query {
		case queryCmdList:
			it, err = tbl.List(txn, index, args[1])
		case queryCmdLowerBound:
			it, err = tbl.LowerBound(txn, index, args[1])
		case queryCmdPrefix:
			it, err = tbl.Prefix(txn, index, args[1])
		case queryCmdGet:
			it, err = tbl.List(txn, index, args[1])
			if err == nil {
				it = firstOfSeq2(it)
			}
		default:
			panic("unknown query enum")
		}
		if err != nil {
			return "", "", fmt.Errorf("query: %w", err)
		}

		err = writeObjects(tbl, it, w, columns, format)
		if err != nil {
			return "", "", err
		}

		if delete {
			wtxn := db.WriteTxn(tbl.Meta)
			count := 0
			for obj := range it {
				_, hadOld, err := tbl.Delete(wtxn, obj)
				if err != nil {
					wtxn.Abort()
					return "", "", err
				}
				if hadOld {
					count++
				}
			}
			s.Logf("Deleted %d objects\n", count)
			wtxn.Commit()
		}

		return buf.String(), "", err
	}, nil
}

func WatchCmd(db *DB) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Watch a table for changes",
			Args:    "table",
			Detail: []string{
				"Watch a table for changes. Streams each insert or delete",
				"that happens to the table.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) < 1 {
				return nil, fmt.Errorf("expected table name")
			}

			tbl, _, err := getTable(db, args[0])
			if err != nil {
				return nil, err
			}
			wtxn := db.WriteTxn(tbl.Meta)
			iter, err := tbl.Changes(wtxn)
			wtxn.Commit()
			if err != nil {
				return nil, err
			}

			header := tbl.TableHeader()
			if header == nil {
				return nil, fmt.Errorf("objects in table %q not TableWritable", tbl.Meta.Name())
			}
			tw := newTabWriter(&strikethroughWriter{w: s.LogWriter()})
			fmt.Fprintf(tw, "%s\n", strings.Join(header, "\t"))

			limiter := rate.NewLimiter(10.0, 1)
			for {
				if err := limiter.Wait(s.Context()); err != nil {
					break
				}
				changes, watch := iter.nextAny(db.ReadTxn())
				for change := range changes {
					row := change.Object.(TableWritable).TableRow()
					if change.Deleted {
						fmt.Fprintf(tw, "%s (deleted)%s", strings.Join(row, "\t"), magicStrikethroughNewline)
					} else {
						fmt.Fprintf(tw, "%s\n", strings.Join(row, "\t"))
					}
				}
				tw.Flush()
				if err := s.FlushLog(); err != nil {
					return nil, err
				}
				select {
				case <-watch:
				case <-s.Context().Done():
					return nil, nil
				}
			}
			return nil, nil

		},
	)
}

func firstOfSeq2[A, B any](it iter.Seq2[A, B]) iter.Seq2[A, B] {
	return func(yield func(a A, b B) bool) {
		for a, b := range it {
			yield(a, b)
			break
		}
	}
}

func writeObjects(tbl *AnyTable, it iter.Seq2[any, Revision], w io.Writer, columns []string, format string) error {
	if len(columns) > 0 && format != "table" {
		return fmt.Errorf("-columns not supported with non-table formats")
	}
	switch format {
	case "yaml":
		sep := []byte("---\n")
		first := true
		for obj := range it {
			if !first {
				w.Write(sep)
			}
			first = false

			out, err := yaml.Marshal(obj)
			if err != nil {
				return fmt.Errorf("yaml.Marshal: %w", err)
			}
			if _, err := w.Write(out); err != nil {
				return err
			}
		}
		return nil
	case "json":
		sep := []byte("\n")
		for obj := range it {
			out, err := json.MarshalIndent(obj, "", "  ")
			if err != nil {
				return fmt.Errorf("json.Marshal: %w", err)
			}
			if _, err := w.Write(out); err != nil {
				return err
			}
			w.Write(sep)
		}
		return nil
	case "table":
		header := tbl.TableHeader()
		if header == nil {
			return fmt.Errorf("objects in table %q not TableWritable", tbl.Meta.Name())
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
		tw := newTabWriter(w)
		fmt.Fprintf(tw, "%s\n", strings.Join(header, "\t"))

		for obj := range it {
			row := takeColumns(obj.(TableWritable).TableRow(), idxs)
			fmt.Fprintf(tw, "%s\n", strings.Join(row, "\t"))
		}
		return tw.Flush()
	}
	return fmt.Errorf("unknown format %q, expected table, yaml or json", format)
}

func takeColumns[T any](xs []T, idxs []int) (out []T) {
	for _, idx := range idxs {
		out = append(out, xs[idx])
	}
	return
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

// strikethroughWriter writes a line of text that is striken through
// if the line contains the magic character at the end before \n.
// This is used to strike through a tab-formatted line without messing
// up with the widths of the cells.
type strikethroughWriter struct {
	buf           []byte
	strikethrough bool
	w             io.Writer
}

var (
	// Magic character to use at the end of the line to denote that this should be
	// striken through.
	// This is to avoid messing up the width calculations in the tab writer, which
	// would happen if ANSI codes were used directly.
	magicStrikethrough        = byte('\xfe')
	magicStrikethroughNewline = "\xfe\n"
)

func stripTrailingWhitespace(buf []byte) []byte {
	idx := bytes.LastIndexFunc(
		buf,
		func(r rune) bool {
			return r != ' ' && r != '\t'
		},
	)
	if idx > 0 {
		return buf[:idx+1]
	}
	return buf
}

func (s *strikethroughWriter) Write(p []byte) (n int, err error) {
	write := func(bs []byte) {
		if err == nil {
			_, e := s.w.Write(bs)
			if e != nil {
				err = e
			}
		}
	}
	for _, c := range p {
		switch c {
		case '\n':
			s.buf = stripTrailingWhitespace(s.buf)

			if s.strikethrough {
				write(beginStrikethrough)
				write(s.buf)
				write(endStrikethrough)
			} else {
				write(s.buf)
			}
			write(newline)

			s.buf = s.buf[:0] // reset len for reuse.
			s.strikethrough = false

			if err != nil {
				return 0, err
			}

		case magicStrikethrough:
			s.strikethrough = true

		default:
			s.buf = append(s.buf, c)
		}
	}
	return len(p), nil
}

var (
	// Use color red and the strikethrough escape
	beginStrikethrough = []byte("\033[9m\033[31m")
	endStrikethrough   = []byte("\033[0m")
	newline            = []byte("\n")
)

var _ io.Writer = &strikethroughWriter{}

func newTabWriter(out io.Writer) *tabwriter.Writer {
	const (
		minWidth = 5
		width    = 4
		padding  = 3
		padChar  = ' '
		flags    = tabwriter.RememberWidths
	)
	return tabwriter.NewWriter(out, minWidth, width, padding, padChar, flags)
}

// sortArgs sorts the arguments to bring '-arg' first. Allows mixing
// the argument order. If e.g. key starts with '-', then it'll just
// need to be quoted: "db/get foo '-mykey'"
func sortedArgs(args []string) []string {
	return slices.SortedStableFunc(
		slices.Values(args),
		func(a, b string) int {
			aIsArg := strings.HasPrefix(a, "-")
			bIsArg := strings.HasPrefix(b, "-")
			switch {
			case aIsArg && !bIsArg:
				return -1
			case bIsArg && !aIsArg:
				return 1
			default:
				return 0
			}
		},
	)
}

func underline(s string) string {
	return "\033[4m" + s + "\033[0m"
}
