// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// benchstat-diff turns the CSV output of benchstat into a markdown report and
// enforces thresholds on the reported deltas.
//
// It expects the CSV produced by a two-input A/B comparison, i.e.
//
//	benchstat -format csv base=base.txt pull=pull.txt
//
// Every metric benchstat reports is assumed to be lower-is-better, which holds
// for the units Go benchmarks emit (sec/op, B/op, allocs/op). A delta is
// therefore a regression when positive.
package main

import (
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
)

const (
	// Column header that marks the comparison column, and with it the row that
	// names the unit each table reports.
	vsBaseHeader = "vs base"

	// Row name benchstat gives the aggregate across all benchmarks. Reported
	// like any other row, but excluded from the thresholds: it is derived from
	// the rows above it rather than measured.
	geomeanRow = "geomean"

	// Delta benchstat reports when a change is indistinguishable from noise.
	noiseDelta = "~"
)

// verdict is how a single delta compares against the thresholds.
type verdict int

const (
	// verdictUnmeasured is a row benchstat reported as '~': there is no delta
	// to compare against anything.
	verdictUnmeasured verdict = iota
	verdictImproved
	verdictOK
	verdictWarn
	verdictFail
)

// thresholds are the percentage bands a delta is classified into. Kept
// together rather than passed as three bare float64s, which are easy to
// transpose at a call site.
type thresholds struct {
	improved float64
	warn     float64
	fail     float64
}

// row is one benchmark's result for one unit.
type row struct {
	name string
	unit string

	base float64
	pull float64

	// delta is the percentage change from base to pull. Only meaningful when
	// hasDelta is set; benchstat omits it for changes that are within noise.
	delta    float64
	hasDelta bool

	// note carries benchstat's p-value and sample count, e.g. "p=0.000 n=10".
	note string
}

func main() {
	improvedThreshold := flag.Float64("improved-threshold", -5, "Report a delta below this percentage as an improvement")
	warnThreshold := flag.Float64("warn-threshold", 10, "Warn when a delta regresses by more than this percentage")
	failThreshold := flag.Float64("fail-threshold", 25, "Fail when a delta regresses by more than this percentage")
	title := flag.String("title", "Go benchmarks", "Heading for the markdown report")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: go run ./tools/benchstat-diff [flags] <benchstat-csv>\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Reads stdin when no file is given.\n")
		flag.PrintDefaults()
	}

	flag.Parse()
	if flag.NArg() > 1 {
		flag.Usage()
		os.Exit(1)
	}

	limits := thresholds{improved: *improvedThreshold, warn: *warnThreshold, fail: *failThreshold}
	if limits.improved > limits.warn || limits.warn > limits.fail {
		fmt.Fprintf(os.Stderr, "-improved-threshold (%.2f), -warn-threshold (%.2f) and -fail-threshold (%.2f) "+
			"must be in ascending order\n", limits.improved, limits.warn, limits.fail)
		os.Exit(1)
	}

	in := io.Reader(os.Stdin)
	if flag.NArg() == 1 {
		file, err := os.Open(flag.Arg(0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(1)
		}
		defer file.Close()
		in = file
	}

	rows, err := parse(in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parsing benchstat csv: %s\n", err)
		os.Exit(1)
	}

	failed := report(os.Stdout, rows, *title, limits)
	if failed {
		os.Exit(1)
	}
}

// parse reads benchstat's CSV output. Each table starts with a row naming the
// input files and a row naming the unit, both of which have an empty first
// field; the rows after those are one benchmark each. Configuration lines such
// as "goos: linux" carry no comma and are skipped.
func parse(r io.Reader) ([]row, error) {
	reader := csv.NewReader(r)
	// Tables have different widths than the leading configuration lines, and a
	// comparison against more inputs is wider still.
	reader.FieldsPerRecord = -1

	var (
		rows     []row
		unit     string
		deltaIdx = -1
		pullIdx  = -1
	)

	for {
		rec, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}

		// A table header: find the comparison column, and take the unit from
		// the same row. The column layout can change between tables, so this
		// is re-read for each one rather than assumed.
		if idx := indexOf(rec, vsBaseHeader); idx >= 0 {
			if len(rec) < 2 {
				return nil, fmt.Errorf("unit row has %d fields, want at least 2", len(rec))
			}
			unit = rec[1]
			deltaIdx = idx
			// benchstat emits "<value>,<CI>" per input, so the second input's
			// value sits two fields after the first.
			pullIdx = 3
			continue
		}

		// Any other row with an empty first field is the row naming the input
		// files, which carries nothing this tool needs.
		if len(rec) == 0 || rec[0] == "" {
			continue
		}

		// Configuration lines, e.g. "goos: linux".
		if len(rec) == 1 {
			continue
		}

		if deltaIdx < 0 {
			return nil, fmt.Errorf("found benchmark row %q before any %q column; "+
				"benchstat needs two inputs to produce a comparison", rec[0], vsBaseHeader)
		}
		if deltaIdx >= len(rec) {
			return nil, fmt.Errorf("row %q has %d fields, want more than %d", rec[0], len(rec), deltaIdx)
		}

		row := row{
			name: rec[0],
			unit: unit,
			base: parseValue(rec, 1),
			pull: parseValue(rec, pullIdx),
		}
		row.delta, row.hasDelta = parseDelta(rec[deltaIdx])
		if deltaIdx+1 < len(rec) {
			row.note = rec[deltaIdx+1]
		}

		rows = append(rows, row)
	}

	if len(rows) == 0 {
		return nil, errors.New("no benchmark results found; the benchstat output may be empty " +
			"or its input may have been unparseable")
	}

	return rows, nil
}

func indexOf(rec []string, want string) int {
	for i, f := range rec {
		if f == want {
			return i
		}
	}
	return -1
}

func parseValue(rec []string, idx int) float64 {
	if idx >= len(rec) {
		return math.NaN()
	}
	v, err := strconv.ParseFloat(rec[idx], 64)
	if err != nil {
		return math.NaN()
	}
	return v
}

// parseDelta reads benchstat's comparison column, e.g. "+7.36%" or "~".
func parseDelta(s string) (float64, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == noiseDelta {
		return 0, false
	}
	v, err := strconv.ParseFloat(strings.TrimSuffix(strings.TrimPrefix(s, "+"), "%"), 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// classify maps a delta onto the thresholds, for colouring. Rows without a
// measured delta have nothing to compare.
func classify(r row, t thresholds) verdict {
	if !r.hasDelta {
		return verdictUnmeasured
	}
	switch {
	case r.delta < t.improved:
		return verdictImproved
	case r.delta > t.fail:
		return verdictFail
	case r.delta > t.warn:
		return verdictWarn
	default:
		return verdictOK
	}
}

// gated reports whether a row's verdict should count towards the exit status.
// The geomean row is coloured like any other but excluded here: it is derived
// from the rows above it, so gating on it would double-count them.
func gated(r row) bool {
	return r.name != geomeanRow
}

// report writes the markdown report and returns whether any delta breached the
// fail threshold.
func report(w io.Writer, rows []row, title string, t thresholds) bool {
	var warns, fails []row

	fmt.Fprintf(w, "## %s\n\n", title)
	fmt.Fprintf(w, "Deltas below %.0f%% are improvements, over %.0f%% warn, "+
		"over %.0f%% fail. A delta of `%s` means benchstat could not distinguish "+
		"the change from noise.\n\n",
		t.improved, t.warn, t.fail, noiseDelta)

	for _, unit := range units(rows) {
		fmt.Fprintf(w, "### %s\n\n", unit)
		fmt.Fprintln(w, "Benchmark | base | pull | vs base")
		fmt.Fprintln(w, "----------|------|------|--------")

		for _, r := range rows {
			if r.unit != unit {
				continue
			}

			v := classify(r, t)
			if gated(r) {
				switch v {
				case verdictWarn:
					warns = append(warns, r)
				case verdictFail:
					fails = append(fails, r)
				}
			}

			fmt.Fprintf(w, "%s | %s | %s | %s\n",
				r.name, formatValue(r.base), formatValue(r.pull), colorDelta(r, v))
		}
		fmt.Fprintln(w)
	}

	if len(fails) == 0 && len(warns) == 0 {
		fmt.Fprintf(w, "No benchmark regressed by more than %.0f%%.\n\n", t.warn)
	}
	listBreaches(w, "regressed by more than", t.fail, fails)
	listBreaches(w, "regressed by more than", t.warn, warns)

	// Mirror the breaches on stderr so they are visible in the step log: this
	// tool's stdout is redirected into the job summary.
	for _, r := range warns {
		fmt.Fprintf(os.Stderr, "::warning::%s %s regressed by %+.2f%%\n", r.name, r.unit, r.delta)
	}
	for _, r := range fails {
		fmt.Fprintf(os.Stderr, "::error::%s %s regressed by %+.2f%%\n", r.name, r.unit, r.delta)
	}

	return len(fails) > 0
}

func listBreaches(w io.Writer, what string, threshold float64, rows []row) {
	if len(rows) == 0 {
		return
	}

	fmt.Fprintf(w, "**%d benchmark%s %s %.0f%%:**\n\n", len(rows), plural(len(rows)), what, threshold)
	for _, r := range rows {
		fmt.Fprintf(w, "- `%s` %s: %+.2f%% (%s)\n", r.name, r.unit, r.delta, r.note)
	}
	fmt.Fprintln(w)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// units returns the units in the order benchstat reported them.
func units(rows []row) []string {
	var (
		order []string
		seen  = map[string]struct{}{}
	)
	for _, r := range rows {
		if _, ok := seen[r.unit]; ok {
			continue
		}
		seen[r.unit] = struct{}{}
		order = append(order, r.unit)
	}
	return order
}

// colorDelta renders a delta, coloured by how it compares to the thresholds.
func colorDelta(r row, v verdict) string {
	if !r.hasDelta {
		// Left outside a math span on purpose: '~' is a non-breaking space in
		// TeX, so it would render as an empty cell.
		return noiseDelta
	}

	// '\%' is the TeX escape for a literal percent sign; an unescaped '%' would
	// start a comment and swallow the rest of the span.
	s := fmt.Sprintf("%+.2f\\%%", r.delta)
	switch v {
	case verdictImproved:
		return texGreen(s)
	case verdictWarn:
		return texOrange(s)
	case verdictFail:
		return texRed(s)
	default:
		return texNoColor(s)
	}
}

func texNoColor(s string) string {
	return "$\\textsf{" + s + "}$"
}

func texGreen(s string) string {
	return "$\\color{green}{\\textsf{" + s + "}}$"
}

func texOrange(s string) string {
	return "$\\color{orange}{\\textsf{" + s + "}}$"
}

func texRed(s string) string {
	return "$\\color{red}{\\textsf{" + s + "}}$"
}

// siPrefixes are the prefixes formatValue scales into, smallest first, with the
// unscaled value in the middle.
var siPrefixes = []struct {
	exp    int
	prefix string
}{
	{-9, "n"}, {-6, "µ"}, {-3, "m"}, {0, ""}, {3, "k"}, {6, "M"}, {9, "G"},
}

// formatValue renders a benchstat value the way its text output does, scaled to
// an SI prefix so that seconds, bytes and counts all stay readable.
func formatValue(v float64) string {
	if math.IsNaN(v) {
		return "-"
	}
	if v == 0 {
		return "0"
	}

	abs := math.Abs(v)
	chosen := siPrefixes[len(siPrefixes)-1]
	for _, p := range siPrefixes {
		if abs < math.Pow(10, float64(p.exp+3)) {
			chosen = p
			break
		}
	}

	scaled := v / math.Pow(10, float64(chosen.exp))
	// Keep four significant digits, as benchstat does.
	switch {
	case math.Abs(scaled) < 10:
		return fmt.Sprintf("%.3f%s", scaled, chosen.prefix)
	case math.Abs(scaled) < 100:
		return fmt.Sprintf("%.2f%s", scaled, chosen.prefix)
	default:
		return fmt.Sprintf("%.1f%s", scaled, chosen.prefix)
	}
}
