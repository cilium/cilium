// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// cl2-report prints the measurements a ClusterLoader2 run left behind as a
// markdown table, compared against a baseline run when one is given.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

const (
	// Glob matching the Prometheus-backed measurements, which are the ones
	// holding numbers worth reporting. The others are raw command output.
	defaultPattern = "GenericPrometheusQuery*.json"

	// Measurement type the files are named after. It is the same for every
	// matched file, so it carries nothing for the reader.
	measurementType = "GenericPrometheusQuery"

	// Prefix the module puts on the name of an informational measurement.
	infoPrefix = "INFO - "

	missingValue = "-"

	// Deltas within this percentage are reported as possible noise.
	noiseThreshold = 10.0
)

// measurementFile is the subset of a ClusterLoader2 measurement file this tool reads.
type measurementFile struct {
	DataItems []struct {
		Data map[string]float64 `json:"data"`
		Unit string             `json:"unit"`
	} `json:"dataItems"`
}

type dataPoint struct {
	value float64
	unit  string
}

func (p dataPoint) reported() bool {
	return !math.IsNaN(p.value)
}

type measurement map[string]dataPoint

func (m measurement) at(name string) dataPoint {
	point, ok := m[name]
	if !ok {
		return dataPoint{value: math.NaN()}
	}
	return point
}

type measurements map[string]measurement

func main() {
	artifacts := flag.String("artifacts", "", "Directory holding the measurements of the run (required)")
	baselineArtifacts := flag.String("baseline-artifacts", "",
		"Directory holding the measurements to compare against. Adds a baseline and a delta column")
	pattern := flag.String("pattern", defaultPattern, "Glob selecting the measurements inside the artifact directories")
	verbose := flag.Bool("verbose", false, "Report measurements that are skipped while reading")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: go run ./tools/cl2-report [flags]\n")
		fmt.Fprintf(flag.CommandLine.Output(), "Writes the markdown table to stdout.\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *artifacts == "" {
		fmt.Fprintf(os.Stderr, "-artifacts is required\n\n")
		flag.Usage()
		os.Exit(1)
	}

	if err := run(os.Stdout, *artifacts, *baselineArtifacts, *pattern, *verbose); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}

func run(w io.Writer, artifacts, baselineArtifacts, pattern string, verbose bool) error {
	tested, err := load(artifacts, pattern, verbose)
	if err != nil {
		return err
	}
	baseline, err := load(baselineArtifacts, pattern, verbose)
	if err != nil {
		return err
	}

	if len(tested) == 0 && len(baseline) == 0 {
		fmt.Fprintf(os.Stderr, "::warning::no measurement matching %q found\n", pattern)
		return nil
	}

	printReport(w, tested, baseline)
	return nil
}

func load(dir, pattern string, verbose bool) (measurements, error) {
	result := measurements{}
	if dir == "" {
		return result, nil
	}

	paths, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		return nil, fmt.Errorf("globbing %q in %q: %w", pattern, dir, err)
	}

	for _, path := range paths {
		description := parseDescription(path)
		if _, ok := result[description]; ok {
			if verbose {
				fmt.Fprintf(os.Stderr, "::warning::skipping %q: measurement %q was already read from another file\n",
					path, description)
			}
			continue
		}

		data, err := readMeasurement(path)
		if err != nil {
			return nil, err
		}
		result[description] = data
	}
	return result, nil
}

// Format: <measurement type> <parseDescription>_<test name>_<timestamp>.json
func parseDescription(path string) string {
	stem := strings.TrimSuffix(filepath.Base(path), ".json")

	parts := strings.Split(stem, "_")
	if len(parts) < 3 {
		return stem
	}

	description := strings.Join(parts[:len(parts)-2], "_")
	description = strings.TrimSpace(strings.TrimPrefix(description, measurementType))
	if description == "" {
		return stem
	}
	return description
}

func readMeasurement(path string) (measurement, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %q: %w", path, err)
	}

	var file measurementFile
	if err := json.Unmarshal(content, &file); err != nil {
		return nil, fmt.Errorf("parsing %q: %w", path, err)
	}

	points := measurement{}
	for _, item := range file.DataItems {
		// TODO: handle the labels a data item can carry.
		for name, value := range item.Data {
			points[name] = dataPoint{value: value, unit: item.Unit}
		}
	}
	return points, nil
}

func printReport(w io.Writer, tested, baseline measurements) {
	printTable(w, tested, baseline, false)

	if slices.ContainsFunc(sortedKeys(tested, baseline), informational) {
		fmt.Fprint(w, "### Informational\n")
		printTable(w, tested, baseline, true)
	}
}

// informational reports whether the module marked the measurement as carrying
// context rather than a result.
func informational(description string) bool {
	return strings.HasPrefix(description, infoPrefix)
}

// printTable writes the measurements whose informational mark matches info.
func printTable(w io.Writer, tested, baseline measurements, info bool) {
	compare := len(baseline) > 0

	if compare {
		printRow(w, "Measurement", "Data point", "Test", "Baseline", "Delta (%)")
		printRow(w, "---", "---", "---:", "---:", "---:")
	} else {
		printRow(w, "Measurement", "Data point", "Value")
		printRow(w, "---", "---", "---:")
	}

	for _, description := range sortedKeys(tested, baseline) {
		if informational(description) != info {
			continue
		}

		dataPoints := tested[description]
		baselineDataPoints := baseline[description]

		measurementKey := fmt.Sprintf("**%s**", measurementLabel(description, dataPoints, baselineDataPoints))
		names := sortedKeys(dataPoints, baselineDataPoints)
		if len(names) == 0 {

			cells := []string{measurementKey, "no data points", missingValue}
			if compare {
				cells = append(cells, missingValue, missingValue)
			}
			printRow(w, cells...)
			continue
		}

		for i, name := range names {
			if i > 0 {
				measurementKey = ""
			}

			testData, baselineData := dataPoints.at(name), baselineDataPoints.at(name)
			cells := []string{measurementKey, fmt.Sprintf("*%s*", name), formatValue(testData)}
			if compare {
				// An informational delta is left uncoloured: with no better or
				// worse direction, a colour would only mislead.
				cells = append(cells, formatValue(baselineData), formatDelta(testData, baselineData, !info))
			}

			printRow(w, cells...)
		}
	}
	fmt.Fprintln(w)
}

func printRow(w io.Writer, cells ...string) {
	fmt.Fprintf(w, "| %s |\n", strings.Join(cells, " | "))
}

func measurementLabel(description string, points ...measurement) string {
	description = strings.TrimPrefix(description, infoPrefix)
	if u := measurementUnit(points...); u != "" {
		return description + " (" + u + ")"
	}
	return description
}

func measurementUnit(points ...measurement) string {
	for _, m := range points {
		for _, name := range slices.Sorted(maps.Keys(m)) {
			if u := m[name].unit; u != "" {
				return u
			}
		}
	}
	return ""
}

func formatValue(point dataPoint) string {
	if !point.reported() {
		return missingValue
	}
	if point.value == float64(int64(point.value)) {
		return strconv.FormatInt(int64(point.value), 10)
	}
	return strconv.FormatFloat(point.value, 'g', 4, 64)
}

// Every measurement that carries a result is assumed to be lower-is-better.
func formatDelta(value, baseline dataPoint, colored bool) string {
	if !value.reported() || !baseline.reported() {
		return missingValue
	}
	if baseline.value == 0 {
		// A change away from zero has no meaningful percentage.
		if value.value != 0 {
			return "n/a"
		}
		return "0.0"
	}

	delta := (value.value - baseline.value) / abs(baseline.value) * 100
	if abs(delta) < 0.1 {
		return "0.0"
	}

	s := fmt.Sprintf("%+.1f", delta)
	switch {
	case !colored:
		return s
	case abs(delta) <= noiseThreshold:
		return texBlue(s)
	case delta > 0:
		return texYellow(s)
	default:
		return texGreen(s)
	}
}

func texGreen(s string) string {
	return "$\\color{green}{\\textsf{" + s + "}}$"
}

func texYellow(s string) string {
	return "$\\color{yellow}{\\textsf{" + s + "}}$"
}

func texBlue(s string) string {
	return "$\\color{blue}{\\textsf{" + s + "}}$"
}

func abs(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}

func sortedKeys[V any](maps_ ...map[string]V) []string {
	union := map[string]struct{}{}
	for _, m := range maps_ {
		for key := range m {
			union[key] = struct{}{}
		}
	}
	return slices.Sorted(maps.Keys(union))
}
