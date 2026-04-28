// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"maps"
	"os"
	"slices"
	"sort"
)

const (
	// Verifier limits, for use when computing percentages associated with absolute values.
	MaxInsnsProcessed = 1_000_000
	MaxStackDepth     = 512
	MaxMapCount       = 64

	// Error and warning thresholds used for the linear (stack depth & map count) and exponential
	// (insns processed) metrics.
	ErrorThresholdLinearMetrics        = 90
	WarningThresholdLinearMetrics      = 75
	ErrorThresholdExponentialMetrics   = 70
	WarningThresholdExponentialMetrics = 50

	// Number of top values to display.
	NumberTopValues = 15
)

type verifierComplexityRecord struct {
	Kernel     string `json:"kernel"`
	Collection string `json:"collection"`
	Build      string `json:"build"`
	Load       string `json:"load"`
	Program    string `json:"program"`

	InsnsProcessed   int `json:"insns_processed"`
	MaxStatesPerInsn int `json:"max_states_per_insn"`
	TotalStates      int `json:"total_states"`
	PeakStates       int `json:"peak_states"`
	MarkRead         int `json:"mark_read"`

	VerificationTimeMicroseconds int `json:"verification_time_microseconds"`
	StackDepth                   int `json:"stack_depth"`

	MapCount int `json:"map_count"`
}

func main() {
	diffFile := flag.String("diff-file", "", "File to store the complexity diff")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: go run ./tools/complexity-diff [flags] <old> [new]\n")
		flag.PrintDefaults()
	}

	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(1)
	}

	oldFile := flag.Arg(0)

	oldRecords, err := loadRecords(oldFile)
	if err != nil {
		panic(err)
	}

	if flag.NArg() == 2 {
		newFile := flag.Arg(1)
		newRecords, err := loadRecords(newFile)
		if err != nil {
			panic(err)
		}

		printDiffRecords(oldRecords, newRecords)
		if *diffFile != "" {
			dumpDiffRecords(oldRecords, newRecords, *diffFile)
		}

		// If two files were given, then printCurrentState() should run on the second,
		// with the new records.
		oldRecords = newRecords
	}

	errors := printCurrentState(oldRecords)
	if len(errors) > 0 {
		fmt.Fprintf(os.Stderr, "Some programs are very close to the verifier limits:\n")
		for _, err := range errors {
			fmt.Fprintf(os.Stderr, "%s\n", err)
		}
		os.Exit(1)
	}
}

func printDiffRecords(oldRecords, newRecords map[string]verifierComplexityRecord) {
	diffRecords := calcDiffRecords(oldRecords, newRecords, true)

	minMaxInsnsProcessed := calcMinMax(diffRecords, func(r verifierComplexityRecord) int {
		return r.InsnsProcessed
	})
	printTopMinMax("largest differences by instructions processed", minMaxInsnsProcessed, percentInsnsProcessed, colorRelativeChange)

	minMaxStackDepth := calcMinMax(diffRecords, func(r verifierComplexityRecord) int {
		return r.StackDepth
	})
	printTopMinMax("largest differences by stack depth", minMaxStackDepth, percentStackDepth, colorRelativeChange)

	minMaxMapCount := calcMinMax(diffRecords, func(r verifierComplexityRecord) int {
		return r.MapCount
	})
	printTopMinMax("largest differences by map count", minMaxMapCount, percentMapCount, colorRelativeChange)
}

func printCurrentState(newRecords map[string]verifierComplexityRecord) []error {
	var sortedNewRecords []verifierComplexityRecord
	errors := make([]error, 0, len(newRecords)*3)

	for _, key := range slices.Sorted(maps.Keys(newRecords)) {
		sortedNewRecords = append(sortedNewRecords, newRecords[key])
	}

	minMaxInsnsProcessed := calcMinMax(sortedNewRecords, func(r verifierComplexityRecord) int {
		return r.InsnsProcessed
	})
	err := printTopMinMax("largest instructions processed", minMaxInsnsProcessed, percentInsnsProcessed, colorAbsoluteValueExponential)
	if len(err) > 0 {
		errors = append(errors, err...)
	}

	minMaxStackDepth := calcMinMax(sortedNewRecords, func(r verifierComplexityRecord) int {
		return r.StackDepth
	})
	err = printTopMinMax("largest stack depth", minMaxStackDepth, percentStackDepth, colorAbsoluteValue)
	if len(err) > 0 {
		errors = append(errors, err...)
	}

	minMaxMapCount := calcMinMax(sortedNewRecords, func(r verifierComplexityRecord) int {
		return r.MapCount
	})
	err = printTopMinMax("largest map count", minMaxMapCount, percentMapCount, colorAbsoluteValue)
	if len(err) > 0 {
		errors = append(errors, err...)
	}

	return errors
}

func dumpDiffRecords(oldRecords, newRecords map[string]verifierComplexityRecord, diffFile string) {
	diffRecords := calcDiffRecords(oldRecords, newRecords, false)

	// Sort diff records to be more logically grouped for human consumption, even though its JSON.
	sort.Slice(diffRecords, func(i, j int) bool {
		if diffRecords[i].Kernel != diffRecords[j].Kernel {
			return diffRecords[i].Kernel < diffRecords[j].Kernel
		}
		if diffRecords[i].Collection != diffRecords[j].Collection {
			return diffRecords[i].Collection < diffRecords[j].Collection
		}
		if diffRecords[i].Program != diffRecords[j].Program {
			return diffRecords[i].Program < diffRecords[j].Program
		}
		if diffRecords[i].Build != diffRecords[j].Build {
			return diffRecords[i].Build < diffRecords[j].Build
		}
		return diffRecords[i].Load < diffRecords[j].Load
	})

	file, err := os.Create(diffFile)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	bufWriter := bufio.NewWriter(file)
	defer bufWriter.Flush()

	encoder := json.NewEncoder(bufWriter)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(diffRecords)
	if err != nil {
		panic(err)
	}
}

func printTopMinMax(title string, minMaxes map[string]minMax, percentFn func(i int) float64,
	fmtFn func(s string, i int, p float64) (string, error)) []error {
	fmt.Printf("## Top %d %s\n", NumberTopValues, title)
	fmt.Println("Collection/Program | Min | Max")
	fmt.Println("-------------------|-----|----")
	errors := make([]error, 0, len(minMaxes))
	for i, key := range minMaxKeysSortAbs(minMaxes) {
		if i >= NumberTopValues {
			break
		}

		mm := minMaxes[key]
		minPercent := percentFn(mm.min)
		min, _ := fmtFn(mm.minKey, mm.min, minPercent)

		maxPercent := percentFn(mm.max)
		max, err := fmtFn(mm.maxKey, mm.max, maxPercent)

		fmt.Printf("%s | %s | %s\n", key, min, max)
		if err != nil {
			errors = append(errors, fmt.Errorf("%s for program %s: %w", title, key, err))
		}
	}
	fmt.Println()
	return errors
}

func percentInsnsProcessed(i int) float64 {
	return float64(i) / float64(MaxInsnsProcessed) * 100
}

func percentStackDepth(i int) float64 {
	return float64(i) / float64(MaxStackDepth) * 100
}

func percentMapCount(i int) float64 {
	return float64(i) / float64(MaxMapCount) * 100
}

func colorRelativeChange(program string, i int, p float64) (string, error) {
	s := fmt.Sprintf("%+d (%.2f\\\\%%) for %s", i, p, program)
	if p == 0 {
		return texNoColor(s), nil
	}

	if p < 0 {
		return texGreen(s), nil
	}

	return texRed(s), nil
}

func colorAbsoluteValue(program string, i int, p float64) (string, error) {
	s := fmt.Sprintf("%d (%.2f\\\\%%) for %s", i, p, program)
	if p > ErrorThresholdLinearMetrics {
		return texRed(s), fmt.Errorf("%s: %.2f%%", program, p)
	}
	if p > WarningThresholdLinearMetrics {
		return texOrange(s), nil
	}

	return texNoColor(s), nil
}

func colorAbsoluteValueExponential(program string, i int, p float64) (string, error) {
	s := fmt.Sprintf("%d (%.2f\\\\%%) for %s", i, p, program)
	if p > ErrorThresholdExponentialMetrics {
		return texRed(s), fmt.Errorf("%s: %.2f%%", program, p)
	}
	if p > WarningThresholdExponentialMetrics {
		return texOrange(s), nil
	}

	return texNoColor(s), nil
}

func texNoColor(s string) string {
	return "$\\textsf{" + s + "}$"
}

func texGreen(s string) string {
	return "$\\color{green}{\\textsf{" + s + "}}$"
}

func texRed(s string) string {
	return "$\\color{red}{\\textsf{" + s + "}}$"
}

func texOrange(s string) string {
	return "$\\color{orange}{\\textsf{" + s + "}}$"
}

type minMax struct {
	minKey string
	min    int
	maxKey string
	max    int
}

func calcMinMax(records []verifierComplexityRecord, metric func(r verifierComplexityRecord) int) map[string]minMax {
	minMaxRecords := map[string]minMax{}
	for _, r := range records {
		mm, ok := minMaxRecords[collectionProgramKey(r)]
		if !ok {
			mm = minMax{
				min:    metric(r),
				minKey: kernelBuildLoadKey(r),
				max:    metric(r),
				maxKey: kernelBuildLoadKey(r),
			}
		}
		if metric(r) < mm.min {
			mm.minKey = kernelBuildLoadKey(r)
			mm.min = metric(r)
		}
		if metric(r) > mm.max {
			mm.maxKey = kernelBuildLoadKey(r)
			mm.max = metric(r)
		}
		minMaxRecords[collectionProgramKey(r)] = mm
	}

	return minMaxRecords
}

func minMaxKeysSortAbs(minMaxes map[string]minMax) []string {
	keys := slices.Sorted(maps.Keys(minMaxes))
	slices.SortStableFunc(keys, func(a, b string) int {
		absMinA := minMaxes[a].min
		if absMinA < 0 {
			absMinA = -absMinA
		}
		absMaxA := minMaxes[a].max
		if absMaxA < 0 {
			absMaxA = -absMaxA
		}
		absA := absMinA + absMaxA

		absMinB := minMaxes[b].min
		if absMinB < 0 {
			absMinB = -absMinB
		}
		absMaxB := minMaxes[b].max
		if absMaxB < 0 {
			absMaxB = -absMaxB
		}
		absB := absMinB + absMaxB

		return absB - absA
	})
	return keys
}

func calcDiffRecords(oldRecords, newRecords map[string]verifierComplexityRecord, onlyChange bool) []verifierComplexityRecord {
	diffRecords := make([]verifierComplexityRecord, 0)
	for _, key := range slices.Sorted(maps.Keys(newRecords)) {
		newRecord := newRecords[key]
		oldRecord, ok := oldRecords[key]
		if !ok {
			if onlyChange {
				continue
			}

			diffRecords = append(diffRecords, newRecord)
			continue
		}

		diffRecords = append(diffRecords, verifierComplexityRecord{
			Kernel:     newRecord.Kernel,
			Collection: newRecord.Collection,
			Build:      newRecord.Build,
			Load:       newRecord.Load,
			Program:    newRecord.Program,

			InsnsProcessed:   newRecord.InsnsProcessed - oldRecord.InsnsProcessed,
			MaxStatesPerInsn: newRecord.MaxStatesPerInsn - oldRecord.MaxStatesPerInsn,
			TotalStates:      newRecord.TotalStates - oldRecord.TotalStates,
			PeakStates:       newRecord.PeakStates - oldRecord.PeakStates,
			MarkRead:         newRecord.MarkRead - oldRecord.MarkRead,

			VerificationTimeMicroseconds: newRecord.VerificationTimeMicroseconds - oldRecord.VerificationTimeMicroseconds,
			StackDepth:                   newRecord.StackDepth - oldRecord.StackDepth,

			MapCount: newRecord.MapCount - oldRecord.MapCount,
		})
	}

	if !onlyChange {
		for key, oldRecord := range oldRecords {
			_, ok := newRecords[key]
			if !ok {
				diffRecords = append(diffRecords, verifierComplexityRecord{
					Kernel:     oldRecord.Kernel,
					Collection: oldRecord.Collection,
					Build:      oldRecord.Build,
					Load:       oldRecord.Load,
					Program:    oldRecord.Program,

					InsnsProcessed:   -oldRecord.InsnsProcessed,
					MaxStatesPerInsn: -oldRecord.MaxStatesPerInsn,
					TotalStates:      -oldRecord.TotalStates,
					PeakStates:       -oldRecord.PeakStates,
					MarkRead:         -oldRecord.MarkRead,

					VerificationTimeMicroseconds: -oldRecord.VerificationTimeMicroseconds,
					StackDepth:                   -oldRecord.StackDepth,

					MapCount: -oldRecord.MapCount,
				})
			}
		}
	}

	return diffRecords
}

func recordKey(r verifierComplexityRecord) string {
	return r.Kernel + "/" + r.Collection + "/" + r.Program + "/" + r.Build + "/" + r.Load
}

func collectionProgramKey(r verifierComplexityRecord) string {
	return r.Collection + "/" + r.Program
}

func kernelBuildLoadKey(r verifierComplexityRecord) string {
	if r.Kernel == "" {
		return r.Build + "/" + r.Load
	}

	return r.Kernel + "/" + r.Build + "/" + r.Load
}

func loadRecords(path string) (map[string]verifierComplexityRecord, error) {
	var records []verifierComplexityRecord
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(bufio.NewReader(file))
	err = decoder.Decode(&records)
	if err != nil {
		return nil, err
	}

	recordMap := make(map[string]verifierComplexityRecord)
	for _, record := range records {
		recordMap[recordKey(record)] = record
	}
	return recordMap, nil
}
