// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"slices"
	"sort"
)

type verifierComplexityRecord struct {
	Kernel     string `json:"kernel"`
	Collection string `json:"collection"`
	Build      string `json:"build"`
	Load       string `json:"load"`
	Program    string `json:"program"`

	InsnsProcessed   int `json:"insns_processed"`
	InsnsLimit       int `json:"insns_limit"`
	MaxStatesPerInsn int `json:"max_states_per_insn"`
	TotalStates      int `json:"total_states"`
	PeakStates       int `json:"peak_states"`
	MarkRead         int `json:"mark_read"`

	VerificationTimeMicroseconds int `json:"verification_time_microseconds"`
	StackDepth                   int `json:"stack_depth"`
}

func main() {
	if len(os.Args) != 4 {
		panic("usage: complexity-diff <old> <new> <diff>")
	}

	oldFile := os.Args[1]
	newFile := os.Args[2]
	diffFile := os.Args[3]

	oldRecords, err := loadRecords(oldFile)
	if err != nil {
		panic(err)
	}
	newRecords, err := loadRecords(newFile)
	if err != nil {
		panic(err)
	}

	diffRecords := calcDiffRecords(oldRecords, newRecords, true)

	minMaxInsnsProcessed := calcMinMax(diffRecords, func(r verifierComplexityRecord) int {
		return r.InsnsProcessed
	})
	printTop15MinMax("largest differences by instructions processed", minMaxInsnsProcessed, percentInsnsProcessed, colorRelativeChange)

	minMaxStackDepth := calcMinMax(diffRecords, func(r verifierComplexityRecord) int {
		return r.StackDepth
	})
	printTop15MinMax("largest differences by stack depth", minMaxStackDepth, percentStackDepth, colorRelativeChange)

	var sortedNewRecords []verifierComplexityRecord
	for _, key := range slices.Sorted(maps.Keys(newRecords)) {
		sortedNewRecords = append(sortedNewRecords, newRecords[key])
	}

	minMaxInsnsProcessed = calcMinMax(sortedNewRecords, func(r verifierComplexityRecord) int {
		return r.InsnsProcessed
	})
	printTop15MinMax("largest instructions processed", minMaxInsnsProcessed, percentInsnsProcessed, colorAbsoluteValue)

	minMaxStackDepth = calcMinMax(sortedNewRecords, func(r verifierComplexityRecord) int {
		return r.StackDepth
	})
	printTop15MinMax("largest stack depth", minMaxStackDepth, percentStackDepth, colorAbsoluteValue)

	diffRecords = calcDiffRecords(oldRecords, newRecords, false)

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

func printTop15MinMax(title string, minMaxes map[string]minMax, percentFn func(i int) float64, fmtFn func(s string, i int, p float64) string) {
	fmt.Printf("## Top 15 %s\n", title)
	fmt.Println("Collection/Program | Min | Max")
	fmt.Println("-------------------|-----|----")
	for i, key := range minMaxKeysSortAbs(minMaxes) {
		if i >= 15 {
			break
		}

		mm := minMaxes[key]
		minPercent := percentFn(mm.min)
		min := fmtFn(mm.minKey, mm.min, minPercent)

		maxPercent := percentFn(mm.max)
		max := fmtFn(mm.maxKey, mm.max, maxPercent)

		fmt.Printf("%s | %s | %s\n", key, min, max)
	}
	fmt.Println()
}

func percentInsnsProcessed(i int) float64 {
	return float64(i) / float64(1_000_000) * 100
}

func percentStackDepth(i int) float64 {
	return float64(i) / float64(512) * 100
}

func colorRelativeChange(program string, i int, p float64) string {
	s := fmt.Sprintf("%s %+d (%.2f\\\\%%)", program, i, p)
	if p == 0 {
		return texNoColor(s)
	}

	if p < 0 {
		return texGreen(s)
	}

	return texRed(s)
}

func colorAbsoluteValue(program string, i int, p float64) string {
	s := fmt.Sprintf("%s %d (%.2f\\\\%%)", program, i, p)
	if p > 80 {
		return texRed(s)
	}

	return texGreen(s)
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
			InsnsLimit:       newRecord.InsnsLimit - oldRecord.InsnsLimit,
			MaxStatesPerInsn: newRecord.MaxStatesPerInsn - oldRecord.MaxStatesPerInsn,
			TotalStates:      newRecord.TotalStates - oldRecord.TotalStates,
			PeakStates:       newRecord.PeakStates - oldRecord.PeakStates,
			MarkRead:         newRecord.MarkRead - oldRecord.MarkRead,

			VerificationTimeMicroseconds: newRecord.VerificationTimeMicroseconds - oldRecord.VerificationTimeMicroseconds,
			StackDepth:                   newRecord.StackDepth - oldRecord.StackDepth,
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
					InsnsLimit:       -oldRecord.InsnsLimit,
					MaxStatesPerInsn: -oldRecord.MaxStatesPerInsn,
					TotalStates:      -oldRecord.TotalStates,
					PeakStates:       -oldRecord.PeakStates,
					MarkRead:         -oldRecord.MarkRead,

					VerificationTimeMicroseconds: -oldRecord.VerificationTimeMicroseconds,
					StackDepth:                   -oldRecord.StackDepth,
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
