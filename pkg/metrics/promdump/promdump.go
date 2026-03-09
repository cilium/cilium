// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package promdump

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
)

// DumpGatherer writes all metrics from a prometheus.Gatherer
// to a prometheus text-format file in the given output directory.
func DumpGatherer(appName string, outputDir string, outputSuffix string, newGatherer func() (prometheus.Gatherer, error)) error {
	if newGatherer == nil {
		return fmt.Errorf("gatherer constructor is nil")
	}
	if outputSuffix == "" {
		return fmt.Errorf("output suffix is empty")
	}

	g, err := newGatherer()
	if err != nil {
		return err
	}
	if g == nil {
		return fmt.Errorf("gatherer is nil")
	}

	outputFile := filepath.Join(outputDir, fmt.Sprintf("%s.%s", appName, outputSuffix))
	return dumpFromGatherer(g, outputFile)
}

func dumpFromGatherer(g prometheus.Gatherer, outputFile string) error {
	mfs, err := g.Gather()
	if err != nil {
		return fmt.Errorf("gather: %w", err)
	}
	sort.Slice(mfs, func(i, j int) bool { return mfs[i].GetName() < mfs[j].GetName() })

	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("creating file: %s: %w", outputFile, err)
	}
	defer f.Close()

	enc := expfmt.NewEncoder(f, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, mf := range mfs {
		if err := enc.Encode(mf); err != nil {
			return fmt.Errorf("encoding metric: %w", err)
		}
	}
	return nil
}
