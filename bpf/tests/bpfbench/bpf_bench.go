// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	bpftest "github.com/cilium/cilium/bpf/tests/bpftest"

	"github.com/cilium/cilium/pkg/bpf"
)

var (
	testPath       = flag.String("bpf-test-path", "", "Path to the eBPF tests")
	testFilePrefix = flag.String("test", "", "Single test file to run (without file extension)")
)

type benchmarkResult struct {
	testing.BenchmarkResult
	name string
}

func main() {
	flag.Parse()

	if testPath == nil || *testPath == "" {
		fmt.Fprintf(os.Stderr, "Set -bpf-test-path to run BPF benchmarks\n")
		os.Exit(1)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "Error removing memlock: %v", err)
	}

	var benchmarkResults []benchmarkResult
	logger := slog.Default()

	if err := bpftest.ForEachSuite(logger, *testPath, func(elfFile string, suiteSpec *ebpf.CollectionSpec) {
		elfPath := path.Join(*testPath, elfFile)

		if *testFilePrefix != "" && !strings.HasPrefix(elfFile, *testFilePrefix) {
			return
		}

		coll, _, err := bpf.LoadCollection(logger, suiteSpec, nil)

		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			fmt.Fprintf(os.Stderr, "Error loading collection from %s: verifier error: %+v\n", elfPath, err)
			return
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading collection from %s: %v\n", elfPath, err)
			return
		}

		defer coll.Close()

		suite, err := bpftest.CollectionToSuite(suiteSpec, coll)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading suite from %s: %v\n", elfPath, err)
			return
		}

		for _, test := range suite {
			if !test.HasBench() {
				continue
			}

			result, err := test.Bench()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Running suite '%s' from %s: %v\n", test.Name(), elfPath, err)
			}

			benchmarkResults = append(benchmarkResults, benchmarkResult{
				BenchmarkResult: result,
				name:            test.Name(),
			})
		}
	}); err != nil {
		fmt.Fprintf(os.Stderr, "Loading suites from %s: %v\n", *testPath, err)
		os.Exit(1)
	}

	for _, results := range benchmarkResults {
		fmt.Printf("%s\t%s\n", results.name, results.String())
	}
}
