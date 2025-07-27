// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:generate protoc --go_out=. trf.proto
package bpftests

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/cilium/coverbee"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"golang.org/x/tools/cover"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/maps/eventsmap"
	"github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/monitor/format"
)

var (
	testPath               = flag.String("bpf-test-path", "", "Path to the eBPF tests")
	testCoverageReport     = flag.String("coverage-report", "", "Specify a path for the coverage report")
	testCoverageFormat     = flag.String("coverage-format", "html", "Specify the format of the coverage report")
	noTestCoverage         = flag.String("no-test-coverage", "", "Don't collect coverages for the file matches to the given regex")
	testInstrumentationLog = flag.String("instrumentation-log", "", "Path to a log file containing details about"+
		" code coverage instrumentation, needed if code coverage breaks the verifier")
	testFilePrefix = flag.String("test", "", "Single test file to run (without file extension)")

	dumpCtx = flag.Bool("dump-ctx", false, "If set, the program context will be dumped after a CHECK and SETUP run.")
)

type testLogWriter struct {
	t *testing.T
}

func (w *testLogWriter) Write(p []byte) (n int, err error) {
	// use the formatted output to avoid the new line
	w.t.Logf("%s", string(p))
	return len(p), nil
}

func TestBPF(t *testing.T) {
	if testPath == nil || *testPath == "" {
		t.Skip("Set -bpf-test-path to run BPF tests")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Log(err)
	}

	logger := hivetest.Logger(t)

	var instrLog io.Writer
	if *testInstrumentationLog != "" {
		instrLogFile, err := os.Create(*testInstrumentationLog)
		if err != nil {
			t.Fatal("os create instrumentation log: ", err)
		}
		defer instrLogFile.Close()

		buf := bufio.NewWriter(instrLogFile)
		instrLog = buf
		defer buf.Flush()
	}
	mergedProfiles := make([]*cover.Profile, 0)

	if err := ForEachSuite(logger, *testPath, func(elfFile string, suiteSpec *ebpf.CollectionSpec) {
		if *testFilePrefix != "" && !strings.HasPrefix(elfFile, *testFilePrefix) {
			return
		}

		t.Run(elfFile, func(t *testing.T) {
			profiles := loadAndRunSpec(t, elfFile, suiteSpec, instrLog)
			for _, profile := range profiles {
				if len(profile.Blocks) > 0 {
					mergedProfiles = addProfile(mergedProfiles, profile)
				}
			}
		})
	}); err != nil {
		t.Fatal(err)
	}

	if *testCoverageReport != "" {
		coverReport, err := os.Create(*testCoverageReport)
		if err != nil {
			t.Fatalf("create coverage report: %s", err.Error())
		}
		defer coverReport.Close()

		switch *testCoverageFormat {
		case "html":
			if err = coverbee.HTMLOutput(mergedProfiles, coverReport); err != nil {
				t.Fatalf("create HTML coverage report: %s", err.Error())
			}
		case "go-cover", "cover":
			coverbee.ProfilesToGoCover(mergedProfiles, coverReport, "count")
		default:
			t.Fatal("unknown output format")
		}
	}
}

func loadAndRunSpec(t *testing.T, elfFile string, spec *ebpf.CollectionSpec, instrLog io.Writer) []*cover.Profile {
	logger := hivetest.Logger(t)
	elfPath := path.Join(*testPath, elfFile)

	if instrLog != nil {
		fmt.Fprintln(instrLog, "===", elfPath, "===")
	}

	var (
		coll            *ebpf.Collection
		cfg             []*coverbee.BasicBlock
		err             error
		collectCoverage bool
	)

	if *testCoverageReport != "" {
		if *noTestCoverage != "" {
			matched, err := regexp.MatchString(*noTestCoverage, elfFile)
			if err != nil {
				t.Fatal("test file regex matching failed:", err)
			}

			if matched {
				t.Logf("Disabling coverage report for %s", elfFile)
			}

			collectCoverage = !matched
		} else {
			collectCoverage = true
		}
	}

	if !collectCoverage {
		coll, _, err = bpf.LoadCollection(logger, spec, nil)
	} else {
		coll, cfg, err = coverbee.InstrumentAndLoadCollection(spec, ebpf.CollectionOptions{}, instrLog)
	}

	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		t.Fatalf("verifier error: %+v", ve)
	}
	if err != nil {
		t.Fatal("loading collection:", err)
	}
	defer coll.Close()

	suite, err := CollectionToSuite(spec, coll)
	if err != nil {
		t.Fatalf("File '%s': %v", elfPath, err)
	}

	// Collect debug events and add them as logs of the main test
	var globalLogReader *perf.Reader
	if m := coll.Maps[eventsmap.MapName]; m != nil {
		globalLogReader, err = perf.NewReader(m, os.Getpagesize()*16)
		if err != nil {
			t.Fatalf("new global log reader: %s", err.Error())
		}
		defer globalLogReader.Close()

		formatter := format.NewMonitorFormatter(api.DEBUG, link.NewLinkCache(), &testLogWriter{t: t})
		go func() {
			for {
				rec, err := globalLogReader.Read()
				if err != nil {
					return
				}
				formatter.FormatSample(rec.RawSample, rec.CPU)
			}
		}()
	}

	for _, test := range suite {
		if !test.HasCheck() {
			continue
		}

		t.Run(test.Name(), func(t *testing.T) {
			test.Check(t, *dumpCtx)
		})
	}

	if globalLogReader != nil {
		// Give the global log buf some time to empty
		// TODO: replace with flush on the buffer, as soon as cilium/ebpf supports that
		time.Sleep(50 * time.Millisecond)
	}

	if !collectCoverage {
		return nil
	}

	blocklist := coverbee.CFGToBlockList(cfg)
	if err = coverbee.ApplyCoverMapToBlockList(coll.Maps["coverbee_covermap"], blocklist); err != nil {
		t.Fatalf("apply covermap to blocklist: %s", err.Error())
	}

	outBlocks, err := coverbee.SourceCodeInterpolation(blocklist, nil)
	if err != nil {
		t.Fatalf("error while interpolating using source files: %s", err)
	}

	var buf bytes.Buffer
	coverbee.BlockListToGoCover(outBlocks, &buf, "count")
	profiles, err := cover.ParseProfilesFromReader(&buf)
	if err != nil {
		t.Fatalf("parse profiles: %s", err.Error())
	}

	return profiles
}
