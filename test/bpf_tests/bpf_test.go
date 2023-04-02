// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:generate protoc --go_out=. trf.proto
package bpftests

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/cilium/coverbee"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/davecgh/go-spew/spew"
	"github.com/golang/protobuf/proto"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/tools/cover"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/monitor"
)

var (
	testPath               = flag.String("bpf-test-path", "", "Path to the eBPF tests")
	testCoverageReport     = flag.String("coverage-report", "", "Specify a path for the coverage report")
	testCoverageFormat     = flag.String("coverage-format", "html", "Specify the format of the coverage report")
	noTestCoverage         = flag.String("no-test-coverage", "", "Don't collect coverages for the file matches to the given regex")
	testInstrumentationLog = flag.String("instrumentation-log", "", "Path to a log file containing details about"+
		" code coverage instrumentation, needed if code coverage breaks the verifier")

	dumpCtx = flag.Bool("dump-ctx", false, "If set, the program context will be dumped after a CHECK and SETUP run.")
)

func TestBPF(t *testing.T) {
	if testPath == nil || *testPath == "" {
		t.Skip("Set -bpf-test-path to run BPF tests")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Log(err)
	}

	entries, err := os.ReadDir(*testPath)
	if err != nil {
		t.Fatal("os readdir: ", err)
	}

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

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if !strings.HasSuffix(entry.Name(), ".o") {
			continue
		}

		t.Run(entry.Name(), func(t *testing.T) {
			profiles := loadAndRunSpec(t, entry, instrLog)
			for _, profile := range profiles {
				if len(profile.Blocks) > 0 {
					mergedProfiles = addProfile(mergedProfiles, profile)
				}
			}
		})
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

func loadAndRunSpec(t *testing.T, entry fs.DirEntry, instrLog io.Writer) []*cover.Profile {
	elfPath := path.Join(*testPath, entry.Name())

	if instrLog != nil {
		fmt.Fprintln(instrLog, "===", elfPath, "===")
	}

	spec := loadAndPrepSpec(t, elfPath)

	var (
		coll            *ebpf.Collection
		cfg             []*coverbee.BasicBlock
		err             error
		collectCoverage bool
	)

	if *testCoverageReport != "" {
		if *noTestCoverage != "" {
			matched, err := regexp.MatchString(*noTestCoverage, entry.Name())
			if err != nil {
				t.Fatal("test file regex matching failed:", err)
			}

			if matched {
				t.Logf("Disabling coverage report for %s", entry.Name())
			}

			collectCoverage = !matched
		} else {
			collectCoverage = true
		}
	}

	if !collectCoverage {
		coll, err = bpf.LoadCollection(spec, ebpf.CollectionOptions{})
	} else {
		coll, cfg, err = coverbee.InstrumentAndLoadCollection(spec, ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				// 64 MiB, not needed in most cases, except when running instrumented code.
				LogSize: 64 << 20,
			},
		}, instrLog)
	}

	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		if ve.Truncated {
			t.Fatal("Verifier log exceeds 64MiB, increase LogSize passed to coverbee.InstrumentAndLoadCollection")
		}
		t.Fatalf("verifier error: %+v", ve)
	}
	if err != nil {
		t.Fatal("loading collection:", err)
	}
	defer coll.Close()

	testNameToPrograms := make(map[string]programSet)

	for progName, spec := range spec.Programs {
		match := checkProgRegex.FindStringSubmatch(spec.SectionName)
		if len(match) == 0 {
			continue
		}

		progs := testNameToPrograms[match[1]]
		if match[2] == "pktgen" {
			progs.pktgenProg = coll.Programs[progName]
		}
		if match[2] == "setup" {
			progs.setupProg = coll.Programs[progName]
		}
		if match[2] == "check" {
			progs.checkProg = coll.Programs[progName]
		}
		testNameToPrograms[match[1]] = progs
	}

	for progName, set := range testNameToPrograms {
		if set.checkProg == nil {
			t.Fatalf(
				"File '%s' contains a setup program in section '%s' but no check program.",
				elfPath,
				spec.Programs[progName].SectionName,
			)
		}
	}

	// Collect debug events and add them as logs of the main test
	var globalLogReader *perf.Reader
	if m := coll.Maps["test_cilium_events"]; m != nil {
		globalLogReader, err = perf.NewReader(m, os.Getpagesize()*16)
		if err != nil {
			t.Fatalf("new global log reader: %s", err.Error())
		}
		defer globalLogReader.Close()

		linkCache := link.NewLinkCache()

		go func() {
			for {
				rec, err := globalLogReader.Read()
				if err != nil {
					return
				}

				dm := monitor.DebugMsg{}
				reader := bytes.NewReader(rec.RawSample)
				if err := binary.Read(reader, byteorder.Native, &dm); err != nil {
					return
				}

				t.Log(dm.Message(linkCache))
			}
		}()
	}

	// Make sure sub-tests are executed in alphabetic order, to make test results repeatable if programs rely on
	// the order of execution.
	testNames := make([]string, 0, len(testNameToPrograms))
	for name := range testNameToPrograms {
		testNames = append(testNames, name)
	}
	sort.Strings(testNames)

	// Get maps used for common mocking facilities
	skbMdMap := coll.Maps[mockSkbMetaMap]

	for _, name := range testNames {
		t.Run(name, subTest(testNameToPrograms[name], coll.Maps[suiteResultMap], skbMdMap))
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

func loadAndPrepSpec(t *testing.T, elfPath string) *ebpf.CollectionSpec {
	spec, err := bpf.LoadCollectionSpec(elfPath)
	if err != nil {
		t.Fatalf("load spec %s: %v", elfPath, err)
	}

	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}

	for n, p := range spec.Programs {
		switch p.Type {
		case ebpf.XDP, ebpf.SchedACT, ebpf.SchedCLS:
			continue
		}

		t.Logf("Skipping program '%s' of type '%s': BPF_PROG_RUN not supported", p.Name, p.Type)
		delete(spec.Programs, n)
	}

	return spec
}

type programSet struct {
	pktgenProg *ebpf.Program
	setupProg  *ebpf.Program
	checkProg  *ebpf.Program
}

var checkProgRegex = regexp.MustCompile(`[^/]+/test/([^/]+)/((?:check)|(?:setup)|(?:pktgen))`)

const (
	ResultSuccess = 1

	suiteResultMap = "suite_result_map"
	mockSkbMetaMap = "mock_skb_meta_map"
)

func subTest(progSet programSet, resultMap *ebpf.Map, skbMdMap *ebpf.Map) func(t *testing.T) {
	return func(t *testing.T) {
		// create ctx with the max allowed size(4k - head room - tailroom)
		ctx := make([]byte, 4096-256-320)

		if progSet.pktgenProg != nil {
			statusCode, result, err := progSet.pktgenProg.Test(ctx)
			if err != nil {
				t.Fatalf("error while running pktgen prog: %s", err)
			}

			if *dumpCtx {
				t.Log("Pktgen returned status: ")
				t.Log(statusCode)
				t.Log("Ctx after pktgen: ")
				t.Log(spew.Sdump(result))
			}

			ctx = result
		}

		if progSet.setupProg != nil {
			statusCode, result, err := progSet.setupProg.Test(ctx)
			if err != nil {
				t.Fatalf("error while running setup prog: %s", err)
			}

			if *dumpCtx {
				t.Log("Setup returned status: ")
				t.Log(statusCode)
				t.Log("Ctx after setup: ")
				t.Log(spew.Sdump(result))
			}

			ctx = make([]byte, len(result)+4)
			nl.NativeEndian().PutUint32(ctx, statusCode)
			copy(ctx[4:], result)
		}

		// Run test, input a
		statusCode, ctxOut, err := progSet.checkProg.Test(ctx)
		if err != nil {
			t.Fatal("error while running check program:", err)
		}

		if *dumpCtx {
			t.Log("Check returned status: ")
			t.Log(statusCode)
			t.Log("Ctx after check: ")
			t.Log(spew.Sdump(ctxOut))
		}

		// Clear map value after each test
		defer func() {
			for _, m := range []*ebpf.Map{resultMap, skbMdMap} {
				if m == nil {
					continue
				}

				var key int32
				value := make([]byte, m.ValueSize())
				m.Lookup(&key, &value)
				for i := 0; i < len(value); i++ {
					value[i] = 0
				}
				m.Update(&key, &value, ebpf.UpdateAny)
			}
		}()

		var key int32
		value := make([]byte, resultMap.ValueSize())
		err = resultMap.Lookup(&key, &value)
		if err != nil {
			t.Fatal("error while getting suite result:", err)
		}

		// Detect the length of the result, since the proto.Unmarshal doesn't like trailing zeros.
		valueLen := 0
		valueC := value
		for {
			_, _, len := protowire.ConsumeField(valueC)
			if len <= 0 {
				break
			}
			valueLen += len
			valueC = valueC[len:]
		}

		result := &SuiteResult{}
		err = proto.Unmarshal(value[:valueLen], result)
		if err != nil {
			t.Fatal("error while unmarshalling suite result:", err)
		}

		for _, testResult := range result.Results {
			// Remove the C-string, null-terminator.
			name := strings.TrimSuffix(testResult.Name, "\x00")
			t.Run(name, func(tt *testing.T) {
				if len(testResult.TestLog) > 0 && testing.Verbose() || testResult.Status != SuiteResult_TestResult_PASS {
					for _, log := range testResult.TestLog {
						tt.Logf("%s", log.FmtString())
					}
				}

				switch testResult.Status {
				case SuiteResult_TestResult_ERROR:
					tt.Fatal("Test failed due to unknown error in test framework")
				case SuiteResult_TestResult_FAIL:
					tt.Fail()
				case SuiteResult_TestResult_SKIP:
					tt.Skip()
				}
			})
		}

		if len(result.SuiteLog) > 0 && testing.Verbose() ||
			SuiteResult_TestResult_TestStatus(statusCode) != SuiteResult_TestResult_PASS {
			for _, log := range result.SuiteLog {
				t.Logf("%s", log.FmtString())
			}
		}

		switch SuiteResult_TestResult_TestStatus(statusCode) {
		case SuiteResult_TestResult_ERROR:
			t.Fatal("Test failed due to unknown error in test framework")
		case SuiteResult_TestResult_FAIL:
			t.Fail()
		case SuiteResult_TestResult_SKIP:
			t.SkipNow()
		}
	}
}

// A simplified version of fmt.Printf logic, the meaning of % specifiers changed to match the kernels printk specifiers.
// In the eBPF code a user can for example call `test_log("expected 123, got %llu", some_val)` the %llu meaning
// long-long-unsigned translates into a uint64, the rendered out would for example be -> 'expected 123, got 234'.
// https://www.kernel.org/doc/Documentation/printk-formats.txt
// https://github.com/libbpf/libbpf/blob/4eb6485c08867edaa5a0a81c64ddb23580420340/src/bpf_helper_defs.h#L152
func (l *Log) FmtString() string {
	var sb strings.Builder

	end := len(l.Fmt)
	argNum := 0

	for i := 0; i < end; {
		lasti := i
		for i < end && l.Fmt[i] != '%' {
			i++
		}
		if i > lasti {
			sb.WriteString(strings.TrimSuffix(l.Fmt[lasti:i], "\x00"))
		}
		if i >= end {
			// done processing format string
			break
		}

		// Process one verb
		i++

		var spec []byte
	loop:
		for ; i < end; i++ {
			c := l.Fmt[i]
			switch c {
			case 'd', 'i', 'u', 'x', 's':
				spec = append(spec, c)
				break loop
			case 'l':
				spec = append(spec, c)
			default:
				break loop
			}
		}
		// Advance to to next char
		i++

		// No argument left over to print for the current verb.
		if argNum >= len(l.Args) {
			sb.WriteString("%!")
			sb.WriteString(string(spec))
			sb.WriteString("(MISSING)")
			continue
		}

		switch string(spec) {
		case "u":
			fmt.Fprint(&sb, uint16(l.Args[argNum]))
		case "d", "i", "s":
			fmt.Fprint(&sb, int16(l.Args[argNum]))
		case "x":
			hb := make([]byte, 2)
			nl.NativeEndian().PutUint16(hb, uint16(l.Args[argNum]))
			fmt.Fprint(&sb, hex.EncodeToString(hb))

		case "lu":
			fmt.Fprint(&sb, uint32(l.Args[argNum]))
		case "ld", "li", "ls":
			fmt.Fprint(&sb, int32(l.Args[argNum]))
		case "lx":
			hb := make([]byte, 4)
			nl.NativeEndian().PutUint32(hb, uint32(l.Args[argNum]))
			fmt.Fprint(&sb, hex.EncodeToString(hb))

		case "llu":
			fmt.Fprint(&sb, uint64(l.Args[argNum]))
		case "lld", "lli", "lls":
			fmt.Fprint(&sb, int64(l.Args[argNum]))
		case "llx":
			hb := make([]byte, 8)
			nl.NativeEndian().PutUint64(hb, uint64(l.Args[argNum]))
			fmt.Fprint(&sb, hex.EncodeToString(hb))

		default:
			sb.WriteString("%!")
			sb.WriteString(string(spec))
			sb.WriteString("(INVALID)")
			continue
		}

		argNum++
	}

	return sb.String()
}
