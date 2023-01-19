// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build privileged_tests

//go:generate protoc --go_out=. trf.proto
package bpftests

import (
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
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/golang/protobuf/proto"
	"github.com/vishvananda/netlink/nl"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/datapath/link"
	"github.com/cilium/cilium/pkg/monitor"
)

var testPath = flag.String("bpf-test-path", "", "Path to the eBPF tests")

func TestBPF(t *testing.T) {
	if testPath == nil || *testPath == "" {
		t.Fatal("-bpf-test-path is a required flag")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Log(err)
	}

	entries, err := os.ReadDir(*testPath)
	if err != nil {
		t.Fatal("os readdir: ", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if !strings.HasSuffix(entry.Name(), ".o") {
			continue
		}

		loadAndRunSpec(t, entry)
	}
}

func loadAndRunSpec(t *testing.T, entry fs.DirEntry) {
	elfPath := path.Join(*testPath, entry.Name())
	spec := loadAndPrepSpec(t, elfPath)

	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSize: 4 << 20, // 4 MiB
		},
	})
	if err != nil {
		// Use this definition of ENOSPC instead of syscall.ENOSPC, since the stdlib constant is only
		// available on linux. Even if this doesn't run, we still want it to compile on non-linux systems.
		const ENOSPC = syscall.Errno(0x1c)
		// ENOSPC usually means that the log size was to small, so increase and retry.
		if errors.Is(err, ENOSPC) {
			t.Fatal("Verifier logs larger than 4MiB, increase the log size passed to ebpf.NewCollectionWithOptions " +
				"or decrease the size/complexity of the program")
		}

		t.Fatal("new coll:", err)
	}
	defer coll.Close()

	err = loadCallsMap(spec, coll)
	if err != nil {
		t.Fatal(err)
	}

	testNameToPrograms := make(map[string]programSet)

	for progName, spec := range spec.Programs {
		match := checkProgRegex.FindStringSubmatch(spec.SectionName)
		if len(match) == 0 {
			continue
		}

		progs := testNameToPrograms[match[1]]
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

	for name, progs := range testNameToPrograms {
		t.Run(name, subTest(progs, coll.Maps[suiteResultMap]))
	}

	if globalLogReader != nil {
		// Give the global log buf some time to empty
		// TODO: replace with flush on the buffer, as soon as cilium/ebpf supports that
		time.Sleep(50 * time.Millisecond)
	}
}

func loadAndPrepSpec(t *testing.T, elfPath string) *ebpf.CollectionSpec {
	spec, err := ebpf.LoadCollectionSpec(elfPath)
	if err != nil {
		t.Fatal("load spec: ", elfPath, err)
	}

	for _, mspec := range spec.Maps {
		// Drain extra info from map specs, cilium/ebpf will complain if we don't
		if mspec.Extra != nil {
			io.ReadAll(mspec.Extra)
		}

		mspec.Pinning = ebpf.PinNone
	}

	var progTestType ebpf.ProgramType
	for progName, prog := range spec.Programs {
		switch prog.Type {
		case ebpf.XDP, ebpf.SchedACT, ebpf.SchedCLS:
		case ebpf.UnspecifiedProgram:
		default:
			t.Logf(
				"program '%s' has program type '%s' which doesn't have BPF_PROG_RUN support, not loading it",
				prog.Name,
				prog.Type,
			)
			delete(spec.Programs, progName)
			continue
		}

		if progTestType != prog.Type {
			if progTestType == ebpf.UnspecifiedProgram {
				progTestType = prog.Type
				continue
			}
			if prog.Type == ebpf.UnspecifiedProgram {
				continue
			}

			t.Fatalf(
				"File '%s' contains both '%s' and '%s' program types, "+
					"only one program type per ELF file allowed:",
				elfPath,
				progTestType,
				prog.Type,
			)
		}
	}

	if progTestType == ebpf.UnspecifiedProgram {
		t.Fatalf("File '%s' only contains unspecified program types", elfPath)
	}

	// Give all tail call programs the same program type as the test programs
	for _, spec := range spec.Programs {
		spec.Type = progTestType
	}

	return spec
}

// Fill the tail calls map with the tail calls based on the calls .id and names of the program sections.
func loadCallsMap(spec *ebpf.CollectionSpec, coll *ebpf.Collection) error {
	callMap, found := coll.Maps[callsMapName]
	if !found {
		// If we can't find the map, tailcalls aren't required for the current tests
		return nil
	}

	for name, prog := range coll.Programs {
		if strings.HasPrefix(spec.Programs[name].SectionName, callsMapID) {
			indexStr := strings.TrimPrefix(spec.Programs[name].SectionName, callsMapID)
			index, err := strconv.Atoi(indexStr)
			if err != nil {
				return fmt.Errorf("atoi tail call index: %w", err)
			}

			index32 := uint32(index)
			err = callMap.Update(&index32, prog, ebpf.UpdateAny)
			if err != nil {
				return fmt.Errorf("update tailcall map: %w", err)
			}
		}
	}

	return nil
}

type programSet struct {
	setupProg *ebpf.Program
	checkProg *ebpf.Program
}

var checkProgRegex = regexp.MustCompile(`[^/]+/test/([^/]+)/((?:check)|(?:setup))`)

const (
	ResultSuccess = 1

	suiteResultMap = "suite_result_map"

	callsMapName = "test_cilium_calls_65535"
	// TODO we should read the .id field from the maps BTF, but the current cilium/ebpf version doesn't make the raw
	// map BTF available.
	callsMapID = "2/"
)

func subTest(progSet programSet, resultMap *ebpf.Map) func(t *testing.T) {
	return func(t *testing.T) {
		// create ctx with the max allowed size(4k - head room - tailroom)
		ctx := make([]byte, 4096-256-320)

		if progSet.setupProg != nil {
			statusCode, result, err := progSet.setupProg.Test(ctx)
			if err != nil {
				t.Fatalf("error while running setup prog: %s", err)
			}

			ctx = make([]byte, len(result)+4)
			nl.NativeEndian().PutUint32(ctx, statusCode)
			copy(ctx[4:], result)
		}

		// Run test, input a
		statusCode, _, err := progSet.checkProg.Test(ctx)
		if err != nil {
			t.Fatal("error while running check program:", err)
		}

		// Clear map value after each test
		defer func() {
			var key int32
			value := make([]byte, resultMap.ValueSize())
			resultMap.Lookup(&key, &value)
			for i := 0; i < len(value); i++ {
				value[i] = 0
			}
			resultMap.Update(&key, &value, ebpf.UpdateAny)
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

type suiteTestResult struct {
	name string
	logs []testLog
	code byte
}

type testLog struct {
	fmt  string
	args []uint64
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
