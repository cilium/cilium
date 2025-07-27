// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpftests

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/vishvananda/netlink/nl"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/bpf"
)

const (
	ResultSuccess = 1

	suiteResultMap = "suite_result_map"
	mockSkbMetaMap = "mock_skb_meta_map"
)

// ForEachSuite iterates through each *.o file in dir, loads it as an
// ebpf.CollectionSpec, unpins any maps in the ebpf.CollectionSpec, then passes
// the file name and the final CollectionSpecit to fn for further processing.
func ForEachSuite(logger *slog.Logger, dir string, fn func(name string, suiteSpec *ebpf.CollectionSpec)) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("reading dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		if !strings.HasSuffix(entry.Name(), ".o") {
			continue
		}

		spec, err := loadAndPrepSuiteSpec(logger, path.Join(dir, entry.Name()))
		if err != nil {
			return fmt.Errorf("loading and prepping spec: %w", err)
		}

		fn(entry.Name(), spec)
	}

	return nil
}

func loadAndPrepSuiteSpec(logger *slog.Logger, elfPath string) (*ebpf.CollectionSpec, error) {
	spec, err := bpf.LoadCollectionSpec(logger, elfPath)
	if err != nil {
		return nil, fmt.Errorf("load spec %s: %w", elfPath, err)
	}

	for _, m := range spec.Maps {
		m.Pinning = ebpf.PinNone
	}

	for n, p := range spec.Programs {
		switch p.Type {
		case ebpf.XDP, ebpf.SchedACT, ebpf.SchedCLS:
			continue
		}

		delete(spec.Programs, n)
	}

	return spec, nil
}

var progRegex = regexp.MustCompile(`[^/]+/test/([^/]+)/((?:check)|(?:bench)|(?:setup)|(?:pktgen))`)

// CollectionToSuite converts spec and coll into a final set of tests while
// performing some validation:
//
// 1. Each test must contain a CHECK or BENCH program.
// 2. Each test must contain at most one PKTGEN/SETUP/CHECK/BENCH program.
//
// It sorts the tests alphabetically based on their name.
func CollectionToSuite(spec *ebpf.CollectionSpec, coll *ebpf.Collection) ([]Test, error) {
	tests := map[string]Test{}

	duplicateProgram := func(testName, progType string) error {
		return fmt.Errorf("contains duplicate %s programs for the '%s' test", progType, testName)
	}

	for progName, spec := range spec.Programs {
		match := progRegex.FindStringSubmatch(spec.SectionName)
		if len(match) == 0 {
			continue
		}

		test := tests[match[1]]
		if match[2] == "pktgen" {
			if test.pktgenProg != nil {
				return nil, duplicateProgram(match[1], match[2])
			}
			test.pktgenProg = coll.Programs[progName]
		}
		if match[2] == "setup" {
			if test.setupProg != nil {
				return nil, duplicateProgram(match[1], match[2])
			}
			test.setupProg = coll.Programs[progName]
		}
		if match[2] == "check" {
			if test.checkProg != nil {
				return nil, duplicateProgram(match[1], match[2])
			}
			test.checkProg = coll.Programs[progName]
		}
		if match[2] == "bench" {
			if test.benchProg != nil {
				return nil, duplicateProgram(match[1], match[2])
			}
			test.benchProg = coll.Programs[progName]
		}
		tests[match[1]] = test
	}

	for testName, test := range tests {
		if test.checkProg == nil && test.benchProg == nil {
			return nil, fmt.Errorf("does not contain a check or bench program for the '%s' test", testName)
		}
	}

	suite := make([]Test, len(tests))

	// Make sure sub-tests are executed in alphabetic order, to make test
	// results repeatable if programs rely on the order of execution.
	for i, name := range slices.Sorted(maps.Keys(tests)) {
		test := tests[name]
		test.name = name
		test.maps = coll.Maps
		suite[i] = test
	}

	return suite, nil
}

// Test represents a single BPF unit test.
type Test struct {
	name       string
	maps       map[string]*ebpf.Map
	pktgenProg *ebpf.Program
	setupProg  *ebpf.Program
	checkProg  *ebpf.Program
	benchProg  *ebpf.Program
}

// Name returns the name of the unit test.
//
// Example: CHECK("tc", "my_test") will return "my_test" as the name.
func (tt *Test) Name() string {
	return tt.name
}

// HasCheck returns true if this BPF unit test contains a CHECK program.
func (tt *Test) HasCheck() bool {
	return tt.checkProg != nil
}

// Check runs the PKTGEN, SETUP, and CHECK programs for a BPF unit test.
func (tt *Test) Check(t *testing.T, dumpCtx bool) {
	resultMap := tt.maps[suiteResultMap]
	skbMdMap := tt.maps[mockSkbMetaMap]
	// create ctx with the max allowed size(4k - head room - tailroom)
	data := make([]byte, 4096-256-320)

	// ctx is only used for tc programs
	// non-empty ctx passed to non-tc programs will cause error: invalid argument
	ctx := make([]byte, 0)
	if tt.checkProg.Type() == ebpf.SchedCLS {
		// sizeof(struct __sk_buff) < 256, let's make it 256
		ctx = make([]byte, 256)
	}

	var (
		statusCode uint32
		err        error
	)
	if tt.pktgenProg != nil {
		if statusCode, data, ctx, err = runBpfProgram(tt.pktgenProg, data, ctx); err != nil {
			t.Fatalf("error while running pktgen prog: %s", err)
		}

		if dumpCtx {
			t.Log("Pktgen returned status: ")
			t.Log(statusCode)
			t.Log("data after pktgen: ")
			t.Log(spew.Sdump(data))
			t.Log("ctx after pktgen: ")
			t.Log(spew.Sdump(ctx))
		}
	}

	if tt.setupProg != nil {
		if statusCode, data, ctx, err = runBpfProgram(tt.setupProg, data, ctx); err != nil {
			t.Fatalf("error while running setup prog: %s", err)
		}

		if dumpCtx {
			t.Log("Setup returned status: ")
			t.Log(statusCode)
			t.Log("data after setup: ")
			t.Log(spew.Sdump(data))
			t.Log("ctx after setup: ")
			t.Log(spew.Sdump(ctx))
		}

		status := make([]byte, 4)
		nl.NativeEndian().PutUint32(status, statusCode)
		data = append(status, data...)
	}

	// Run test, input a
	if statusCode, data, ctx, err = runBpfProgram(tt.checkProg, data, ctx); err != nil {
		t.Fatal("error while running check program:", err)
	}

	if dumpCtx {
		t.Log("Check returned status: ")
		t.Log(statusCode)
		t.Logf("data after check: %d", len(data))
		t.Log(spew.Sdump(data))
		t.Log("ctx after check: ")
		t.Log(spew.Sdump(ctx))
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
			for i := range value {
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

// HasBench returns true if this BPF unit test contains a BENCH program.
func (tt *Test) HasBench() bool {
	return tt.benchProg != nil
}

// Bench runs the PKTGEN, and BENCH programs for a BPF unit test.
func (tt *Test) Bench() (testing.BenchmarkResult, error) {
	// create ctx with the max allowed size(4k - head room - tailroom)
	data := make([]byte, 4096-256-320)

	// ctx is only used for tc programs
	// non-empty ctx passed to non-tc programs will cause error: invalid argument
	ctx := make([]byte, 0)
	if tt.benchProg.Type() == ebpf.SchedCLS {
		// sizeof(struct __sk_buff) < 256, let's make it 256
		ctx = make([]byte, 256)
	}

	var err error

	if tt.pktgenProg != nil {
		if _, data, ctx, err = runBpfProgram(tt.pktgenProg, data, ctx); err != nil {
			return testing.BenchmarkResult{}, fmt.Errorf("while running pktgen prog: %w", err)
		}
	}

	result, err := benchmarkBpfProgram(tt.benchProg, data, ctx)
	if err != nil {
		return testing.BenchmarkResult{}, fmt.Errorf("while running bench program: %w", err)
	}

	return result, nil
}

func runBpfProgram(prog *ebpf.Program, data, ctx []byte) (statusCode uint32, dataOut, ctxOut []byte, err error) {
	dataOut = make([]byte, len(data))
	if len(dataOut) > 0 {
		// See comments at https://github.com/cilium/ebpf/blob/20c4d8896bdde990ce6b80d59a4262aa3ccb891d/prog.go#L563-L567
		dataOut = make([]byte, len(data)+256+2)
	}
	ctxOut = make([]byte, len(ctx))
	opts := &ebpf.RunOptions{
		Data:       data,
		DataOut:    dataOut,
		Context:    ctx,
		ContextOut: ctxOut,
		Repeat:     1,
	}
	ret, err := prog.Run(opts)
	return ret, opts.DataOut, ctxOut, err
}

func benchmarkBpfProgram(prog *ebpf.Program, data, ctx []byte) (testing.BenchmarkResult, error) {
	const repeat = 1_000_000

	_, avg, err := prog.Benchmark(data, repeat, nil)
	if err != nil {
		return testing.BenchmarkResult{}, err
	}

	return testing.BenchmarkResult{
		N: repeat,
		T: avg * repeat,
	}, nil
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
			binary.BigEndian.PutUint16(hb, uint16(l.Args[argNum]))
			fmt.Fprint(&sb, hex.EncodeToString(hb))

		case "lu":
			fmt.Fprint(&sb, uint32(l.Args[argNum]))
		case "ld", "li", "ls":
			fmt.Fprint(&sb, int32(l.Args[argNum]))
		case "lx":
			hb := make([]byte, 4)
			binary.BigEndian.PutUint32(hb, uint32(l.Args[argNum]))
			fmt.Fprint(&sb, hex.EncodeToString(hb))

		case "llu":
			fmt.Fprint(&sb, uint64(l.Args[argNum]))
		case "lld", "lli", "lls":
			fmt.Fprint(&sb, int64(l.Args[argNum]))
		case "llx":
			hb := make([]byte, 8)
			binary.BigEndian.PutUint64(hb, uint64(l.Args[argNum]))
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
