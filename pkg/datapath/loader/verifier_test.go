// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"iter"
	"log/slog"
	"maps"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/testutils"
)

var (
	flagCiliumBasePath = flag.String("cilium-base-path", "", "Cilium checkout base path")
	flagKernelName     = flag.String("kernel-name", "netnext", "Name of the kernel under test")
	flagKernelVersion  = flag.String("kernel-version", kernelVersionNetNext.String(), "Kernel version to assume for verifier tests for the purposes of selecting build permutations.")
	flagResultDir      = flag.String("result-dir", "", "Directory to write verifier complexity results and verifier logs to (temp directory if empty)")
	flagKeepObject     = flag.Bool("keep-object", false, "Keep compiled object files in the result directory (default: false)")
	flagFullLog        = flag.Bool("full-log", false, "Write full verifier log to file (default: false)")
)

// TestPrivilegedVerifier compiles and loads BPF programs with various configurations
// to test the verifier's complexity and performance.
// There are permutations of both compile time configuration and load time configuration.
// The test name schema is: `TestPrivilegedVerifier/<program type>/<build>/<load>`
// Where `build` and `load` are the permutation number.
func TestPrivilegedVerifier(t *testing.T) {
	testutils.PrivilegedTest(t)

	if *flagKernelVersion == "" {
		t.Fatal("Kernel version must be specified")
	}
	kv, err := kernelVersionFromString(*flagKernelVersion)
	if err != nil {
		t.Fatalf("Invalid kernel version '%s': %v", *flagKernelVersion, err)
	}
	t.Logf("Using kernel version: %s", *flagKernelVersion)

	if *flagCiliumBasePath == "" {
		t.Skip("Skipping verifier complexity tests, Cilium base path must be specified")
		return
	}

	var records verifierComplexityRecords

	if *flagResultDir == "" {
		resultDir, err := os.MkdirTemp("", "verifier-complexity")
		if err != nil {
			t.Fatalf("Failed to create temporary directory for verifier complexity results: %v", err)
		}
		if err = os.Chmod(resultDir, 0755); err != nil {
			t.Fatalf("Failed to set permissions on temporary directory %s: %v", resultDir, err)
		}
		flagResultDir = &resultDir
	} else {
		if err := os.Mkdir(*flagResultDir, 0755); err != nil && !os.IsExist(err) && !os.IsPermission(err) {
			t.Fatalf("Failed to create directory %s with permissions: %v", *flagResultDir, err)
		}
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		path := path.Join(*flagResultDir, "verifier-complexity.json")
		t.Logf("Writing verifier complexity records to %s", path)
		records.WriteToFile(path)
	})

	for _, c := range collections {
		c.Run(t, kv, &records)
	}
}

var collections = []collection{
	{
		name:             "LXC",
		progDir:          "bpf_lxc",
		loadPermutations: lxcLoadPermutations,
		collection:       "lxc",
		source:           endpointProg,
		output:           endpointObj,
	},
	{
		name:             "Host",
		progDir:          "bpf_host",
		loadPermutations: hostLoadPermutations,
		collection:       "host",
		source:           hostEndpointProg,
		output:           hostEndpointObj,
	},
	{
		name:             "Overlay",
		progDir:          "bpf_overlay",
		loadPermutations: overlayLoadPermutations,
		collection:       "overlay",
		source:           overlayProg,
		output:           overlayObj,
	},
	{
		name:             "Sock",
		progDir:          "bpf_sock",
		loadPermutations: sockLoadPermutations,
		collection:       "sock",
		source:           socketProg,
		output:           socketObj,
	},
	{
		name:             "Wireguard",
		progDir:          "bpf_wireguard",
		loadPermutations: wireguardLoadPermutations,
		collection:       "wireguard",
		source:           wireguardProg,
		output:           wireguardObj,
	},
	{
		name:             "XDP",
		progDir:          "bpf_xdp",
		loadPermutations: xdpLoadPermutations,
		collection:       "xdp",
		source:           xdpProg,
		output:           xdpObj,
	},
}

type collection struct {
	name             string
	progDir          string
	loadPermutations *loadPermutationBuilder
	collection       string
	source           string
	output           string
}

func (c *collection) Run(t *testing.T, kv kernelVersion, records *verifierComplexityRecords) {
	t.Run(c.name, func(t *testing.T) {
		t.Parallel()
		i := 1
		for perm := range buildPermutations(c.progDir, kv, c.loadPermutations) {
			t.Run(strconv.Itoa(i), compileAndLoad(perm, c.collection, c.source, c.output, i, records))
			i++
		}
	})
}

func compileAndLoad(perm buildPermutation, collection, source, output string, build int, records *verifierComplexityRecords) func(t *testing.T) {
	return func(t *testing.T) {
		t.Parallel()

		stateDir := t.TempDir()
		dirInfo := &directoryInfo{
			Library: path.Join(*flagCiliumBasePath, defaults.BpfDir),
			Runtime: stateDir,
			State:   stateDir,
			Output:  stateDir,
		}

		log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

		objFileName, err := compile(t.Context(), log, &progInfo{
			Source:     source,
			Output:     output,
			OutputType: outputObject,
			Options:    perm.options,
		}, dirInfo)
		if err != nil {
			t.Fatalf("Failed to compile %s program: %v", collection, err)
		}

		t.Logf("Compiled %s program: %s", collection, objFileName)

		spec, err := ebpf.LoadCollectionSpec(objFileName)
		if err != nil {
			t.Fatalf("Failed to load BPF collection spec: %v", err)
		}
		// Do not attempt to pin maps
		for _, m := range spec.Maps {
			m.Pinning = ebpf.PinNone
		}

		ii := 0
		for constants := range perm.loadPermutations {
			t.Run(strconv.Itoa(ii), loadAndRecordComplexity(
				objFileName,
				spec,
				constants,
				collection,
				build, ii,
				records,
			))
			ii++
		}

		if *flagKeepObject {
			dst := path.Join(*flagResultDir, fmt.Sprintf("%s_%d.o", collection, build))
			if err := os.Rename(objFileName, dst); err != nil {
				t.Fatalf("Failed to move object file to result directory: %v", err)
			}
		}
	}

}

func loadAndRecordComplexity(
	objectFile string,
	spec *ebpf.CollectionSpec,
	constants any,
	collection string,
	build, load int,
	records *verifierComplexityRecords,
) func(t *testing.T) {
	return func(t *testing.T) {
		t.Parallel()
		log := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

		// Only print last line + additional stats.
		logLevel := ebpf.LogLevelStats
		if *flagFullLog {
			logLevel = ebpf.LogLevelInstruction | ebpf.LogLevelStats
		}

		var (
			coll *ebpf.Collection
			err  error
		)
		for {
			coll, _, err = bpf.LoadCollection(log, spec, &bpf.CollectionOptions{
				Constants: constants,
				CollectionOptions: ebpf.CollectionOptions{
					Maps: ebpf.MapOptions{PinPath: bpf.TCGlobalsPath()},
					Programs: ebpf.ProgramOptions{
						LogLevel: logLevel,
					},
				},
			})
			if err != nil {
				// When we have a load error, and we initially did not request the full log,
				// we retry with the full log enabled.
				if logLevel != ebpf.LogLevelInstruction|ebpf.LogLevelStats {
					logLevel = ebpf.LogLevelInstruction | ebpf.LogLevelStats
					continue
				}
			}

			break
		}

		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			// Write full verifier log to a path on disk for offline analysis.
			var buf bytes.Buffer
			fmt.Fprintf(&buf, "%+v", ve)
			fullLogFile := path.Join(*flagResultDir, fmt.Sprintf("%s_%d_%d_verifier.log", collection, build, load))
			_ = os.WriteFile(fullLogFile, buf.Bytes(), 0444)
			t.Log("Full verifier log at", fullLogFile)

			// Copy the object file to the result directory, so it can be inspected together with the
			// verifier log.
			// Use os.O_EXCL, so we error when the file already exists. This prevents us from writing
			// the same object file multiple times.
			dst, err := os.OpenFile(path.Join(*flagResultDir, fmt.Sprintf("%s_%d.o", collection, build)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
			if err == nil {
				src, err := os.Open(objectFile)
				if err != nil {
					t.Fatalf("Failed to open object file %s: %v", objectFile, err)
				}

				_, err = io.Copy(dst, src)
				if err != nil {
					t.Fatalf("Failed to copy object file %s to result directory: %v", objectFile, err)
				}

				src.Close()
				dst.Close()
			} else if !os.IsExist(err) {
				t.Fatalf("Failed to create object file in result directory: %v", err)
			}

			// Print unverified instruction count.
			t.Log("BPF unverified instruction count per program:")
			for n, p := range spec.Programs {
				t.Logf("\t%s: %d insns", n, len(p.Instructions))
			}

			// Include the original err in the output since it contains the name
			// of the program that triggered the verifier error.
			// ebpf.VerifierError only contains the return code and verifier log
			// buffer.
			t.Logf("Error: %v\nVerifier error tail: %-10v", err, ve)
			t.Fail()
			return
		}
		if err != nil {
			t.Log(err)
			t.Fail()
			return
		}
		defer coll.Close()

		for _, n := range slices.Sorted(maps.Keys(coll.Programs)) {
			p := coll.Programs[n]
			s := spec.Programs[n]

			if *flagFullLog {
				fullLogFile := path.Join(*flagResultDir, fmt.Sprintf("%s_%d_%d_%s_verifier.log", collection, build, load, n))
				f, err := os.Create(fullLogFile)
				if err != nil {
					t.Fatalf("Failed to create full verifier log file: %v", err)
				}
				if _, err := io.Copy(f, strings.NewReader(p.VerifierLog)); err != nil {
					t.Fatalf("Failed to write full verifier log: %v", err)
				}
				if err := f.Close(); err != nil {
					t.Fatalf("Failed to close full verifier log file: %v", err)
				}
			}

			// The part of the log we are interested in is at the end. And looks like this:
			//   verification time 355643 usec
			//   stack depth 144+280+120
			//   insns processed 12591+75421+455  <-- only on newer kernels
			//   processed 88467 insns (limit 1000000) max_states_per_insn 44 total_states 4141 peak_states 1137 mark_read 56

			// Remove trailing newline so strings.LastIndex finds the newline ahead of the last log line.
			p.VerifierLog = strings.TrimRight(p.VerifierLog, "\n")
			lastLineIndex := strings.LastIndex(p.VerifierLog, "\n")

			// Offset points at the last newline, increment by 1 to skip it.
			// Turn a -1 into a 0 if there are no newlines in the log.
			lastOff := lastLineIndex + 1

			r := verifierComplexityRecord{
				Kernel:     *flagKernelName,
				Collection: collection,
				Build:      strconv.Itoa(build),
				Load:       strconv.Itoa(load),
				Program:    n,
			}

			_, err := fmt.Sscanf(p.VerifierLog[lastOff:], "processed %d insns (limit %d) max_states_per_insn %d total_states %d peak_states %d mark_read %d",
				&r.InsnsProcessed, &r.InsnsLimit, &r.MaxStatesPerInsn, &r.TotalStates, &r.PeakStates, &r.MarkRead)
			if err != nil {
				t.Fatalf("Failed to parse verifier log for program %s: %v", n, err)
			}

			stackDepth, stackDepthIndex, err := parseStackDepth(s, p.VerifierLog, lastLineIndex, lastOff)
			if err != nil {
				t.Fatalf("Failed to parse stack depth for program %s: %v", n, err)
			}
			r.StackDepth = stackDepth

			// Extract the third to last line, which looks like:
			//   verification time 355643 usec
			verificationTimeIndex := strings.LastIndex(p.VerifierLog[:stackDepthIndex], "\n")
			_, err = fmt.Sscanf(p.VerifierLog[verificationTimeIndex+1:stackDepthIndex], "verification time %d usec", &r.VerificationTimeMicroseconds)
			if err != nil {
				t.Fatalf("Failed to parse verification time for program %s: %v", n, err)
			}

			progInfo, err := p.Info()
			if err != nil {
				t.Fatalf("Failed to get program info for program %s: %v", n, err)
			}
			mapIds, _ := progInfo.MapIDs()
			r.MapCount = len(mapIds)

			records.Add(r)
		}
	}
}

// Extract the second to last line, which looks like:
//
//	stack depth 144+280+120
func parseStackDepth(s *ebpf.ProgramSpec, verifierLogs string, lastLineIndex, lastOff int) (int, int, error) {
	stackDepthIndex := strings.LastIndex(verifierLogs[:lastLineIndex], "\n")
	stackDepthLine := verifierLogs[stackDepthIndex+1 : lastOff]
	if !strings.Contains(stackDepthLine, "stack depth ") {
		lastOff = stackDepthIndex + 1
		stackDepthIndex = strings.LastIndex(verifierLogs[:stackDepthIndex], "\n")
		stackDepthLine = verifierLogs[stackDepthIndex+1 : lastOff]
		if !strings.Contains(stackDepthLine, "stack depth ") {
			return 0, stackDepthIndex, fmt.Errorf("Couldn't find stack depths line in verifier logs")
		}
	}
	stackDepthLine = strings.TrimPrefix(strings.TrimSpace(stackDepthLine), "stack depth ")

	// Remove prefix so we are just left with plus separated stack depths, and parse them into ints.
	//   144+280+120
	// Split and parse to ints
	var depths []int
	for part := range strings.SplitSeq(stackDepthLine, "+") {
		depth, err := strconv.Atoi(part)
		if err != nil {
			return 0, stackDepthIndex, err
		}
		depths = append(depths, depth)
	}
	return maxStackDepth(s, depths), stackDepthIndex, nil
}

func maxStackDepth(spec *ebpf.ProgramSpec, stackDepths []int) int {
	insns := spec.Instructions
	graph := make(map[string][]string)
	sizes := make(map[string]int)

	// The stack depths in the verifier log are in the same order as the functions in the instructions.
	// We iterate through the instructions, and whenever we see a function definition, we take the next stack depth
	// from the log and associate it with that function. Also record calls to construct a call graph.
	var cur string
	for _, insn := range insns {
		if insn.IsFunctionCall() {
			graph[cur] = append(graph[cur], insn.Reference())
			continue
		}
		if fn := btf.FuncMetadata(&insn); fn != nil {
			cur = fn.Name
			sizes[cur] = stackDepths[0]
			stackDepths = stackDepths[1:]
		}
	}

	// Recursively visit the call graph to calculate the maximum stack depth, by summing the stack sizes of called
	// functions. This is safe to do since the verifier will have rejected any program with recursive calls, so we know
	// the graph is acyclic.
	maxDepth := 0
	var visit func(callstack []string)
	visit = func(callstack []string) {
		depth := 0
		for _, fn := range callstack {
			depth += sizes[fn]
		}
		maxDepth = max(maxDepth, depth)

		for _, callee := range graph[callstack[len(callstack)-1]] {
			visit(append(callstack, callee))
		}
	}
	visit([]string{spec.Name})

	return maxDepth
}

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

	MapCount int `json:"map_count"`
}

type verifierComplexityRecords struct {
	mu      lock.Mutex
	Records []verifierComplexityRecord
}

func (v *verifierComplexityRecords) Add(r verifierComplexityRecord) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.Records = append(v.Records, r)
}

func (ve *verifierComplexityRecords) WriteToFile(filename string) error {
	ve.mu.Lock()
	defer ve.mu.Unlock()

	f, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create result file: %w", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(ve.Records); err != nil {
		return fmt.Errorf("failed to write result file: %w", err)
	}
	return nil
}

type kernelVersion int

const (
	kernelVersion510 kernelVersion = iota
	kernelVersion61
	kernelVersionNetNext
	_kernelVersionMax
)

func (kv kernelVersion) String() string {
	switch kv {
	case kernelVersion510:
		return "510"
	case kernelVersion61:
		return "61"
	case kernelVersionNetNext:
		return "netnext"
	default:
		return "unknown"
	}
}

func kernelVersionFromString(s string) (kernelVersion, error) {
	switch s {
	case "510":
		return kernelVersion510, nil
	case "61":
		return kernelVersion61, nil
	case "netnext":
		return kernelVersionNetNext, nil
	default:
		return _kernelVersionMax, fmt.Errorf("unknown kernel version: %s", s)
	}
}

type buildPermutation struct {
	options          []string
	loadPermutations iter.Seq[[]any]
}

func buildPermutations(progDir string, kernel kernelVersion, loadPerm *loadPermutationBuilder) iter.Seq[buildPermutation] {
	return func(yield func(buildPermutation) bool) {
		dir := path.Join(*flagCiliumBasePath, "bpf", "complexity-tests", kernel.String(), progDir)
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}

		for _, file := range entries {
			filePath := path.Join(dir, file.Name())
			contents, err := os.ReadFile(filePath)
			if err != nil {
				continue
			}

			optionsSlice := strings.Split(string(contents), "\n")

			if !yield(buildPermutation{
				options:          optionsSlice,
				loadPermutations: loadPerm.build(),
			}) {
				return
			}
		}
	}
}

type loadPermutationBuilder struct {
	constructors []func() any
	options      []configOption
}

func (b *loadPermutationBuilder) addConstructor(constructor func() any) {
	b.constructors = append(b.constructors, constructor)
}

func (b *loadPermutationBuilder) addOptions(options ...configOption) {
	b.options = append(b.options, options...)
}

// build a sequence of configuration slices from the registered constructors and options.
func (b *loadPermutationBuilder) build() iter.Seq[[]any] {
	var alwaysSetters []configSetter
	var incrementSetters []configSetter
	var permuteSetters []configSetter

	for _, option := range b.options {
		switch option.typ {
		case configAlways:
			alwaysSetters = append(alwaysSetters, option.fn)
		case configIncrement:
			incrementSetters = append(incrementSetters, option.fn)
		case configPermute:
			permuteSetters = append(permuteSetters, option.fn)
		case configIncrementOrPermute:
			if testing.Short() {
				incrementSetters = append(incrementSetters, option.fn)
			} else {
				permuteSetters = append(permuteSetters, option.fn)
			}
		default:
			panic("unknown option type")
		}
	}

	return func(yield func([]any) bool) {
		// given a number of bools, returns a sequence of all unique permutations of those bools being true or false.
		// If n=0, then a single empty slice is returned.
		permute := func(n int) iter.Seq[[]bool] {
			permutation := make([]bool, n)
			return func(yield func([]bool) bool) {
				for i := range uint64(1 << n) {
					for j := range n {
						permutation[j] = (i & (1 << j)) != 0
					}
					if !yield(permutation) {
						return
					}
				}
			}
		}

		// For each permutation of the `Permute` options, or just once if there are none.
		for permutations := range permute(len(permuteSetters)) {
			// For each incremental combination of the `Increment` options, or just once if there are none.
			// it's len + 1, because we always want to yield the configuration with all options disabled, and then
			// incrementally enable options until all are enabled.
			for i := range len(incrementSetters) + 1 {
				// Construct a configuration object from each registered constructor.
				cfgs := make([]any, len(b.constructors))
				for j, constructor := range b.constructors {
					cfgs[j] = constructor()
				}

				for _, setter := range alwaysSetters {
					for _, cfg := range cfgs {
						setter(cfg, true)
					}
				}

				for oi, setter := range incrementSetters {
					for _, cfg := range cfgs {
						setter(cfg, oi < i)
					}
				}

				for oi, setter := range permuteSetters {
					for _, cfg := range cfgs {
						setter(cfg, permutations[oi])
					}
				}

				if !yield(cfgs) {
					return
				}
			}
		}
	}
}

type configType int

const (
	configAlways configType = iota
	configIncrement
	configPermute
	configIncrementOrPermute
)

type configOption struct {
	typ configType
	fn  configSetter
}

type configSetter func(c any, v bool)

func callWithT[T any](fn func(*T, bool)) configSetter {
	return func(c any, v bool) {
		if cfg, ok := c.(*T); ok {
			fn(cfg, v)
		}
	}
}

// Always apply `fn` to the configuration, regardless of the permutation.
func Always[T any](fn func(*T, bool)) configOption {
	return configOption{typ: configAlways, fn: callWithT(fn)}
}

// Apply `fn` to the configuration, incrementally enabling the option for each permutation.
// `fn` is always invoked, the boolean parameter indicates whether the option should be enabled for this permutation.
func Increment[T any](fn func(*T, bool)) configOption {
	return configOption{typ: configIncrement, fn: callWithT(fn)}
}

// Apply `fn` to the configuration, permuting the option on or off for each permutation.
// `fn` is always invoked, the boolean parameter indicates whether the option should be enabled for this permutation.
//
// Note: permuting options exponentially increases the number of permutations to be checked.
func Permute[T any](fn func(*T, bool)) configOption {
	return configOption{typ: configPermute, fn: callWithT(fn)}
}

// When -short is set, use Increment behavior, otherwise use Permute behavior.
func IncrementOrPermute[T any](fn func(*T, bool)) configOption {
	return configOption{typ: configIncrementOrPermute, fn: callWithT(fn)}
}

func TestTable(t *testing.T) {
	type configA struct {
		enableA bool
		enableB bool
		enableC bool
	}

	type configB struct {
		enableD bool
		enableE bool
		enableF bool
	}

	builder := loadPermutationBuilder{
		constructors: []func() any{
			func() any { return &configA{} },
			func() any { return &configB{} },
		},
		options: []configOption{
			Always(func(c *configA, _ bool) { c.enableA = true }),
			Increment(func(c *configA, v bool) { c.enableB = v }),
			Permute(func(c *configA, v bool) { c.enableC = v }),
			Always(func(c *configB, _ bool) { c.enableD = true }),
			Increment(func(c *configB, v bool) { c.enableE = v }),
			Permute(func(c *configB, v bool) { c.enableF = v }),
		},
	}

	result := slices.Collect(builder.build())
	if len(result) != 12 {
		t.Fatalf("expected 12 configurations, got %d", len(result))
	}
	expected := [][]any{
		{&configA{true, false, false}, &configB{true, false, false}},
		{&configA{true, true, false}, &configB{true, false, false}},
		{&configA{true, true, false}, &configB{true, true, false}},
		{&configA{true, false, true}, &configB{true, false, false}},
		{&configA{true, true, true}, &configB{true, false, false}},
		{&configA{true, true, true}, &configB{true, true, false}},
		{&configA{true, false, false}, &configB{true, false, true}},
		{&configA{true, true, false}, &configB{true, false, true}},
		{&configA{true, true, false}, &configB{true, true, true}},
		{&configA{true, false, true}, &configB{true, false, true}},
		{&configA{true, true, true}, &configB{true, false, true}},
		{&configA{true, true, true}, &configB{true, true, true}},
	}
	for i, cfg := range result {
		gotA := cfg[0].(*configA)
		gotB := cfg[1].(*configB)
		expA := expected[i][0].(*configA)
		expB := expected[i][1].(*configB)
		if *gotA != *expA || *gotB != *expB {
			t.Errorf("configuration %d does not match expected: got (%+v, %+v), want (%+v, %+v)", i, gotA, gotB, expA, expB)
		}
	}
}
