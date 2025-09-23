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

	t.Run("LXC", func(t *testing.T) {
		t.Parallel()
		i := 1
		for perm := range buildPermutations("bpf_lxc", kv, lxcLoadPermutations) {
			t.Run(strconv.Itoa(i), compileAndLoad(perm, "lxc", endpointProg, endpointObj, i, &records))
			i++
		}
	})

	t.Run("Host", func(t *testing.T) {
		t.Parallel()
		i := 1
		for perm := range buildPermutations("bpf_host", kv, hostLoadPermutations) {
			t.Run(strconv.Itoa(i), compileAndLoad(perm, "host", hostEndpointProg, hostEndpointObj, i, &records))
			i++
		}
	})

	t.Run("Network", func(t *testing.T) {
		t.Parallel()
		i := 1
		for perm := range buildPermutations("bpf_network", kv, networkLoadPermutations) {
			t.Run(strconv.Itoa(i), compileAndLoad(perm, "network", networkProg, networkObj, i, &records))
			i++
		}
	})

	t.Run("Overlay", func(t *testing.T) {
		t.Parallel()
		i := 1
		for perm := range buildPermutations("bpf_overlay", kv, overlayLoadPermutations) {
			t.Run(strconv.Itoa(i), compileAndLoad(perm, "overlay", overlayProg, overlayObj, i, &records))
			i++
		}
	})

	t.Run("Sock", func(t *testing.T) {
		t.Parallel()
		i := 1
		for perm := range buildPermutations("bpf_sock", kv, sockLoadPermutations) {
			t.Run(strconv.Itoa(i), compileAndLoad(perm, "sock", "bpf_sock.c", "bpf_sock.o", i, &records))
			i++
		}
	})

	t.Run("Wireguard", func(t *testing.T) {
		t.Parallel()
		i := 1
		for perm := range buildPermutations("bpf_wireguard", kv, wireguardLoadPermutations) {
			t.Run(strconv.Itoa(i), compileAndLoad(perm, "wireguard", wireguardProg, wireguardObj, i, &records))
			i++
		}
	})

	t.Run("XDP", func(t *testing.T) {
		t.Parallel()
		i := 1
		for perm := range buildPermutations("bpf_xdp", kv, xdpLoadPermutations) {
			t.Run(strconv.Itoa(i), compileAndLoad(perm, "xdp", xdpProg, xdpObj, i, &records))
			i++
		}
	})
}

func compileAndLoad[T any](perm buildPermutation[T], collection, source, output string, build int, records *verifierComplexityRecords) func(t *testing.T) {
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

			stackDepthIndex := strings.LastIndex(p.VerifierLog[:lastLineIndex], "\n")
			_, err = fmt.Sscanf(p.VerifierLog[stackDepthIndex+1:lastOff], "stack depth %d", &r.StackDepth)
			if err != nil {
				t.Fatalf("Failed to parse stack depth for program %s: %v", n, err)
			}

			verificationTimeIndex := strings.LastIndex(p.VerifierLog[:stackDepthIndex], "\n")
			_, err = fmt.Sscanf(p.VerifierLog[verificationTimeIndex+1:stackDepthIndex], "verification time %d usec", &r.VerificationTimeMicroseconds)
			if err != nil {
				t.Fatalf("Failed to parse verification time for program %s: %v", n, err)
			}

			records.Add(r)
		}
	}
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

type buildPermutation[T any] struct {
	options          []string
	loadPermutations iter.Seq[T]
}

func buildPermutations[T any](progDir string, kernel kernelVersion, loadPerm func() iter.Seq[T]) iter.Seq[buildPermutation[T]] {
	return func(yield func(buildPermutation[T]) bool) {
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

			if !yield(buildPermutation[T]{
				options:          optionsSlice,
				loadPermutations: loadPerm(),
			}) {
				return
			}
		}
	}
}
