// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package verifier_test

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/logging"
)

var (
	ciliumBasePath  = flag.String("cilium-base-path", "", "Cilium checkout base path")
	ciKernelVersion = flag.String("ci-kernel-version", "", "CI kernel version to assume for verifier tests (supported values: 54, 510, 61, netnext)")
)

func getCIKernelVersion(t *testing.T) (string, string) {
	t.Helper()

	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		t.Fatalf("uname: %v", err)
	}
	release := unix.ByteSliceToString(uts.Release[:])
	t.Logf("Running kernel version: %s", release)

	if ciKernelVersion != nil && *ciKernelVersion != "" {
		return *ciKernelVersion, "cli"
	}

	var ciKernel string
	switch {
	case strings.HasPrefix(release, "5.4"):
		ciKernel = "54"
	case strings.HasPrefix(release, "5.10"):
		ciKernel = "510"
	case strings.HasPrefix(release, "6.1"):
		ciKernel = "61"
	case strings.HasPrefix(release, "bpf-next"):
		ciKernel = "netnext"
	default:
		t.Fatalf("detected kernel version %s not supported by verifier complexity tests, specify using -ci-kernel-version", release)
	}

	return ciKernel, "detected"
}

func getDatapathConfigFiles(t *testing.T, ciKernelVersion, bpfProgram string) []string {
	t.Helper()

	pattern := filepath.Join("bpf", "complexity-tests", ciKernelVersion, bpfProgram, "*.txt")
	files, err := filepath.Glob(filepath.Join(*ciliumBasePath, pattern))
	if err != nil {
		t.Fatal(err)
	}

	if len(files) == 0 {
		t.Fatal("No files match", pattern)
	}

	return files
}

// readDatapathConfig turns each line in a reader into a single line with each
// element separated by spaces.
func readDatapathConfig(t *testing.T, r io.Reader) string {
	scanner := bufio.NewScanner(r)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, strings.TrimSpace(scanner.Text()))
	}

	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	return strings.Join(lines, " ")
}

// This test tries to compile BPF programs with a set of options that maximize
// size & complexity (as defined in bpf/complexity-tests). Programs are then
// loaded into the kernel to detect complexity & other verifier-related
// regressions.
func TestVerifier(t *testing.T) {
	flag.Parse()

	logging.DefaultLogger.SetLevel(logrus.DebugLevel)

	if ciliumBasePath == nil || *ciliumBasePath == "" {
		t.Skip("Please set -cilium-base-path to run verifier tests")
	}
	t.Logf("Cilium checkout base path: %s", *ciliumBasePath)

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	kernelVersion, source := getCIKernelVersion(t)
	t.Logf("CI kernel version: %s (%s)", kernelVersion, source)

	for _, bpfProgram := range []struct {
		name      string
		macroName string
	}{
		{
			name:      "bpf_lxc",
			macroName: "MAX_LXC_OPTIONS",
		},
		{
			name:      "bpf_host",
			macroName: "MAX_HOST_OPTIONS",
		},
		{
			name:      "bpf_wireguard",
			macroName: "MAX_WIREGUARD_OPTIONS",
		},
		{
			name:      "bpf_xdp",
			macroName: "MAX_XDP_OPTIONS",
		},
		{
			name:      "bpf_overlay",
			macroName: "MAX_OVERLAY_OPTIONS",
		},
		{
			name:      "bpf_sock",
			macroName: "MAX_LB_OPTIONS",
		},
		{
			name:      "bpf_network",
			macroName: "BPF_SIMPLE_OPTIONS",
		},
	} {
		t.Run(bpfProgram.name, func(t *testing.T) {
			initObjFile := path.Join(*ciliumBasePath, "bpf", fmt.Sprintf("%s.o", bpfProgram.name))

			fileNames := getDatapathConfigFiles(t, kernelVersion, bpfProgram.name)
			for _, fileName := range fileNames {
				configName := strings.TrimSuffix(filepath.Base(fileName), filepath.Ext(fileName))
				t.Run(configName, func(t *testing.T) {
					file, err := os.Open(fileName)
					if err != nil {
						t.Fatalf("Unable to open configuration: %v", err)
					}
					defer file.Close()

					datapathConfig := readDatapathConfig(t, file)

					name := fmt.Sprintf("%s_%s", bpfProgram.name, configName)
					cmd := exec.Command("make", "-C", "bpf", "clean", fmt.Sprintf("%s.o", bpfProgram.name))
					cmd.Dir = *ciliumBasePath
					cmd.Env = append(os.Environ(),
						fmt.Sprintf("%s=%s", bpfProgram.macroName, datapathConfig),
						fmt.Sprintf("KERNEL=%s", kernelVersion),
					)
					t.Logf("Compiling with %q", cmd.Args)
					t.Logf("Env is %q", cmd.Env)
					if out, err := cmd.CombinedOutput(); err != nil {
						t.Logf("Command output:\n%s", string(out))
						t.Fatalf("Failed to compile bpf objects: %v", err)
					}

					objFile := filepath.Join("./", name+".o")
					// Rename object file to avoid subsequent runs to overwrite it,
					// so we can keep it for CI's artifact upload.
					if err = os.Rename(initObjFile, objFile); err != nil {
						t.Fatalf("Failed to rename %s to %s: %v", initObjFile, objFile, err)
					}

					// Parse the compiled object into a CollectionSpec.
					spec, err := bpf.LoadCollectionSpec(objFile)
					if err != nil {
						t.Fatal(err)
					}

					// Delete unsupported programs from the spec.
					for n, p := range spec.Programs {
						err := probes.HaveAttachType(p.Type, p.AttachType)
						if errors.Is(err, ebpf.ErrNotSupported) {
							t.Logf("%s: skipped unsupported program/attach type (%s/%s)", n, p.Type, p.AttachType)
							delete(spec.Programs, n)
							continue
						}
						if err != nil {
							t.Fatal(err)
						}
					}

					// Strip all pinning flags so we don't need to specify a pin path.
					// This creates new maps for every Collection.
					for _, m := range spec.Maps {
						m.Pinning = ebpf.PinNone
					}

					coll, _, err := bpf.LoadCollection(spec, &bpf.CollectionOptions{
						CollectionOptions: ebpf.CollectionOptions{
							// Enable verifier logs for successful loads.
							// Use log level 1 since it's known by all target kernels.
							Programs: ebpf.ProgramOptions{
								// Maximum log size for kernels <5.2. Some programs generate a
								// verifier log of over 8MiB, so avoid retries due to the initial
								// size being too small. This saves a lot of time as retrying means
								// reloading all maps and progs in the collection.
								LogSize:  (math.MaxUint32 >> 8), // 16MiB
								LogLevel: ebpf.LogLevelBranch,
							},
						},
					})
					var ve *ebpf.VerifierError
					if errors.As(err, &ve) {
						// Write full verifier log to a path on disk for offline analysis.
						var buf bytes.Buffer
						fmt.Fprintf(&buf, "%+v", ve)
						fullLogFile := name + "_verifier.log"
						_ = os.WriteFile(fullLogFile, buf.Bytes(), 0444)
						t.Log("Full verifier log at", fullLogFile)

						// Print unverified instruction count.
						t.Log("BPF unverified instruction count per program:")
						for n, p := range spec.Programs {
							t.Logf("\t%s: %d insns", n, len(p.Instructions))
						}

						// Include the original err in the output since it contains the name
						// of the program that triggered the verifier error.
						// ebpf.VerifierError only contains the return code and verifier log
						// buffer.
						t.Fatalf("Error: %v\nVerifier error tail: %-10v", err, ve)
					}
					if err != nil {
						t.Fatal(err)
					}
					defer coll.Close()

					// Print verifier stats appearing on the last line of the log, e.g.
					// 'processed 12248 insns (limit 1000000) ...'.
					// Sort by program names for stable output.
					names := make([]string, 0, len(coll.Programs))
					for n := range coll.Programs {
						names = append(names, n)
					}
					sort.Strings(names)
					for _, n := range names {
						p := coll.Programs[n]
						p.VerifierLog = strings.TrimRight(p.VerifierLog, "\n")
						// Offset points at the last newline, increment by 1 to skip it.
						// Turn a -1 into a 0 if there are no newlines in the log.
						lastOff := strings.LastIndex(p.VerifierLog, "\n") + 1
						t.Logf("%s: %v (%d unverified insns)", n, p.VerifierLog[lastOff:], len(spec.Programs[n].Instructions))
					}
				})
			}
		})
	}
}
