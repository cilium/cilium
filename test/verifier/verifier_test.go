// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package verifier_test

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
)

var (
	ciliumBasePath  = flag.String("cilium-base-path", "", "Cilium checkout base path")
	ciKernelVersion = flag.String("ci-kernel-version", "", "CI kernel version to assume for verifier tests (supported values: 419, 54, 510, netnext)")
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
	case strings.HasPrefix(release, "4.19"):
		ciKernel = "419"
	case strings.HasPrefix(release, "5.4"):
		ciKernel = "54"
	case strings.HasPrefix(release, "5.10"):
		ciKernel = "510"
	case strings.HasPrefix(release, "bpf-next"):
		ciKernel = "netnext"
	default:
		t.Fatalf("detected kernel version %s not supported by verifier complexity tests, specify using -ci-kernel-version", release)
	}

	return ciKernel, "detected"
}

func getDatapathConfigFile(t *testing.T, ciKernelVersion, bpfProgram string) string {
	t.Helper()

	return filepath.Join(*ciliumBasePath, "bpf", "complexity-tests", ciKernelVersion, fmt.Sprintf("%s.txt", bpfProgram))
}

// This test tries to compile BPF programs with a set of options that maximize
// size & complexity (as defined in bpf/complexity-tests). Programs are then
// loaded into the kernel to detect complexity & other verifier-related
// regressions.
func TestVerifier(t *testing.T) {
	flag.Parse()

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
	} {
		file, err := os.Open(getDatapathConfigFile(t, kernelVersion, bpfProgram.name))
		if err != nil {
			t.Fatalf("Unable to open list of datapath configurations for %s: %v", bpfProgram.name, err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for i := 1; scanner.Scan(); i++ {
			datapathConfig := scanner.Text()

			name := fmt.Sprintf("%s_%d", bpfProgram.name, i)
			t.Run(name, func(t *testing.T) {
				cmd := exec.Command("make", "-C", "bpf/", "clean")
				cmd.Dir = *ciliumBasePath
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("Failed to clean bpf objects: %v\ncommand output: %s", err, out)
				}

				cmd = exec.Command("make", "-C", "bpf", fmt.Sprintf("%s.o", bpfProgram.name))
				cmd.Dir = *ciliumBasePath
				cmd.Env = append(cmd.Env,
					fmt.Sprintf("%s=%s", bpfProgram.macroName, datapathConfig),
					fmt.Sprintf("KERNEL=%s", kernelVersion),
				)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("Failed to compile %s bpf objects: %v\ncommand output: %s", bpfProgram.name, err, out)
				}

				// Parse the compiled object into a CollectionSpec.
				spec, err := bpf.LoadCollectionSpec(path.Join(*ciliumBasePath, "bpf", fmt.Sprintf("%s.o", bpfProgram.name)))
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

				coll, err := bpf.LoadCollection(spec, ebpf.CollectionOptions{
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
				})
				var ve *ebpf.VerifierError
				if errors.As(err, &ve) {
					var buf bytes.Buffer
					fmt.Fprintf(&buf, "%+v", ve)
					fullLogFile := name + "_verifier.log"
					_ = os.WriteFile(fullLogFile, buf.Bytes(), 0444)
					t.Log("Full verifier log at", fullLogFile)
					t.Fatalf("Verifier error: %-10v\nDatapath build config: %s", ve, datapathConfig)
				}
				if err != nil {
					t.Fatal(err)
				}
				defer coll.Close()

				// Print verifier stats appearing on the last line of the log, e.g.
				// 'processed 12248 insns (limit 1000000) ...'.
				for n, p := range coll.Programs {
					p.VerifierLog = strings.TrimRight(p.VerifierLog, "\n")
					// Offset points at the last newline, increment by 1 to skip it.
					// Turn a -1 into a 0 if there are no newlines in the log.
					lastOff := strings.LastIndex(p.VerifierLog, "\n") + 1
					t.Logf("%s: %v", n, p.VerifierLog[lastOff:])
				}
			})

			if err = scanner.Err(); err != nil {
				t.Fatalf("Error while reading list of datapath configurations for %s: %v", bpfProgram.name, err)
			}
		}
	}
}
