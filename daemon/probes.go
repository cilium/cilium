// Copyright 2016-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

func kernelConfig() ([]byte, error) {
	localConfigLocations := []string{
		"/proc/config",
		"/proc/config.gz",
	}
	localConfigLocationsGz := []string{
		fmt.Sprintf("/boot/config-%s", getKernelVersionStr()),
	}

	for _, localConfigLocation := range localConfigLocations {
		if _, err := os.Stat(localConfigLocation); !os.IsNotExist(err) {
			fConfig, err := os.Open(localConfigLocation)
			if err != nil {
				return nil, err
			}
			return ioutil.ReadAll(fConfig)
		}
	}

	for _, localConfigLocation := range localConfigLocationsGz {
		if _, err := os.Stat(localConfigLocation); !os.IsNotExist(err) {
			fConfig, err := os.Open(localConfigLocation)
			if err != nil {
				return nil, err
			}
			gConfig, err := gzip.NewReader(fConfig)
			if err != nil {
				return nil, err
			}
			return ioutil.ReadAll(gConfig)
		}
	}

	return nil, fmt.Errorf("could not find kernel config file")
}

func probeKernelConfig() error {
	requiredParams := []string{
		"CONFIG_BPF=y",
		"CONFIG_BPF_SYSCALL=y",
		"CONFIG_NET_SCH_INGRESS=(m|y)",
		"CONFIG_NET_CLS_BPF=(m|y)",
		"CONFIG_NET_CLS_ACT=y",
		"CONFIG_BPF_JIT=y",
		"CONFIG_HAVE_EBPF_JIT=y",
	}

	kConfig, err := kernelConfig()
	if err != nil {
		return err
	}

	for _, param := range requiredParams {
		re := regexp.MustCompile(param)
		if !re.Match(kConfig) {
			return fmt.Errorf("%s is not in kernel configuration", param)
		}
	}

	return nil
}

func probeRunTc() error {
	return nil
}

func copyFile(src, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

func probeRunLl(probesDir, libIncludeDir, outDir string) error {
	outFilename := path.Join(outDir, "raw_probe.t")

	err := filepath.Walk(probesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(info.Name(), ".t") {
			copyFile(path, outFilename)
			out, err := exec.Command(
				"clang",
				"-O2",
				"-Wall",
				fmt.Sprintf("-I%s", probesDir),
				fmt.Sprintf("-I%s", libIncludeDir),
				fmt.Sprintf("-I%s", outDir),
			).CombinedOutput()
			if err != nil {
				return fmt.Errorf("clang failed: %s: %s", err, out)
			}
		}
		return nil
	})
	return err
}

func probe(bpfDir, stateDir string) error {
	probesDir := path.Join(bpfDir, "probes")
	libIncludeDir := path.Join(bpfDir, "include")

	outDir, err := ioutil.TempDir("", "cilium-probes-out")
	if err != nil {
		return fmt.Errorf("could not create temporary directory for probes: %s", err)
	}
	defer os.RemoveAll(outDir)

	if err := probeKernelConfig(); err != nil {
		return fmt.Errorf("kernel config probe failed: %s", err)
	}
	if err := probeRunTc(); err != nil {
		return fmt.Errorf("tc probe failed: %s", err)
	}
	if err := probeRunLl(probesDir, libIncludeDir, outDir); err != nil {
		return fmt.Errorf("ll probe failed: %s", err)
	}

	return nil
}
