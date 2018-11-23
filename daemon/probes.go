// Copyright 2018 Authors of Cilium
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
	"bytes"
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

var (
	localConfigLocations = []string{
		"/proc/config",
		fmt.Sprintf("/boot/config-%s", getKernelVersionStr()),
	}
	localConfigLocationsGz = []string{
		"/proc/config.gz",
	}
)

// readKernelConfig finds the file with kernel configuration and returns its
// content, number of bytes written to warningFile and error.
func readKernelConfig(warningFile io.Writer) (content []byte, warningFileBytes int, err error) {
	for _, localConfigLocation := range localConfigLocations {
		if _, err = os.Stat(localConfigLocation); err == nil {
			var fConfig *os.File
			fConfig, err = os.Open(localConfigLocation)
			if err != nil {
				return
			}
			content, err = ioutil.ReadAll(fConfig)
			return
		} else if !os.IsNotExist(err) {
			log.WithError(err).Warnf("error when getting stat of file %s", localConfigLocation)
		}
	}

	for _, localConfigLocation := range localConfigLocationsGz {
		if _, err = os.Stat(localConfigLocation); err == nil {
			var fConfig *os.File
			fConfig, err = os.Open(localConfigLocation)
			if err != nil {
				return
			}

			var gConfig io.Reader
			gConfig, err = gzip.NewReader(fConfig)
			if err != nil {
				return
			}

			content, err = ioutil.ReadAll(gConfig)
			return
		} else if !os.IsNotExist(err) {
			log.WithError(err).Warnf("error when getting stat of file %s", localConfigLocation)
		}
	}

	warningFileBytes, _ = io.WriteString(warningFile, "BPF/probes: Missing kernel configuration\n")
	err = fmt.Errorf("missing kernel configuration")
	return
}

// probeKernelConfig checks whether the kernel configuration contains required
// and optional parameters. It returns number of bytes written to infoFile,
// number of bytes written to warningFile and error.
func probeKernelConfig(infoFile, warningFile io.Writer) (infoFileBytes int, warningFileBytes int, err error) {
	optionalParams := []string{
		"CONFIG_CGROUP_BPF=y",
		"CONFIG_LWTUNNEL_BPF=y",
		"CONFIG_BPF_EVENTS=y",
	}
	requiredParams := []string{
		"CONFIG_BPF=y",
		"CONFIG_BPF_SYSCALL=y",
		"CONFIG_NET_SCH_INGRESS=(m|y)",
		"CONFIG_NET_CLS_BPF=(m|y)",
		"CONFIG_NET_CLS_ACT=y",
		"CONFIG_BPF_JIT=y",
		"CONFIG_HAVE_EBPF_JIT=y",
	}

	var n int
	var config []byte
	config, n, err = readKernelConfig(warningFile)
	warningFileBytes += n
	if err != nil {
		n, _ = io.WriteString(infoFile, "BPF/probes: Kernel config not found.\n")
		infoFileBytes += n
		return
	}

	for _, param := range optionalParams {
		re := regexp.MustCompile(param)
		if !re.Match(config) {
			n, _ := io.WriteString(infoFile, fmt.Sprintf("BPF/probes: %s is not in kernel configuration\n", param))
			infoFileBytes += n
		}
	}
	for _, param := range requiredParams {
		re := regexp.MustCompile(param)
		if !re.Match(config) {
			n, _ := io.WriteString(warningFile, fmt.Sprintf("BPF/probes: %s is not in kernel configuration\n", param))
			warningFileBytes += n
			err = fmt.Errorf("%s is not in kernel configuration", param)
			return
		}
	}

	return
}

// copyFile copies the file from source to destination. Before calling this
// function, there should be no file under destination path.
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

// probeRunLl runs the probe for compiling the program with clang. It returns
// number of bytes written to infoFile, number of bytes written to warningFile
// and error.
func probeRunLl(featureFile, infoFile io.Writer, probesDir, libIncludeDir, outDir string) (infoFileBytes int, err error) {
	outFilename := path.Join(outDir, "raw_probe.t")

	err = filepath.Walk(probesDir, func(probePath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if strings.HasSuffix(info.Name(), ".t") {
			outBin := path.Join(outDir, path.Base(probePath))
			if err := copyFile(probePath, outFilename); err != nil {
				return err
			}
			out, err := exec.Command(
				"clang",
				"-O2",
				"-Wall",
				fmt.Sprintf("-I%s", probesDir),
				fmt.Sprintf("-I%s", libIncludeDir),
				fmt.Sprintf("-I%s", outDir),
				path.Join(probesDir, "raw_main.c"),
				"-o",
				outBin,
			).CombinedOutput()
			if err != nil {
				return fmt.Errorf("clang failed: %s: %s", err, out)
			}

			var stdoutBuf, stderrBuf bytes.Buffer
			cmd := exec.Command(outBin)
			cmd.Stdout = &stdoutBuf
			cmd.Stderr = &stderrBuf
			if err := cmd.Run(); err != nil {
				return err
			}

			if _, err := stdoutBuf.WriteTo(featureFile); err != nil {
				return err
			}
			n, err := stderrBuf.WriteTo(infoFile)
			if err != nil {
				return err
			}
			infoFileBytes += int(n)
		}
		return nil
	})
	return
}

// writeFeatures wrtites definitions of features into the header file which is
// going to be used by BPF programs.
func writeFeatures(featureFile, infoFile, warningFile io.Writer, probesDir, libIncludeDir, outDir string) (infoFileBytes int, warningFileBytes int, err error) {
	io.WriteString(featureFile, `#ifndef BPF_FEATURES_H_
#define BPF_FEATURES_H_
`)

	var ni, nw int
	ni, nw, err = probeKernelConfig(infoFile, warningFile)
	if err != nil {
		err := fmt.Errorf("kernel config probe failed: %s", err)
		return infoFileBytes, warningFileBytes, err
	}
	infoFileBytes += ni
	warningFileBytes += nw

	var n int
	n, err = probeRunLl(featureFile, infoFile, probesDir, libIncludeDir, outDir)
	if err != nil {
		err := fmt.Errorf("ll probe failed: %s", err)
		return infoFileBytes, warningFileBytes, err
	}
	infoFileBytes += n

	io.WriteString(featureFile, "#endif /* BPF_FEATURES_H_ */\n")

	return
}

// runProbes runs probes for BPF features. It generates a header file for BPF
// programs and log files.
func runProbes(bpfDir, stateDir string) error {
	probesDir := path.Join(bpfDir, "probes")
	libIncludeDir := path.Join(bpfDir, "include")
	featureFilePath := path.Join(stateDir, "globals", "bpf_features.h")
	infoFilePath := path.Join(stateDir, "bpf_features.log")
	warningFilePath := path.Join(stateDir, "bpf_requirements.log")

	os.Remove(infoFilePath)
	os.Remove(warningFilePath)

	// File descriptors for feature, info and warning file.
	featureFile, err := os.OpenFile(featureFilePath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer featureFile.Close()
	infoFile, err := os.OpenFile(infoFilePath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	warningFile, err := os.OpenFile(warningFilePath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return err
	}

	// Create tempotary dir for probes.
	outDir, err := ioutil.TempDir("", "cilium-probes-out")
	if err != nil {
		return fmt.Errorf("could not create temporary directory for probes: %s", err)
	}
	defer os.RemoveAll(outDir)

	// Generate the content of features files, get count of bytes written
	// to info and warning file.
	infoFileBytes, warningFileBytes, err := writeFeatures(featureFile, infoFile, warningFile, probesDir, libIncludeDir, outDir)
	if err != nil {
		return err
	}

	// Remove info and warning files if nothing was written there.
	infoFile.Close()
	warningFile.Close()
	if infoFileBytes == 0 {
		os.Remove(infoFilePath)
	}
	if warningFileBytes == 0 {
		os.Remove(warningFilePath)
	}

	featureFile.Sync()
	infoFile.Sync()
	warningFile.Sync()

	return nil
}
