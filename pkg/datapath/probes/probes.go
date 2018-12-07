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

package probes

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

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/multierror"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "probes")

	localConfigLocations = []string{
		"/proc/config",
		fmt.Sprintf("/boot/config-%s", getKernelVersionStr()),
	}
	localConfigLocationsGz = []string{
		"/proc/config.gz",
	}
)

// fileWithCleanup is a wrapper for os.File which removes the file on closing
// when no bytes were written.
type fileWithCleanup struct {
	path string
	n    int
	*os.File
}

// Close closes the File, rendering it unusable for I/O. On files that support
// SetDeadline, any pending I/O operations will be canceled and return
// immediately with an error. If no bytes were written to the file, it will be
// removed after closing.
func (f *fileWithCleanup) Close() error {
	if err := f.File.Close(); err != nil {
		return fmt.Errorf("could not close file %s: %s", f.path, err)
	}
	if f.n == 0 {
		if err := os.Remove(f.path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("could not remove file %s: %s", f.path, err)
		}
	}
	return nil
}

// Sync commits the current contents of the file to stable storage. Typically,
// this means flushing the file system's in-memory copy of recently written
// data to disk.
func (f *fileWithCleanup) Sync() error {
	if err := f.File.Sync(); err != nil {
		return fmt.Errorf("could not sync file %s: %s", f.path, err)
	}
	return nil
}

// Write writes len(b) bytes to the File. It returns the number of bytes
// written and an error, if any. Write returns a non-nil error when n != len(b).
func (f *fileWithCleanup) Write(data []byte) (int, error) {
	n, err := f.File.Write(data)
	if err != nil {
		return n, fmt.Errorf("could not write to file %s: %s", f.path, err)
	}
	f.n += n
	return n, nil
}

func openOrCreate(path string) (*fileWithCleanup, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}
	return &fileWithCleanup{path: path, n: 0, File: f}, nil
}

// readKernelConfig finds the file with kernel configuration and returns its
// content.
func readKernelConfig(warningFile io.Writer) ([]byte, error) {
	for _, localConfigLocation := range localConfigLocations {
		if _, err := os.Stat(localConfigLocation); err == nil {
			fConfig, err := os.Open(localConfigLocation)
			if err != nil {
				return nil, err
			}
			return ioutil.ReadAll(fConfig)
		} else if !os.IsNotExist(err) {
			log.WithError(err).Warnf("error when getting stat of file %s", localConfigLocation)
		}
	}

	for _, localConfigLocation := range localConfigLocationsGz {
		if _, err := os.Stat(localConfigLocation); err == nil {
			fConfig, err := os.Open(localConfigLocation)
			if err != nil {
				return nil, err
			}

			gConfig, err := gzip.NewReader(fConfig)
			if err != nil {
				return nil, err
			}

			return ioutil.ReadAll(gConfig)
		} else if !os.IsNotExist(err) {
			log.WithError(err).Warnf("error when getting stat of file %s", localConfigLocation)
		}
	}

	if _, err := io.WriteString(warningFile, "BPF/probes: Missing kernel configuration\n"); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("missing kernel configuration")
}

// probeKernelConfig checks whether the kernel configuration contains required
// and optional parameters.
func probeKernelConfig(infoFile, warningFile io.Writer) (err error) {
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

	var config []byte
	config, err = readKernelConfig(warningFile)
	if err != nil {
		if _, err := io.WriteString(infoFile, "BPF/probes: Kernel config not found.\n"); err != nil {
			return err
		}
		return err
	}

	for _, param := range optionalParams {
		re := regexp.MustCompile(param)
		if !re.Match(config) {
			if _, err := io.WriteString(infoFile, fmt.Sprintf("BPF/probes: %s is not in kernel configuration\n", param)); err != nil {
				return err
			}
		}
	}
	for _, param := range requiredParams {
		re := regexp.MustCompile(param)
		if !re.Match(config) {
			if _, err := io.WriteString(warningFile, fmt.Sprintf("BPF/probes: %s is not in kernel configuration\n", param)); err != nil {
				return err
			}
			return fmt.Errorf("%s is not in kernel configuration", param)
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

// probeRunLl runs the probe for compiling the program with clang.
func probeRunLl(featureFile, infoFile io.Writer, probesDir, libIncludeDir, outDir string) (err error) {
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
			_, err = stderrBuf.WriteTo(infoFile)
			if err != nil {
				return err
			}
		}
		return nil
	})
	return
}

// writeFeatures wrtites definitions of features into the header file which is
// going to be used by BPF programs.
func writeFeatures(featureFile, infoFile, warningFile io.Writer, probesDir, libIncludeDir, outDir string) error {
	if _, err := io.WriteString(featureFile, `#ifndef BPF_FEATURES_H_
#define BPF_FEATURES_H_
`); err != nil {
		return err
	}
	if err := probeKernelConfig(infoFile, warningFile); err != nil {
		return fmt.Errorf("kernel config probe failed: %s", err)
	}
	if err := probeRunLl(featureFile, infoFile, probesDir, libIncludeDir, outDir); err != nil {
		return fmt.Errorf("ll probe failed: %s", err)
	}
	if _, err := io.WriteString(featureFile, "#endif /* BPF_FEATURES_H_ */\n"); err != nil {
		return err
	}
	return nil
}

// RunProbes runs probes for BPF features. It generates a header file for BPF
// programs and log files.
func RunProbes(bpfDir, stateDir string) error {
	var featureFile, infoFile, warningFile *fileWithCleanup
	var outDir string
	var errs *multierror.Multierror
	var err error

	probesDir := path.Join(bpfDir, "probes")
	libIncludeDir := path.Join(bpfDir, "include")
	featureFilePath := path.Join(stateDir, "globals", "bpf_features.h")
	infoFilePath := path.Join(stateDir, "bpf_features.log")
	warningFilePath := path.Join(stateDir, "bpf_requirements.log")

	os.Remove(infoFilePath)
	os.Remove(warningFilePath)

	featureFile, err = openOrCreate(featureFilePath)
	if err != nil {
		errs = multierror.Append(errs, err)
		goto cleanup
	}
	infoFile, err = openOrCreate(infoFilePath)
	if err != nil {
		errs = multierror.Append(errs, err)
		goto cleanup
	}
	warningFile, err = openOrCreate(warningFilePath)
	if err != nil {
		errs = multierror.Append(errs, err)
		goto cleanup
	}

	outDir, err = ioutil.TempDir("", "cilium-probes-out")
	if err != nil {
		err = fmt.Errorf("could not create temporary directory for probes: %s", err)
		errs = multierror.Append(errs, err)
		goto cleanup
	}
	defer os.RemoveAll(outDir)

	if err := writeFeatures(featureFile, infoFile, warningFile, probesDir, libIncludeDir, outDir); err != nil {
		errs = multierror.Append(errs, err)
		goto cleanup
	}

	if err := featureFile.Sync(); err != nil {
		errs = multierror.Append(errs, err)
		goto cleanup
	}
	if err := infoFile.Sync(); err != nil {
		errs = multierror.Append(errs, err)
		goto cleanup
	}
	if err := warningFile.Sync(); err != nil {
		errs = multierror.Append(errs, err)
		goto cleanup
	}

cleanup:
	if err := featureFile.Close(); err != nil {
		errs = multierror.Append(errs, err)
	}
	if err := infoFile.Close(); err != nil {
		errs = multierror.Append(errs, err)
	}
	if err := warningFile.Close(); err != nil {
		errs = multierror.Append(errs, err)
	}

	if errs != nil {
		return errs
	}
	return nil
}
