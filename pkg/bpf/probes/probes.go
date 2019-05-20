// Copyright 2019 Authors of Cilium
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
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/cilium/cilium/pkg/command/exec"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "probes")
)

func GenerateHeaders(featuresFile io.Writer) error {
	cmd := exec.WithTimeout(
		defaults.ExecTimeout, "bpftool", "feature", "probe", "macros")
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("could not start bpftool: %s", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf(
			"could not initialize stout pipe for bpftool: %s", err)
	}

	writer := bufio.NewWriter(featuresFile)
	defer writer.Flush()

	go io.Copy(writer, stdoutPipe)
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("bpftool did not run successfully: %s", err)
	}
	return nil
}

func Probes() error {
	globalsDir := option.Config.GetGlobalsDir()
	if err := os.MkdirAll(globalsDir, defaults.StateDirRights); err != nil {
		log.WithError(err).WithField(logfields.Path, globalsDir).Fatal("Could not create runtime directory")
	}
	featuresFilePath := filepath.Join(globalsDir, "bpf_features.h")
	featuresFile, err := os.Create(featuresFilePath)
	if err != nil {
		return fmt.Errorf("could not create features header file %s: %s",
			featuresFilePath, err)
	}
	defer featuresFile.Close()

	if err := GenerateHeaders(featuresFile); err != nil {
		return err
	}
	return nil
}
