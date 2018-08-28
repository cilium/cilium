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

package loader

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// TODO: Rebase against https://github.com/cilium/cilium/pull/5286.
var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "datapath-loader")

// endpoint provides access to endpoint information that is necessary to
// compile and load the datapath.
type endpoint interface {
	InterfaceName() string
	Logger() *logrus.Entry
	StateDir() string
	StringID() string
}

// joinEP shells out to bpf/join_ep.sh to compile/load the BPF datapath for the
// specified endpoint, and handles timeouts if the loading takes too long.
func joinEP(ctx context.Context, ep endpoint, libdir, rundir, epdir, debug string) error {
	args := []string{libdir, rundir, epdir, debug, ep.InterfaceName(), ep.StringID()}
	prog := filepath.Join(libdir, "join_ep.sh")

	scopedLog := ep.Logger()

	joinEpCmd := exec.CommandContext(ctx, prog, args...)
	joinEpCmd.Env = bpf.Environment()
	out, err := joinEpCmd.CombinedOutput()

	cmd := fmt.Sprintf("%s %s", prog, strings.Join(args, " "))
	scopedLog = scopedLog.WithField("cmd", cmd)
	if ctx.Err() == context.DeadlineExceeded {
		scopedLog.Error("JoinEP: Command execution failed: Timeout")
		return ctx.Err()
	}
	if err != nil {
		scopedLog.WithError(err).Warn("JoinEP: Command execution failed")
		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			log.Warn(scanner.Text())
		}
		return fmt.Errorf("error: %q command output: %q", err, out)
	}

	return nil
}

// CompileAndLoad compiles the BPF datapath programs for the specified endpoint
// and loads it onto the interface associated with the endpoint.
//
// Expects the caller to have created the directory at the path ep.StateDir().
func CompileAndLoad(ctx context.Context, ep endpoint) error {
	if ep == nil {
		log.Fatalf("LoadBPF() doesn't support non-endpoint load")
	}

	libdir := option.Config.BpfDir
	rundir := option.Config.StateDir
	epdir := ep.StateDir()
	debug := strconv.FormatBool(viper.GetBool(option.BPFCompileDebugName))
	return joinEP(ctx, ep, libdir, rundir, epdir, debug)
}
