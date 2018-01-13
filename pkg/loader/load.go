// Copyright 2017 Authors of Cilium
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
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/vishvananda/netlink"
)

const (
	libbpfFixupMsg = "struct bpf_elf_map fixup performed due to size mismatch!"
	// ExecTimeout is the execution timeout to use when compiling and replacing endpoint programs
	ExecTimeout = 30 * time.Second
)

var log = logging.DefaultLogger

// Replace the qdisc and BPF program for a endpoint
func Replace(ifName string, objPath string, progSec string) error {
	ctx, cancel := context.WithTimeout(context.Background(), ExecTimeout)
	defer cancel()

	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return err
	}
	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	// Ignore failure on replacing clsact,
	_ = netlink.QdiscReplace(qdisc)

	// FIXME: replace exec with native call
	out, err := exec.CommandContext(ctx, "tc", "filter", "replace", "dev", ifName,
		"ingress", "prio", "1", "handle", "1", "bpf", "da", "obj", objPath, "sec", progSec).CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return ctx.Err()
	}
	if err != nil {
		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			text := scanner.Text()
			if strings.Contains(text, libbpfFixupMsg) {
				return nil
			}
		}
		return fmt.Errorf("error: %q command output: %q", err, out)
	}

	return nil
}
