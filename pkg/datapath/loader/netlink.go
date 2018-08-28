// Copyright 2017-2018 Authors of Cilium
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

	"github.com/vishvananda/netlink"
)

const (
	libbpfFixupMsg = "struct bpf_elf_map fixup performed due to size mismatch!"

	// ExecTimeout is the execution timeout to use in join_ep.sh executions
	ExecTimeout = 300 * time.Second
)

func replaceQdisc(ifName string) error {
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

	// Ignore failure on replacing clsact, means we replaced it.
	_ = netlink.QdiscReplace(qdisc)
	return nil
}

// replaceDatapath the qdisc and BPF program for a endpoint
func replaceDatapath(ifName string, objPath string, progSec string) error {
	ctx, cancel := context.WithTimeout(context.Background(), ExecTimeout)
	defer cancel()

	err := replaceQdisc(ifName)
	if err != nil {
		return fmt.Errorf("Failed to replace Qdisc for %s: %s", ifName, err)
	}

	// FIXME: Replace cilium-map-migrate with Golang map migration
	out, err := exec.CommandContext(ctx, "cilium-map-migrate", "-s", objPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("Failed to migrate endpoint maps: %s", err)
	}
	defer func() {
		var retCode string
		if err == nil {
			retCode = "0"
		} else {
			retCode = "1"
		}
		out2, err2 := exec.CommandContext(ctx, "cilium-map-migrate", "-e", objPath, "-r", retCode).CombinedOutput()
		if err2 != nil {
			log.Infof("Failed to migrate maps back after unsuccessful prog replace: %s: %q", err2, out2)
		}
	}()

	// FIXME: replace exec with native call
	out, err = exec.CommandContext(ctx, "tc", "filter", "replace", "dev", ifName,
		"ingress", "prio", "1", "handle", "1", "bpf", "da", "obj", objPath, "sec", progSec).CombinedOutput()
	if err != nil {
		filteredOutput := bytes.NewBuffer(make([]byte, 0, len(out)))
		scanner := bufio.NewScanner(bytes.NewReader(out))
		for scanner.Scan() {
			text := scanner.Text()
			if !strings.Contains(text, libbpfFixupMsg) {
				_, err2 := filteredOutput.WriteString(text)
				if err2 != nil {
					log.WithError(err2).Debugf("Cannot buffer tc failure output: %s: %q", err2, text)
				}
			}
		}
		return fmt.Errorf("Failed to load tc filter: %s: %q", err, filteredOutput)
	}

	return nil
}
