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

	"github.com/cilium/cilium/pkg/bpf"

	"github.com/vishvananda/netlink"
)

const (
	libbpfFixupMsg = "struct bpf_elf_map fixup performed due to size mismatch!"
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

	// Replacing the qdisc after the first creation will always fail with
	// the current netlink library due to the issue fixed in this PR:
	// https://github.com/vishvananda/netlink/pull/382
	//
	// FIXME GH-5423 rebase against the latest netlink library
	if err = netlink.QdiscReplace(qdisc); err != nil {
		log.WithError(err).Debugf("netlink: Replacing qdisc for %s failed", ifName)
	} else {
		log.Debugf("netlink: Replacing qdisc for %s succeeded", ifName)
	}

	return nil
}

// replaceDatapath the qdisc and BPF program for a endpoint
func replaceDatapath(ctx context.Context, ifName string, objPath string, progSec string) error {
	err := replaceQdisc(ifName)
	if err != nil {
		return fmt.Errorf("Failed to replace Qdisc for %s: %s", ifName, err)
	}

	// FIXME: Replace cilium-map-migrate with Golang map migration
	cmd := exec.CommandContext(ctx, "cilium-map-migrate", "-s", objPath)
	cmd.Env = bpf.Environment()
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("Command execution failed: Timeout")
	}
	if err != nil {
		scanner := bufio.NewScanner(bytes.NewReader(out))
		return fmt.Errorf("Failed to migrate endpoint maps: %s: %q", err, scanner.Text())
	}
	defer func() {
		var retCode string
		if err == nil {
			retCode = "0"
		} else {
			retCode = "1"
		}
		cmd := exec.CommandContext(ctx, "cilium-map-migrate", "-e", objPath, "-r", retCode)
		cmd.Env = bpf.Environment()
		out2, err2 := cmd.CombinedOutput()
		if ctx.Err() == context.DeadlineExceeded {
			err = fmt.Errorf("Command execution failed: Timeout")
		}
		if err2 != nil {
			scanner := bufio.NewScanner(bytes.NewReader(out2))
			log.Infof("Failed to migrate maps back after unsuccessful prog replace: %s: %q", err2, scanner.Text())
		}
	}()

	// FIXME: replace exec with native call
	args := []string{"filter", "replace", "dev", ifName, "ingress",
		"prio", "1", "handle", "1", "bpf", "da", "obj", objPath,
		"sec", progSec,
	}
	cmd = exec.CommandContext(ctx, "tc", args...)
	cmd.Env = bpf.Environment()
	out, err = cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("Command execution failed: Timeout")
	}
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
