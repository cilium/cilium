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
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command/exec"

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

	if err = netlink.QdiscReplace(qdisc); err != nil {
		return fmt.Errorf("netlink: Replacing qdisc for %s failed: %s", ifName, err)
	} else {
		log.Debugf("netlink: Replacing qdisc for %s succeeded", ifName)
	}

	return nil
}

// replaceDatapath the qdisc and BPF program for a endpoint
func replaceDatapath(ctx context.Context, ifName, objPath, progSec, progDirection string) error {
	err := replaceQdisc(ifName)
	if err != nil {
		return fmt.Errorf("Failed to replace Qdisc for %s: %s", ifName, err)
	}

	// FIXME: Replace cilium-map-migrate with Golang map migration
	cmd := exec.CommandContext(ctx, "cilium-map-migrate", "-s", objPath)
	cmd.Env = bpf.Environment()
	if _, err = cmd.CombinedOutput(log, true); err != nil {
		return err
	}
	defer func() {
		var retCode string
		if err == nil {
			retCode = "0"
		} else {
			retCode = "1"
		}
		args := []string{"-e", objPath, "-r", retCode}
		cmd := exec.CommandContext(ctx, "cilium-map-migrate", args...)
		cmd.Env = bpf.Environment()
		_, _ = cmd.CombinedOutput(log, true) // ignore errors
	}()

	// FIXME: replace exec with native call
	args := []string{"filter", "replace", "dev", ifName, progDirection,
		"prio", "1", "handle", "1", "bpf", "da", "obj", objPath,
		"sec", progSec,
	}
	cmd = exec.CommandContext(ctx, "tc", args...).WithFilters(libbpfFixupMsg)
	_, err = cmd.CombinedOutput(log, true)
	if err != nil {
		return fmt.Errorf("Failed to load tc filter: %s", err)
	}

	return nil
}

// graftDatapath replaces obj in tail call map
func graftDatapath(ctx context.Context, mapPath, objPath, progSec string) error {
	var err error

	// FIXME: Replace cilium-map-migrate with Golang map migration
	cmd := exec.CommandContext(ctx, "cilium-map-migrate", "-s", objPath)
	cmd.Env = bpf.Environment()
	if _, err = cmd.CombinedOutput(log, true); err != nil {
		return err
	}
	defer func() {
		var retCode string
		if err == nil {
			retCode = "0"
		} else {
			retCode = "1"
		}
		args := []string{"-e", objPath, "-r", retCode}
		cmd := exec.CommandContext(ctx, "cilium-map-migrate", args...)
		cmd.Env = bpf.Environment()
		_, _ = cmd.CombinedOutput(log, true) // ignore errors
	}()

	// FIXME: replace exec with native call
	// FIXME: only key 0 right now, could be made more flexible
	args := []string{"exec", "bpf", "graft", mapPath, "key", "0",
		"obj", objPath, "sec", progSec,
	}
	cmd = exec.CommandContext(ctx, "tc", args...).WithFilters(libbpfFixupMsg)
	_, err = cmd.CombinedOutput(log, true)
	if err != nil {
		return fmt.Errorf("Failed to graft tc object: %s", err)
	}

	return nil
}

// DeleteDatapath filter from the given ifName
func DeleteDatapath(ctx context.Context, ifName, direction string) error {
	args := []string{"filter", "delete", "dev", ifName, direction, "pref", "1", "handle", "1", "bpf"}
	cmd := exec.CommandContext(ctx, "tc", args...).WithFilters(libbpfFixupMsg)
	_, err := cmd.CombinedOutput(log, true)
	if err != nil {
		return fmt.Errorf("Failed to remove tc filter: %s", err)
	}

	return nil
}
