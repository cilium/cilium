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
	"net"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command/exec"
	"golang.org/x/sys/unix"

	"github.com/florianl/go-tc"
)

const (
	libbpfFixupMsg = "struct bpf_elf_map fixup performed due to size mismatch!"
)

func replaceQdisc(ifName string) error {

	devID, err := net.InterfaceByName(ifName)
	if err != nil {
		return err
	}

	qdisc := tc.Object{
		tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  tc.BuildHandle(tc.HandleIngress, 0x0000),
			Parent:  tc.HandleIngress,
		},
		tc.Attribute{
			Kind: "clsact",
		},
	}

	rtnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return err
	}
	defer func() {
		if err := rtnl.Close(); err != nil {
			log.Debugf("netlink: could not close rtnetlink socket: %v\n", err)
		}
	}()

	if err := rtnl.Qdisc().Replace(&qdisc); err != nil {
		return err
	}

	log.Debugf("netlink: Replacing qdisc for %s succeeded", ifName)

	return nil
}

// replaceDatapath the qdisc and BPF program for a endpoint
func (l *Loader) replaceDatapath(ctx context.Context, ifName, objPath, progSec, progDirection string) error {
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
func (l *Loader) DeleteDatapath(ctx context.Context, ifName, direction string) error {
	rtnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return err
	}
	defer func() {
		if err := rtnl.Close(); err != nil {
			log.Debugf("netlink: could not close rtnetlink socket: %v\n", err)
		}
	}()

	devID, err := net.InterfaceByName(ifName)
	if err != nil {
		return err
	}

	parent := tc.BuildHandle(tc.HandleIngress, tc.HandleMinIngress)
	if direction == "egress " {
		parent = tc.BuildHandle(tc.HandleIngress, tc.HandleMinEgress)
	}

	return rtnl.Filter().Delete(&tc.Object{
		tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),
			Handle:  1,
			Parent:  parent,
			Info:    0x10000,
		},
		tc.Attribute{
			Kind: "bpf",
		},
	})
}
