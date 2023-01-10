// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package netns

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
)

// RemoveIfFromNetNSIfExists removes the given interface from the given
// network namespace.
//
// If the interface does not exist, no error will be returned.
func RemoveIfFromNetNSIfExists(netNS ns.NetNS, ifName string) error {
	return netNS.Do(func(_ ns.NetNS) error {
		l, err := netlink.LinkByName(ifName)
		if err != nil {
			if errors.As(err, &netlink.LinkNotFoundError{}) {
				return nil
			}
			return err
		}
		return netlink.LinkDel(l)
	})
}

// RemoveIfFromNetNSWithNameIfBothExist removes the given interface from
// the given network namespace identified by its name.
//
// If either the interface or the namespace do not exist, no error will
// be returned.
func RemoveIfFromNetNSWithNameIfBothExist(netNSName, ifName string) error {
	netNS, err := ns.GetNS(netNSPath(netNSName))
	if err != nil {
		if _, ok := err.(ns.NSPathNotExistErr); ok {
			return nil
		}
		return err
	}
	return RemoveIfFromNetNSIfExists(netNS, ifName)
}

// ReplaceNetNSWithName creates a network namespace with the given name and
// returns a handle to it. If such netns already exists from a previous run, it
// will be removed and then re-created to avoid any previous state of the
// netns.
//
// Example usage of this function:
//
//	netns0, err := netns.ReplaceNetNSWithName(netnsName)
//	if err != nil {
//	  return err
//	}
//	defer netns.RemoveNetNSWithName(netnsName)
//
//	netns0.Do(func(_ ns.NetNS) error {
//	  <logic to be executed within the new netns>
//	})
//
// FIXME: replace "ip-netns" invocations with native Go code
func ReplaceNetNSWithName(netNSName string) (ns.NetNS, error) {
	path := netNSPath(netNSName)

	if err := ns.IsNSorErr(path); err == nil {
		if err := exec.Command("ip", "netns", "del", netNSName).Run(); err != nil {
			return nil, fmt.Errorf("Unable to delete named netns %s: %s", netNSName, err)
		}
	}

	if err := exec.Command("ip", "netns", "add", netNSName).Run(); err != nil {
		return nil, fmt.Errorf("Unable to create named netns %s: %s", netNSName, err)
	}

	ns, err := ns.GetNS(path)
	if err != nil {
		return nil, fmt.Errorf("Unable to open netns %s: %s", path, err)
	}

	return ns, nil
}

// RemoveNetNSWithName removes the given named network namespace.
//
// FIXME: replace "ip-netns" invocations with native Go code
func RemoveNetNSWithName(netNSName string) error {
	if out, err := exec.Command("ip", "netns", "del", netNSName).CombinedOutput(); err != nil {
		return fmt.Errorf("Unable to delete named netns %s: %s %s", netNSName, out, err)
	}

	return nil
}

// ListNamedNetNSWithPrefix returns list of named network namespaces which name
// starts with the given prefix.
func ListNamedNetNSWithPrefix(prefix string) ([]string, error) {
	entries, err := os.ReadDir(netNSRootDir())
	if err != nil {
		return nil, err
	}

	ns := make([]string, 0)
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), prefix) {
			ns = append(ns, e.Name())
		}
	}

	return ns, nil
}

func netNSPath(name string) string {
	return filepath.Join(netNSRootDir(), name)
}

func netNSRootDir() string {
	return filepath.Join("/", "var", "run", "netns")
}
