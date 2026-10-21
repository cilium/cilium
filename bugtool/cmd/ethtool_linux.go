// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package cmd

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
)

const (
	ethGStringLen = 32 // ETH_GSTRING_LEN
	ethSSStats    = 1  // ETH_SS_STATS
)

func ethtoolCommands() []string {
	links, err := safenetlink.LinkList()
	if err != nil {
		return nil
	}
	sources := make([]string, 0, len(links)*2)
	for _, link := range links {
		// query current settings
		sources = append(sources, fmt.Sprintf("ethtool %s", link.Attrs().Name))
		// query for driver information
		sources = append(sources, fmt.Sprintf("ethtool -i %s", link.Attrs().Name))
	}
	return sources
}

// dumpNICStats writes what `ethtool -S` prints for each link, since the agent image has no ethtool.
func dumpNICStats(cmdDir string) error {
	links, err := safenetlink.LinkList()
	if err != nil {
		return err
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	for _, link := range links {
		name := link.Attrs().Name
		stats, err := nicStats(fd, name)
		if err != nil || stats == "" {
			continue
		}
		prompt := "ethtool -S " + name
		content := "NIC statistics:\n" + stats
		if enableMarkdown {
			content = fmt.Sprintf("# %s\n\n```\n%s```\n", prompt, content)
		}
		file := filepath.Join(cmdDir, strings.ReplaceAll(prompt, " ", "-")+".md")
		if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func nicStats(fd int, name string) (string, error) {
	drv, err := unix.IoctlGetEthtoolDrvinfo(fd, name)
	if err != nil {
		return "", err
	}
	n := drv.N_stats
	if n == 0 {
		return "", nil
	}

	// struct ethtool_gstrings: cmd, string_set and len, then len names of ETH_GSTRING_LEN bytes.
	names := make([]byte, 12+int(n)*ethGStringLen)
	binary.NativeEndian.PutUint32(names[0:], unix.ETHTOOL_GSTRINGS)
	binary.NativeEndian.PutUint32(names[4:], ethSSStats)
	binary.NativeEndian.PutUint32(names[8:], n)
	if err := ethtoolIoctl(fd, name, names); err != nil {
		return "", err
	}

	// struct ethtool_stats: cmd and n_stats, then n_stats u64 values.
	values := make([]byte, 8+int(n)*8)
	binary.NativeEndian.PutUint32(values[0:], unix.ETHTOOL_GSTATS)
	binary.NativeEndian.PutUint32(values[4:], n)
	if err := ethtoolIoctl(fd, name, values); err != nil {
		return "", err
	}
	return formatNICStats(names, values)
}

// formatNICStats pairs the ETHTOOL_GSTRINGS and ETHTOOL_GSTATS replies into "name: value" lines.
func formatNICStats(names, values []byte) (string, error) {
	if len(names) < 12 || len(values) < 8 {
		return "", errors.New("short ethtool reply")
	}
	n := min(binary.NativeEndian.Uint32(names[8:]), binary.NativeEndian.Uint32(values[4:]))
	if len(names) < 12+int(n)*ethGStringLen || len(values) < 8+int(n)*8 {
		return "", errors.New("truncated ethtool reply")
	}
	var b strings.Builder
	for i := range int(n) {
		raw := names[12+i*ethGStringLen : 12+(i+1)*ethGStringLen]
		if end := strings.IndexByte(string(raw), 0); end >= 0 {
			raw = raw[:end]
		}
		fmt.Fprintf(&b, "     %s: %d\n", raw, binary.NativeEndian.Uint64(values[8+i*8:]))
	}
	return b.String(), nil
}

type ifreqData struct {
	name [unix.IFNAMSIZ]byte
	data unsafe.Pointer
	_    [24 - unsafe.Sizeof(uintptr(0))]byte
}

func ethtoolIoctl(fd int, name string, buf []byte) error {
	var ifr ifreqData
	copy(ifr.name[:unix.IFNAMSIZ-1], name)
	ifr.data = unsafe.Pointer(&buf[0])
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.SIOCETHTOOL), uintptr(unsafe.Pointer(&ifr)))
	runtime.KeepAlive(buf)
	if errno != 0 {
		return errno
	}
	return nil
}
