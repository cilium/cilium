// Copyright 2021 Authors of Cilium
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

package ethtool

import (
	"bytes"
	"unsafe"

	"golang.org/x/sys/unix"
)

type ifreq struct {
	name [unix.IFNAMSIZ]byte
	data uintptr
}

type ethtoolDrvInfo struct {
	cmd         uint32
	driver      [32]byte
	version     [32]byte
	fwVersion   [32]byte
	busInfo     [32]byte
	eromVersion [32]byte
	reserved2   [12]byte
	nPrivFlags  uint32
	nStats      uint32
	testInfoLen uint32
	eedumpLen   uint32
	regdumpLen  uint32
}

func ethtoolIoctl(iface string, info *ethtoolDrvInfo) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_IP)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	var ifname [unix.IFNAMSIZ]byte
	copy(ifname[:], iface)
	req := ifreq{
		name: ifname,
		data: uintptr(unsafe.Pointer(info)),
	}
	_, _, ep := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCETHTOOL, uintptr(unsafe.Pointer(&req)))
	if ep != 0 {
		return ep
	}
	return nil
}

func GetDeviceName(iface string) (string, error) {
	info := ethtoolDrvInfo{
		cmd: unix.ETHTOOL_GDRVINFO,
	}

	if err := ethtoolIoctl(iface, &info); err != nil {
		return "", err
	}
	return string(bytes.Trim(info.driver[:], "\x00")), nil
}

func IsVirtualDriver(iface string) (bool, error) {
	drvName, err := GetDeviceName(iface)
	if err != nil {
		return false, err
	}

	return drvName == "veth", nil
}
