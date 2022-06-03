// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"os"
	"path"
	"strings"
)

// This tool attempts to write a sysctl config file to the sysctl config directory with the highest precedence so
// we can overwrite any other config and ensure correct sysctl options for Cilium to function.

const (
	sysctlD = "/etc/sysctl.d/"
	// The 99-zzz prefix ensures our config file gets precedence over most if not all other files.
	ciliumOverwrites = "99-zzz-override_cilium.conf"
)

var sysctlConfig = strings.Join([]string{
	"# Disable rp_filter on Cilium interfaces since it may cause mangled packets to be dropped",
	"net.ipv4.conf.lxc*.rp_filter = 0",
	"net.ipv4.conf.cilium_*.rp_filter = 0",
	"",
}, "\n")

// This program is executed by an init container so we purposely don't
// exit with any error codes. In case of errors, the function will print warnings,
// but we don't block cilium agent pod from running.
func main() {
	info, err := os.Stat(sysctlD)
	if err != nil {
		fmt.Printf("can't stat sysctl.d dir '%s': %s", sysctlD, err)
		return
	}

	if !info.IsDir() {
		fmt.Printf("'%s' is not a directory", sysctlD)
		return
	}

	overwritesPath := path.Join(sysctlD, ciliumOverwrites)
	f, err := os.OpenFile(overwritesPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		fmt.Printf("unable to create cilium sysctl overwrites config: %s", err)
		return
	}
	defer f.Close()

	_, err = fmt.Fprint(f, sysctlConfig)
	if err != nil {
		fmt.Printf("error while writing to sysctl config: %s", err)
		return
	}

	fmt.Println("sysctl config written")
}
