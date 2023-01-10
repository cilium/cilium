// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"time"

	"github.com/coreos/go-systemd/v22/dbus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/safeio"
)

// This tool attempts to write a sysctl config file to the sysctl config directory with the highest precedence so
// we can overwrite any other config and ensure correct sysctl options for Cilium to function.

var (
	flagSet = pflag.NewFlagSet(os.Args[0], pflag.ContinueOnError)

	sysctlD = flagSet.String("sysctl-conf-dir", "/etc/sysctl.d/", "Path to the sysctl config directory")
	// The 99-zzz prefix ensures our config file gets precedence over most if not all other files.
	ciliumOverwrites = flagSet.String(
		"sysctl-config-file",
		"99-zzz-override_cilium.conf",
		"Filename of the cilium sysctl overwrites config file",
	)
	// Name of the systemd-sysctl unit to restart after making changes
	sysctlUnit = flagSet.String(
		"systemd-sysctl-unit",
		"systemd-sysctl.service",
		"Name of the systemd sysctl unit to reload",
	)
)

var sysctlConfig = `
# Disable rp_filter on Cilium interfaces since it may cause mangled packets to be dropped
-net.ipv4.conf.lxc*.rp_filter = 0
-net.ipv4.conf.cilium_*.rp_filter = 0
# The kernel uses max(conf.all, conf.{dev}) as its value, so we need to set .all. to 0 as well.
# Otherwise it will overrule the device specific settings.
net.ipv4.conf.all.rp_filter = 0
`

// This program is executed by an init container so we purposely don't
// exit with any error codes. In case of errors, the function will print warnings,
// but we don't block cilium agent pod from running.
func main() {
	err := flagSet.Parse(os.Args[1:])
	if err != nil {
		fmt.Printf("parse flags: %s\n", err)
		return
	}

	info, err := os.Stat(*sysctlD)
	if err != nil {
		fmt.Printf("can't stat sysctl.d dir '%s': %s\n", *sysctlD, err)
		return
	}

	if !info.IsDir() {
		fmt.Printf("'%s' is not a directory\n", *sysctlD)
		return
	}

	overwritesPath := path.Join(*sysctlD, *ciliumOverwrites)
	f, err := os.OpenFile(overwritesPath, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		fmt.Printf("unable to create cilium sysctl overwrites config: %s\n", err)
		return
	}
	defer f.Close()

	currentContents, err := safeio.ReadAllLimit(f, safeio.MB)
	if err != nil {
		fmt.Printf("read config: %s\n", err)
		return
	}

	if string(currentContents) == sysctlConfig {
		fmt.Println("sysctl config up-to-date, nothing to do")
		return
	}

	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		fmt.Printf("error while seeking to start of sysctl config: %s\n", err)
		return
	}

	// Truncate the whole file
	err = f.Truncate(0)
	if err != nil {
		fmt.Printf("error while truncating sysctl config: %s\n", err)
		return
	}

	_, err = fmt.Fprint(f, sysctlConfig)
	if err != nil {
		fmt.Printf("error while writing to sysctl config: %s\n", err)
		return
	}

	fmt.Println("sysctl config created/updated")

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	conn, err := dbus.NewSystemdConnectionContext(ctx)
	if err != nil {
		fmt.Printf("error while creating SystemD D-Bus connection: %s\n", err)
		return
	}

	_, err = conn.GetUnitPropertiesContext(ctx, *sysctlUnit)
	if err != nil {
		fmt.Printf("can't verify unit '%s' exists: %s\n", *sysctlUnit, err)
		return
	}

	// https://www.freedesktop.org/wiki/Software/systemd/dbus/
	// "The mode needs to be one of replace, fail, isolate, ignore-dependencies, ignore-requirements.
	//  If "replace" the call will start the unit and its dependencies, possibly replacing already queued jobs that
	//  conflict with this."
	const mode = "replace"

	// Restart the systemd-sysctl unit, this will trigger SystemD to apply the new config to all existing interfaces
	// which is required for host-interfaces and reloads on existing cilium deployments.
	_, err = conn.RestartUnitContext(ctx, *sysctlUnit, mode, nil)
	if err != nil {
		fmt.Printf("error while restarting unit '%s': %s\n", *sysctlUnit, err)
		return
	}

	fmt.Printf("systemd unit '%s' restarted\n", *sysctlUnit)
}
