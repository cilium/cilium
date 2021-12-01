// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

//go:build windows
// +build windows

package logging

func setupSyslog(logOpts LogOptions, tag string, debug bool) error {
	return nil
}
