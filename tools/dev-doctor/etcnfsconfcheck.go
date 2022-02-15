// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"os"

	"gopkg.in/ini.v1"
)

// An etcdNFSConfCheck checks /etc/nfs.conf.
type etcNFSConfCheck struct{}

func (etcNFSConfCheck) Name() string {
	return "/etc/nfs.conf"
}

func (etcNFSConfCheck) Run() (checkResult, string) {
	data, err := os.ReadFile("/etc/nfs.conf")
	switch {
	case os.IsNotExist(err):
		return checkError, "/etc/nfs.conf does not exist"
	case err != nil:
		return checkFailed, err.Error()
	}

	var nfsConf struct {
		NFSD struct {
			TCP string `ini:"tcp"`
		} `ini:"nfsd"`
	}
	if err := ini.MapTo(&nfsConf, data); err != nil {
		return checkError, err.Error()
	}

	switch {
	case nfsConf.NFSD.TCP == "":
		return checkError, `nfsd.tcp is not set, want "y"`
	case nfsConf.NFSD.TCP != "y":
		return checkError, fmt.Sprintf(`nfsd.tcp is %q, want "y"`, nfsConf.NFSD.TCP)
	}

	return checkOK, `nfsd.tcp is "y"`
}

func (etcNFSConfCheck) Hint() string {
	return `Ensure that /etc/nfs.conf includes "[nfsd]\ntcp=y\n".`
}
