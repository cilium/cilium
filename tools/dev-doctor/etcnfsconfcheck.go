// Copyright 2020 Authors of Cilium
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

package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"gopkg.in/ini.v1"
)

// An etcdNFSConfCheck checks /etc/nfs.conf.
type etcNFSConfCheck struct{}

func (etcNFSConfCheck) Name() string {
	return "/etc/nfs.conf"
}

func (etcNFSConfCheck) Run() (checkResult, string) {
	data, err := ioutil.ReadFile("/etc/nfs.conf")
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
