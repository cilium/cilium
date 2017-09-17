// Copyright 2016 CNI authors
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

package testutils

import (
	"io/ioutil"
	"os"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/version"
)

func envCleanup() {
	os.Unsetenv("CNI_COMMAND")
	os.Unsetenv("CNI_PATH")
	os.Unsetenv("CNI_NETNS")
	os.Unsetenv("CNI_IFNAME")
}

func CmdAddWithResult(cniNetns, cniIfname string, conf []byte, f func() error) (types.Result, []byte, error) {
	os.Setenv("CNI_COMMAND", "ADD")
	os.Setenv("CNI_PATH", os.Getenv("PATH"))
	os.Setenv("CNI_NETNS", cniNetns)
	os.Setenv("CNI_IFNAME", cniIfname)
	defer envCleanup()

	// Redirect stdout to capture plugin result
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}

	os.Stdout = w
	err = f()
	w.Close()

	var out []byte
	if err == nil {
		out, err = ioutil.ReadAll(r)
	}
	os.Stdout = oldStdout

	// Return errors after restoring stdout so Ginkgo will correctly
	// emit verbose error information on stdout
	if err != nil {
		return nil, nil, err
	}

	// Plugin must return result in same version as specified in netconf
	versionDecoder := &version.ConfigDecoder{}
	confVersion, err := versionDecoder.Decode(conf)
	if err != nil {
		return nil, nil, err
	}

	result, err := version.NewResult(confVersion, out)
	if err != nil {
		return nil, nil, err
	}

	return result, out, nil
}

func CmdDelWithResult(cniNetns, cniIfname string, f func() error) error {
	os.Setenv("CNI_COMMAND", "DEL")
	os.Setenv("CNI_PATH", os.Getenv("PATH"))
	os.Setenv("CNI_NETNS", cniNetns)
	os.Setenv("CNI_IFNAME", cniIfname)
	defer envCleanup()

	return f()
}
