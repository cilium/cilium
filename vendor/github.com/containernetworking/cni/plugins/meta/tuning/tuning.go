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

// This is a "meta-plugin". It reads in its own netconf, it does not create
// any network interface but just changes the network sysctl.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
)

// TuningConf represents the network tuning configuration.
type TuningConf struct {
	types.NetConf
	SysCtl map[string]string `json:"sysctl"`
}

func cmdAdd(args *skel.CmdArgs) error {
	tuningConf := TuningConf{}
	if err := json.Unmarshal(args.StdinData, &tuningConf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}

	// The directory /proc/sys/net is per network namespace. Enter in the
	// network namespace before writing on it.

	err := ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		for key, value := range tuningConf.SysCtl {
			fileName := filepath.Join("/proc/sys", strings.Replace(key, ".", "/", -1))
			fileName = filepath.Clean(fileName)

			// Refuse to modify sysctl parameters that don't belong
			// to the network subsystem.
			if !strings.HasPrefix(fileName, "/proc/sys/net/") {
				return fmt.Errorf("invalid net sysctl key: %q", key)
			}
			content := []byte(value)
			err := ioutil.WriteFile(fileName, content, 0644)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	result := current.Result{}
	return result.Print()
}

func cmdDel(args *skel.CmdArgs) error {
	// TODO: the settings are not reverted to the previous values. Reverting the
	// settings is not useful when the whole container goes away but it could be
	// useful in scenarios where plugins are added and removed at runtime.
	return nil
}

func main() {
	skel.PluginMain(cmdAdd, cmdDel, version.All)
}
