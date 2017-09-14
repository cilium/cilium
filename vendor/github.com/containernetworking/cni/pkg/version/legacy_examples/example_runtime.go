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

package legacy_examples

// An ExampleRuntime is a small program that uses libcni to invoke a network plugin.
// It should call ADD and DELETE, verifying all intermediate steps
// and data structures.
type ExampleRuntime struct {
	Example
	NetConfs []string // The network configuration names to pass
}

// NetConfs are various versioned network configuration files. Examples should
// specify which version they expect
var NetConfs = map[string]string{
	"unversioned": `{
	"name": "default",
	"type": "ptp",
	"ipam": {
		"type": "host-local",
		"subnet": "10.1.2.0/24"
	}
}`,
	"0.1.0": `{
	"cniVersion": "0.1.0",
	"name": "default",
	"type": "ptp",
	"ipam": {
		"type": "host-local",
		"subnet": "10.1.2.0/24"
	}
}`,
}

// V010_Runtime creates a simple ptp network configuration, then
// executes libcni against the currently-built plugins.
var V010_Runtime = ExampleRuntime{
	NetConfs: []string{"unversioned", "0.1.0"},
	Example: Example{
		Name:          "example_invoker_v010",
		CNIRepoGitRef: "c0d34c69", //version with ns.Do
		PluginSource: `package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"

	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/libcni"
)

func main(){
	code :=	exec()
	os.Exit(code)
}

func exec() int {
	confBytes, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		fmt.Printf("could not read netconfig from stdin: %+v", err)
		return 1
	}

	netConf, err := libcni.ConfFromBytes(confBytes)
	if err != nil {
		fmt.Printf("could not parse netconfig: %+v", err)
		return 1
	}
	fmt.Printf("Parsed network configuration: %+v\n", netConf.Network)

	if len(os.Args) == 1 {
		fmt.Printf("Expect CNI plugin paths in argv")
		return 1
	}

	targetNs, err := ns.NewNS()
	if err !=  nil {
		fmt.Printf("Could not create ns: %+v", err)
		return 1
	}
	defer targetNs.Close()

	ifName := "eth0"

	runtimeConf := &libcni.RuntimeConf{
		ContainerID: "some-container-id",
		NetNS:       targetNs.Path(),
		IfName:      ifName,
	}

	cniConfig := &libcni.CNIConfig{Path: os.Args[1:]}

	result, err := cniConfig.AddNetwork(netConf, runtimeConf)
	if err != nil {
		fmt.Printf("AddNetwork failed: %+v", err)
		return 2
	}
	fmt.Printf("AddNetwork result: %+v", result)

	expectedIP := result.IP4.IP

	err = targetNs.Do(func(ns.NetNS) error {
		netif, err := net.InterfaceByName(ifName)
		if err != nil {
			return fmt.Errorf("could not retrieve interface: %v", err)
		}

		addrs, err := netif.Addrs()
		if err != nil {
			return fmt.Errorf("could not retrieve addresses, %+v", err)
		}

		found := false
		for _, addr := range addrs {
			if addr.String() == expectedIP.String() {
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("Far-side link did not have expected address %s", expectedIP)
		}
		return nil
	})
	if err != nil {
		fmt.Println(err)
		return 4
	}

	err = cniConfig.DelNetwork(netConf, runtimeConf)
	if err != nil {
		fmt.Printf("DelNetwork failed: %v", err)
		return 5
	}

	err = targetNs.Do(func(ns.NetNS) error {
		_, err := net.InterfaceByName(ifName)
		if err == nil {
			return fmt.Errorf("interface was not deleted")
		}
		return nil
	})
	if err != nil {
		fmt.Println(err)
		return 6
	}

	return 0
}
`,
	},
}
