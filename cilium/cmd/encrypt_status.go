// Copyright 2017 Authors of Cilium
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

package cmd

import (
	"fmt"
	"reflect"

	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/option"
	"github.com/prometheus/procfs"
	"github.com/vishvananda/netlink"

	"github.com/spf13/cobra"
)

const (
	// EncryptionModeDisabled captures enum value "Disabled"
	EncryptionModeDisabled string = "Disabled"

	// EncryptionModeIPsec captures enum value "IPsec"
	EncryptionModeIPsec string = "IPsec"

	// EncryptionModeWireguard captures enum value "Wireguard"
	EncryptionModeWireguard string = "Wireguard"
)

type void struct{}

var (
	voidType    void
	countErrors int
)

var encryptStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Display current state of IPSec configurations",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium encrypt status")
		dumpStatus()
	},
}

func init() {
	encryptCmd.AddCommand(encryptStatusCmd)
	command.AddJSONOutput(encryptStatusCmd)
}

func getIpsecmode() string {
	if option.Config.EnableIPSec {
		return EncryptionModeIPsec
	} else if option.Config.EnableWireguard {
		return EncryptionModeWireguard
	}
	return EncryptionModeDisabled
}

func getXfrmStats() (int, map[string]int) {
	fs, _ := procfs.NewDefaultFS()
	stats, _ := fs.NewXfrmStat()
	v := reflect.ValueOf(stats)

	errorMap := make(map[string]int)
	for i := 0; i < v.NumField(); i++ {
		name := v.Type().Field(i).Name
		value := v.Field(i).Interface().(int)
		if value != 0 {
			countErrors += value
			errorMap[name] = value
		}
	}
	return countErrors, errorMap
}

func countUniqueIpsecKeys() int {
	// trying to mimic set type data structure
	// using void data type as struct{} because it does not use any memory
	set := make(map[string]void)
	xfrmStates, _ := netlink.XfrmStateList(0)
	for _, v := range xfrmStates {
		set[string(v.Crypt.Key)] = voidType
	}
	return len(set)
}

func dumpStatus() {
	fmt.Printf("Status%-26s", getIpsecmode())
}
