// Copyright 2018 Authors of Cilium
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
	"net"

	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/maps/lxcmap"

	"github.com/spf13/cobra"
)

var bpfEndpointDeleteCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete local endpoint entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf endpoint delete")

		if args[0] == "" {
			Fatalf("Please specify the endpoint to delete")
		}

		ip := net.ParseIP(args[0])
		if ip == nil {
			Fatalf("Unable to parse IP '%s'", args[0])
		}

		if err := lxcmap.DeleteEntry(ip); err != nil {
			Fatalf("Unable to delete endpoint entry: %s", err)
		}
	},
}

func init() {
	bpfEndpointCmd.AddCommand(bpfEndpointDeleteCmd)
}
