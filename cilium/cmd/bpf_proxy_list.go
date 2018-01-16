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
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/proxy"

	"github.com/spf13/cobra"
)

const (
	proxyTitle       = "PROXY"
	destinationTitle = "DESTINATION"
)

var proxyList = map[string]string{}

// bpfProxyListCmd represents the bpf_proxy_list command
var bpfProxyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List proxy configuration",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf proxy list")
		proxy.Dump(dumpProxy4)
		proxy.Dump6(dumpProxy6)

		if len(dumpOutput) > 0 {
			if err := OutputPrinter(proxyList); err != nil {
				os.Exit(1)
			}
			return
		}

		w := tabwriter.NewWriter(os.Stdout, 5, 0, 3, ' ', 0)

		fmt.Fprintf(w, "%s\t%s\t\n", proxyTitle, destinationTitle)
		for k, v := range proxyList {
			fmt.Fprintf(w, "%s\t%s\t\n", k, v)
		}

		w.Flush()
	},
}

func init() {
	bpfProxyCmd.AddCommand(bpfProxyListCmd)
	AddMultipleOutput(bpfProxyListCmd)
}

func dumpProxy4(key bpf.MapKey, value bpf.MapValue) {
	proxyKey := key.(*proxy.Proxy4Key)
	proxyValue := value.(*proxy.Proxy4Value)
	proxyList[proxyKey.String()] = proxyValue.String()
}

func dumpProxy6(key bpf.MapKey, value bpf.MapValue) {
	proxyKey := key.(*proxy.Proxy6Key)
	proxyValue := value.(*proxy.Proxy6Value)
	proxyList[proxyKey.String()] = proxyValue.String()
}
