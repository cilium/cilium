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

	"github.com/spf13/cobra"
)

// pingCmd represents the ping command
var pingCmd = &cobra.Command{
	Use:   "ping",
	Short: "Check whether the cilium-health API is up",
	Run: func(cmd *cobra.Command, args []string) {
		_, err := client.Restapi.GetHealthz(nil)
		if err != nil {
			Fatalf("Cannot ping: %s\n", err)
		}
		fmt.Println("OK")
	},
}

func init() {
	rootCmd.AddCommand(pingCmd)
}
