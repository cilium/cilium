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
	"os"

	"github.com/spf13/cobra"
)

var fqdnCleanCacheCmd = &cobra.Command{
	Use:   "fqdn-clean-cache",
	Short: "Clean fqdn cache",
	Run: func(cmd *cobra.Command, args []string) {
		cleanFQDNCache()
	},
}

func init() {
	rootCmd.AddCommand(fqdnCleanCacheCmd)
	fqdnCleanCacheCmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation")
}

func cleanFQDNCache() {
	if !force && !confirmCleanup() {
		return
	}

	_, err := client.Policy.DeleteFqdnCache(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	}
	fmt.Println("FQDN proxy cache cleared")
}
