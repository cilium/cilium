// Copyright 2019 Authors of Cilium
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

	"github.com/cilium/cilium/api/v1/client/policy"
)

var fqdnCmd = &cobra.Command{
	Use:   "fqdn",
	Short: "Manage fqdn proxy",
	Run:   func(cmd *cobra.Command, args []string) {},
}

var fqdnCacheCmd = &cobra.Command{
	Use:   "cache",
	Short: "Manage fqdn proxy cache",
	Run:   func(cmd *cobra.Command, args []string) {},
}

var fqdnCleanCacheCmd = &cobra.Command{
	Use:   "clean",
	Short: "Clean fqdn cache",
	Run: func(cmd *cobra.Command, args []string) {
		cleanFQDNCache()
	},
}

var fqdnCacheClearMatchPattern string

func init() {
	fqdnCacheCmd.AddCommand(fqdnCleanCacheCmd)
	fqdnCmd.AddCommand(fqdnCacheCmd)
	rootCmd.AddCommand(fqdnCmd)

	fqdnCleanCacheCmd.Flags().BoolVarP(&force, "force", "f", false, "Skip confirmation")
	fqdnCleanCacheCmd.Flags().StringVarP(&fqdnCacheClearMatchPattern, "pattern", "p", "", "Cache entries with fqdn matching the pattern will be deleted")
}

func cleanFQDNCache() {
	if !force && !confirmCleanup() {
		return
	}

	params := policy.NewDeleteFqdnCacheParams()

	if fqdnCacheClearMatchPattern != "" {
		params.SetMatchpattern(&fqdnCacheClearMatchPattern)
	}

	_, err := client.Policy.DeleteFqdnCache(params)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\n", err)
	}
	fmt.Println("FQDN proxy cache cleared")
}
