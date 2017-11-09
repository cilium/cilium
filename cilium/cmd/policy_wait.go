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
	"strconv"
	"time"

	"github.com/cilium/cilium/api/v1/models"

	"github.com/spf13/cobra"
)

var waitTime int
var policyWaitCmd = &cobra.Command{
	Use:   "wait <revision>",
	Short: "Wait for all endpoints to have updated to a given policy revision",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 || args[0] == "" {
			Usagef(cmd, "invalid revision")
		}

		reqRevision, err := strconv.ParseInt(args[0], 10, 64)
		if err != nil {
			Fatalf("invalid revision '%s': %s", args[0], err)
		}

		haveWaited := false

		for {
			eps, err := client.EndpointList()
			if err != nil {
				Fatalf("cannot list endpoints: %s\n", err)
			}

			needed := len(eps)
			ready := 0

			for _, ep := range eps {
				if ep.Policy != nil && ep.PolicyRevision >= reqRevision &&
					ep.State == models.EndpointStateReady {
					ready++
				}
			}

			if ready == needed {
				if haveWaited {
					fmt.Printf("\n")
				}
				return
			}

			fmt.Printf("\rWaiting for endpoints to run policy revision %d: %d/%d              ",
				reqRevision, ready, needed)
			time.Sleep(time.Duration(waitTime) * time.Second)
			haveWaited = true
		}
	},
}

func init() {
	policyCmd.AddCommand(policyWaitCmd)
	policyWaitCmd.Flags().IntVar(&waitTime, "sleep-time", 1, "Sleep interval between checks (seconds)")
}
