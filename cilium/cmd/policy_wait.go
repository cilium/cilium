// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium/api/v1/models"
)

var waitTime, failWaitTime, maxWaitTime int
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

		startTime := time.Now()
		failDeadline := startTime.Add(time.Duration(failWaitTime) * time.Second)
		maxDeadline := startTime.Add(time.Duration(maxWaitTime) * time.Second)

		haveWaited := false

		for {
			eps, err := client.EndpointList()
			if err != nil {
				Fatalf("cannot list endpoints: %s\n", err)
			}

			needed := len(eps)
			ready := 0
			notReady := 0

			for _, ep := range eps {
				switch {
				case ep.Status.Policy == nil || ep.Status.Policy.Realized == nil || ep.Status.State == nil:
					notReady++

				case ep.Status.Policy.Realized.PolicyRevision >= reqRevision &&
					*ep.Status.State == models.EndpointStateReady:
					ready++

				case *ep.Status.State == models.EndpointStateNotDashReady:
					notReady++
				}
			}

			if ready == needed {
				if haveWaited {
					fmt.Printf("\n")
				}
				return
			} else if time.Now().After(failDeadline) && notReady > 0 {
				// Fail earlier if any endpoints have a failed state
				Fatalf("\n%d endpoints have failed regeneration after %s\n", notReady, time.Since(startTime))
			} else if time.Now().After(maxDeadline) {
				// Fail after timeout
				Fatalf("\n%d endpoints still not ready after %s (%d failed)\n", needed-ready, time.Since(startTime), notReady)
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
	policyWaitCmd.Flags().IntVar(&failWaitTime, "fail-wait-time", 60, "Wait time after which command fails if endpoint regeration fails (seconds)")
	policyWaitCmd.Flags().IntVar(&maxWaitTime, "max-wait-time", 360, "Wait time after which command fails (seconds)")
}
