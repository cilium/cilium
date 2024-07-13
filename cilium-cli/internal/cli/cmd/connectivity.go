// Copyright 2020-2021 Authors of Cilium
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
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"

	"github.com/cilium/cilium-cli/connectivity"
	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/defaults"

	"github.com/spf13/cobra"
)

var errInternal = errors.New("encountered internal error, exiting")

func newCmdConnectivity() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "connectivity",
		Short: "Connectivity troubleshooting",
		Long:  ``,
	}

	cmd.AddCommand(newCmdConnectivityTest())

	return cmd
}

var params = check.Parameters{
	Writer: os.Stdout,
}
var tests []string

func newCmdConnectivityTest() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Validate connectivity in cluster",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {

			for _, test := range tests {
				if strings.HasPrefix(test, "!") {
					rgx, err := regexp.Compile(strings.TrimPrefix(test, "!"))
					if err != nil {
						return fmt.Errorf("Test filter: %w", err)
					}
					params.SkipTests = append(params.SkipTests, rgx)
				} else {
					rgx, err := regexp.Compile(test)
					if err != nil {
						return fmt.Errorf("Test filter: %w", err)
					}
					params.RunTests = append(params.RunTests, rgx)
				}
			}

			// Instantiate the test harness.
			cc, err := check.NewConnectivityTest(k8sClient, params)

			if err != nil {
				return err
			}

			ctx, _ := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)

			go func() {
				<-ctx.Done()
				cc.Log("Interrupt received, cancelling tests...")
			}()

			done := make(chan struct{})
			var finished bool

			// Execute connectivity.Run() in its own goroutine, it might call Fatal()
			// and end the goroutine without returning.
			go func() {
				defer func() { done <- struct{}{} }()
				err = connectivity.Run(ctx, cc)

				// If Fatal() was called in the test suite, the statement below won't fire.
				finished = true
			}()
			<-done

			if !finished {
				// Exit with a non-zero return code.
				return errInternal
			}

			if err != nil {
				return fmt.Errorf("Connectivity test failed: %w", err)
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&params.SingleNode, "single-node", false, "Limit to tests able to run on a single node")
	cmd.Flags().BoolVar(&params.PrintFlows, "print-flows", false, "Print flow logs for each test")
	cmd.Flags().DurationVar(&params.PostTestSleepDuration, "post-test-sleep", 0, "Wait time after each test before next test starts")
	cmd.Flags().BoolVar(&params.ForceDeploy, "force-deploy", false, "Force re-deploying test artifacts")
	cmd.Flags().BoolVar(&params.Hubble, "hubble", true, "Automatically use Hubble for flow validation & troubleshooting")
	cmd.Flags().StringVar(&params.HubbleServer, "hubble-server", "localhost:4245", "Address of the Hubble endpoint for flow validation")
	cmd.Flags().StringVarP(&params.CiliumNamespace, "namespace", "n", "kube-system", "Namespace Cilium is running in")
	cmd.Flags().StringVar(&params.TestNamespace, "test-namespace", defaults.ConnectivityCheckNamespace, "Namespace to perform the connectivity test in")
	cmd.Flags().StringVar(&params.MultiCluster, "multi-cluster", "", "Test across clusters to given context")
	cmd.Flags().StringVar(&contextName, "context", "", "Kubernetes configuration context")
	cmd.Flags().StringSliceVar(&tests, "test", []string{}, "Run tests that match one of the given regular expressions, skip tests by starting the expression with '!', target Scenarios with e.g. '/pod-to-cidr'")
	cmd.Flags().StringVar(&params.FlowValidation, "flow-validation", check.FlowValidationModeWarning, "Enable Hubble flow validation { disabled | warning | strict }")
	cmd.Flags().BoolVar(&params.AllFlows, "all-flows", false, "Print all flows during flow validation")
	cmd.Flags().BoolVarP(&params.Verbose, "verbose", "v", false, "Show informational messages and don't buffer any lines")
	cmd.Flags().BoolVarP(&params.Debug, "debug", "d", false, "Show debug messages")
	cmd.Flags().BoolVarP(&params.PauseOnFail, "pause-on-fail", "p", false, "Pause execution on test failure")

	return cmd
}
