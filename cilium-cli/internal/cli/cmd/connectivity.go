// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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
	"time"

	"github.com/spf13/cobra"

	"github.com/cilium/cilium-cli/connectivity"
	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/sysdump"
)

var errInternal = errors.New("encountered internal error, exiting")

func newCmdConnectivity(hooks Hooks) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "connectivity",
		Short: "Connectivity troubleshooting",
		Long:  ``,
	}

	cmd.AddCommand(newCmdConnectivityTest(hooks))

	return cmd
}

var params = check.Parameters{
	Writer: os.Stdout,
	SysdumpOptions: sysdump.Options{
		LargeSysdumpAbortTimeout: sysdump.DefaultLargeSysdumpAbortTimeout,
		LargeSysdumpThreshold:    sysdump.DefaultLargeSysdumpThreshold,
		Writer:                   os.Stdout,
	},
}

var tests []string

func newCmdConnectivityTest(hooks Hooks) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Validate connectivity in cluster",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {
			params.CiliumNamespace = namespace

			for _, test := range tests {
				if strings.HasPrefix(test, "!") {
					rgx, err := regexp.Compile(strings.TrimPrefix(test, "!"))
					if err != nil {
						return fmt.Errorf("test filter: %w", err)
					}
					params.SkipTests = append(params.SkipTests, rgx)
				} else {
					rgx, err := regexp.Compile(test)
					if err != nil {
						return fmt.Errorf("test filter: %w", err)
					}
					params.RunTests = append(params.RunTests, rgx)
				}
			}

			// Instantiate the test harness.
			cc, err := check.NewConnectivityTest(k8sClient, params, version)
			if err != nil {
				return err
			}

			ctx, _ := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)

			if params.Timeout > 0 {
				timeoutCtx, cancelFunc := context.WithTimeoutCause(ctx, params.Timeout, fmt.Errorf("connectivity test suite timeout (%s) reached", params.Timeout))
				defer cancelFunc()
				ctx = timeoutCtx
			}

			go func() {
				<-ctx.Done()
				cc.Logf("Cancellation request (%s) received, cancelling tests...", context.Cause(ctx))
			}()

			done := make(chan struct{})
			var finished bool

			// Execute connectivity.Run() in its own goroutine, it might call Fatal()
			// and end the goroutine without returning.
			go func() {
				defer func() { done <- struct{}{} }()
				err = connectivity.Run(ctx, cc, hooks.AddConnectivityTests, hooks.SetupAndValidate)

				// If Fatal() was called in the test suite, the statement below won't fire.
				finished = true
			}()
			<-done

			if !finished {
				// Exit with a non-zero return code.
				return errInternal
			}

			if err != nil {
				return fmt.Errorf("connectivity test failed: %w", err)
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
	cmd.Flags().StringVar(&params.TestNamespace, "test-namespace", defaults.ConnectivityCheckNamespace, "Namespace to perform the connectivity test in")
	cmd.Flags().StringVar(&params.AgentDaemonSetName, "agent-daemonset-name", defaults.AgentDaemonSetName, "Name of cilium agent daemonset")
	cmd.Flags().StringVar(&params.AgentPodSelector, "agent-pod-selector", defaults.AgentPodSelector, "Label on cilium-agent pods to select with")
	cmd.Flags().StringToStringVar(&params.NodeSelector, "node-selector", map[string]string{}, "Restrict connectivity test pods to nodes matching this label")
	cmd.Flags().Var(&params.NamespaceAnnotations, "namespace-annotations", "Add annotations to the connectivity test namespace, e.g. '{\"foo\":\"bar\"}'")
	cmd.Flags().MarkHidden("namespace-annotations")
	cmd.Flags().Var(&params.DeploymentAnnotations, "deployment-pod-annotations", "Add annotations to the connectivity test pods, e.g. '{\"client\":{\"foo\":\"bar\"}}'")
	cmd.Flags().MarkHidden("deployment-pod-annotations")
	cmd.Flags().StringVar(&params.MultiCluster, "multi-cluster", "", "Test across clusters to given context")
	cmd.Flags().StringSliceVar(&tests, "test", []string{}, "Run tests that match one of the given regular expressions, skip tests by starting the expression with '!', target Scenarios with e.g. '/pod-to-cidr'")
	cmd.Flags().StringVar(&params.FlowValidation, "flow-validation", check.FlowValidationModeWarning, "Enable Hubble flow validation { disabled | warning | strict }")
	cmd.Flags().BoolVar(&params.AllFlows, "all-flows", false, "Print all flows during flow validation")
	cmd.Flags().StringVar(&params.AssumeCiliumVersion, "assume-cilium-version", "", "Assume Cilium version for connectivity tests")
	cmd.Flags().BoolVarP(&params.Verbose, "verbose", "v", false, "Show informational messages and don't buffer any lines")
	cmd.Flags().BoolVarP(&params.Debug, "debug", "d", false, "Show debug messages")
	cmd.Flags().BoolVarP(&params.Timestamp, "timestamp", "t", false, "Show timestamp in messages")
	cmd.Flags().BoolVarP(&params.PauseOnFail, "pause-on-fail", "p", false, "Pause execution on test failure")
	cmd.Flags().StringVar(&params.ExternalTarget, "external-target", "one.one.one.one", "Domain name to use as external target in connectivity tests")
	cmd.Flags().StringVar(&params.ExternalTargetCANamespace, "external-target-ca-namespace", defaults.ConnectivityCheckNamespace, "Namespace of the CA secret for the external target. Used by client-egress-l7-tls test cases.")
	cmd.Flags().StringVar(&params.ExternalTargetCAName, "external-target-ca-name", "cabundle", "Name of the CA secret for the external target. Used by client-egress-l7-tls test cases.")
	cmd.Flags().StringVar(&params.ExternalCIDR, "external-cidr", "1.0.0.0/8", "CIDR to use as external target in connectivity tests")
	cmd.Flags().StringVar(&params.ExternalIP, "external-ip", "1.1.1.1", "IP to use as external target in connectivity tests")
	cmd.Flags().StringVar(&params.ExternalOtherIP, "external-other-ip", "1.0.0.1", "Other IP to use as external target in connectivity tests")
	cmd.Flags().StringSliceVar(&params.NodeCIDRs, "node-cidr", nil, "one or more CIDRs that cover all nodes in the cluster")
	cmd.Flags().StringVar(&params.JunitFile, "junit-file", "", "Generate junit report and write to file")
	cmd.Flags().StringToStringVar(&params.JunitProperties, "junit-property", map[string]string{}, "Add key=value properties to the generated junit file")
	cmd.Flags().BoolVar(&params.SkipIPCacheCheck, "skip-ip-cache-check", true, "Skip IPCache check")
	cmd.Flags().MarkHidden("skip-ip-cache-check")
	cmd.Flags().BoolVar(&params.IncludeUnsafeTests, "include-unsafe-tests", false, "Include tests which can modify cluster nodes state")
	cmd.Flags().MarkHidden("include-unsafe-tests")
	cmd.Flags().BoolVar(&params.K8sLocalHostTest, "k8s-localhost-test", false, "Include tests which test for policy enforcement for the k8s entity on its own host")
	cmd.Flags().MarkHidden("k8s-localhost-test")

	cmd.Flags().StringVar(&params.K8sVersion, "k8s-version", "", "Kubernetes server version in case auto-detection fails")
	cmd.Flags().StringVar(&params.HelmChartDirectory, "chart-directory", "", "Helm chart directory")
	cmd.Flags().StringVar(&params.HelmValuesSecretName, "helm-values-secret-name", defaults.HelmValuesSecretName, "Secret name to store the auto-generated helm values file. The namespace is the same as where Cilium will be installed")

	cmd.Flags().StringSliceVar(&params.DeleteCiliumOnNodes, "delete-cilium-pod-on-nodes", []string{}, "List of node names from which Cilium pods will be delete before running tests")

	cmd.Flags().BoolVar(&params.Perf, "perf", false, "Run network Performance tests")
	cmd.Flags().DurationVar(&params.PerfDuration, "perf-duration", 10*time.Second, "Duration for the Performance test to run")
	cmd.Flags().IntVar(&params.PerfSamples, "perf-samples", 1, "Number of Performance samples to capture (how many times to run each test)")
	cmd.Flags().BoolVar(&params.PerfCRR, "perf-crr", false, "Run Netperf CRR Test. --perf-samples and --perf-duration ignored")
	cmd.Flags().BoolVar(&params.PerfHostNet, "host-net", false, "Use host networking during network performance tests")
	cmd.Flags().BoolVar(&params.PerfLatency, "perf-latency", false, "Run network latency tests")

	cmd.Flags().StringVar(&params.CurlImage, "curl-image", defaults.ConnectivityCheckAlpineCurlImage, "Image path to use for curl")
	cmd.Flags().StringVar(&params.PerformanceImage, "performance-image", defaults.ConnectivityPerformanceImage, "Image path to use for performance")
	cmd.Flags().StringVar(&params.JSONMockImage, "json-mock-image", defaults.ConnectivityCheckJSONMockImage, "Image path to use for json mock")
	cmd.Flags().StringVar(&params.DNSTestServerImage, "dns-test-server-image", defaults.ConnectivityDNSTestServerImage, "Image path to use for CoreDNS")

	cmd.Flags().UintVar(&params.Retry, "retry", defaults.ConnectRetry, "Number of retries on connection failure to external targets")
	cmd.Flags().DurationVar(&params.RetryDelay, "retry-delay", defaults.ConnectRetryDelay, "Delay between retries for external targets")

	cmd.Flags().DurationVar(&params.ConnectTimeout, "connect-timeout", defaults.ConnectTimeout, "Maximum time to allow initiation of the connection to take")
	cmd.Flags().DurationVar(&params.RequestTimeout, "request-timeout", defaults.RequestTimeout, "Maximum time to allow a request to take")
	cmd.Flags().BoolVar(&params.CurlInsecure, "curl-insecure", false, "Pass --insecure to curl")

	cmd.Flags().BoolVar(&params.CollectSysdumpOnFailure, "collect-sysdump-on-failure", false, "Collect sysdump after a test fails")

	initSysdumpFlags(cmd, &params.SysdumpOptions, "sysdump-", hooks)

	cmd.Flags().BoolVar(&params.IncludeConnDisruptTest, "include-conn-disrupt-test", false, "Include conn disrupt test")
	cmd.Flags().BoolVar(&params.ConnDisruptTestSetup, "conn-disrupt-test-setup", false, "Set up conn disrupt test dependencies")
	cmd.Flags().StringVar(&params.ConnDisruptTestRestartsPath, "conn-disrupt-test-restarts-path", "/tmp/cilium-conn-disrupt-restarts", "Conn disrupt test temporary result file (used internally)")
	cmd.Flags().StringVar(&params.ConnDisruptTestXfrmErrorsPath, "conn-disrupt-test-xfrm-errors-path", "/tmp/cilium-conn-disrupt-xfrm-errors", "Conn disrupt test temporary result file (used internally)")
	cmd.Flags().DurationVar(&params.ConnDisruptDispatchInterval, "conn-disrupt-dispatch-interval", 10*time.Millisecond, "TCP packet dispatch interval")
	cmd.Flags().BoolVar(&params.FlushCT, "flush-ct", false, "Flush conntrack of Cilium on each node")
	cmd.Flags().MarkHidden("flush-ct")
	cmd.Flags().StringVar(&params.SecondaryNetworkIface, "secondary-network-iface", "", "Secondary network iface name (e.g., to test NodePort BPF on multiple networks)")

	cmd.Flags().DurationVar(&params.Timeout, "timeout", defaults.ConnectivityTestSuiteTimeout, "Maximum time to allow the connectivity test suite to take")

	hooks.AddConnectivityTestFlags(cmd.Flags())

	return cmd
}
