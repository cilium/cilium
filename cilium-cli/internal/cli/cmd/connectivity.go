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
	SysdumpOptions: sysdump.Options{
		LargeSysdumpAbortTimeout: sysdump.DefaultLargeSysdumpAbortTimeout,
		LargeSysdumpThreshold:    sysdump.DefaultLargeSysdumpThreshold,
		Writer:                   os.Stdout,
	},
}
var tests []string

func newCmdConnectivityTest() *cobra.Command {
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
			cc, err := check.NewConnectivityTest(k8sClient, params, Version)
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
	cmd.Flags().StringVar(&params.MultiCluster, "multi-cluster", "", "Test across clusters to given context")
	cmd.Flags().StringSliceVar(&tests, "test", []string{}, "Run tests that match one of the given regular expressions, skip tests by starting the expression with '!', target Scenarios with e.g. '/pod-to-cidr'")
	cmd.Flags().StringVar(&params.FlowValidation, "flow-validation", check.FlowValidationModeWarning, "Enable Hubble flow validation { disabled | warning | strict }")
	cmd.Flags().BoolVar(&params.AllFlows, "all-flows", false, "Print all flows during flow validation")
	cmd.Flags().StringVar(&params.AssumeCiliumVersion, "assume-cilium-version", "", "Assume Cilium version for connectivity tests")
	cmd.Flags().BoolVarP(&params.Verbose, "verbose", "v", false, "Show informational messages and don't buffer any lines")
	cmd.Flags().BoolVarP(&params.Debug, "debug", "d", false, "Show debug messages")
	cmd.Flags().BoolVarP(&params.Timestamp, "timestamp", "t", false, "Show timestamp in messages")
	cmd.Flags().BoolVarP(&params.PauseOnFail, "pause-on-fail", "p", false, "Pause execution on test failure")
	cmd.Flags().BoolVar(&params.SkipIPCacheCheck, "skip-ip-cache-check", true, "Skip IPCache check")
	cmd.Flags().MarkHidden("skip-ip-cache-check")
	cmd.Flags().BoolVar(&params.Datapath, "datapath", false, "Run datapath conformance tests")
	cmd.Flags().MarkHidden("datapath")

	cmd.Flags().StringVar(&params.K8sVersion, "k8s-version", "", "Kubernetes server version in case auto-detection fails")
	cmd.Flags().StringVar(&params.HelmChartDirectory, "chart-directory", "", "Helm chart directory")
	cmd.Flags().StringVar(&params.HelmValuesSecretName, "helm-values-secret-name", defaults.HelmValuesSecretName, "Secret name to store the auto-generated helm values file. The namespace is the same as where Cilium will be installed")

	cmd.Flags().StringSliceVar(&params.DeleteCiliumOnNodes, "delete-cilium-pod-on-nodes", []string{}, "List of node names from which Cilium pods will be delete before running tests")

	cmd.Flags().BoolVar(&params.Perf, "perf", false, "Run network Performance tests")
	cmd.Flags().DurationVar(&params.PerfDuration, "perf-duration", 10*time.Second, "Duration for the Performance test to run")
	cmd.Flags().IntVar(&params.PerfSamples, "perf-samples", 1, "Number of Performance samples to capture (how many times to run each test)")
	cmd.Flags().BoolVar(&params.PerfCRR, "perf-crr", false, "Run Netperf CRR Test. --perf-samples and --perf-duration ignored")
	cmd.Flags().BoolVar(&params.PerfHostNet, "host-net", false, "Use host networking during network performance tests")

	cmd.Flags().StringVar(&params.CurlImage, "curl-image", defaults.ConnectivityCheckAlpineCurlImage, "Image path to use for curl")
	cmd.Flags().StringVar(&params.PerformanceImage, "performance-image", defaults.ConnectivityPerformanceImage, "Image path to use for performance")
	cmd.Flags().StringVar(&params.JSONMockImage, "json-mock-image", defaults.ConnectivityCheckJSONMockImage, "Image path to use for json mock")
	cmd.Flags().StringVar(&params.DNSTestServerImage, "dns-test-server-image", defaults.ConnectivityDNSTestServerImage, "Image path to use for CoreDNS")

	cmd.Flags().BoolVar(&params.CollectSysdumpOnFailure, "collect-sysdump-on-failure", false, "Collect sysdump after a test fails")

	cmd.Flags().StringVar(&params.SysdumpOptions.CiliumLabelSelector, "sysdump-cilium-label-selector", sysdump.DefaultCiliumLabelSelector, "The labels used to target Cilium pods")
	cmd.Flags().StringVar(&params.SysdumpOptions.CiliumNamespace, "sysdump-cilium-namespace", "", "The namespace Cilium is running in")
	cmd.Flags().StringVar(&params.SysdumpOptions.CiliumOperatorNamespace, "sysdump-cilium-operator-namespace", "", "The namespace Cilium operator is running in")
	cmd.Flags().StringVar(&params.SysdumpOptions.CiliumDaemonSetSelector, "sysdump-cilium-daemon-set-label-selector", sysdump.DefaultCiliumLabelSelector, "The labels used to target Cilium daemon set")
	cmd.Flags().StringVar(&params.SysdumpOptions.CiliumOperatorLabelSelector, "sysdump-cilium-operator-label-selector", sysdump.DefaultCiliumOperatorLabelSelector, "The labels used to target Cilium operator pods")
	cmd.Flags().StringVar(&params.SysdumpOptions.ClustermeshApiserverLabelSelector, "sysdump-clustermesh-apiserver-label-selector", sysdump.DefaultClustermeshApiserverLabelSelector, "The labels used to target 'clustermesh-apiserver' pods")
	cmd.Flags().BoolVar(&params.SysdumpOptions.Debug, "sysdump-debug", sysdump.DefaultDebug, "Whether to enable debug logging")
	cmd.Flags().StringArrayVar(&params.SysdumpOptions.ExtraLabelSelectors, "sysdump-extra-label-selectors", nil, "Optional set of labels selectors used to target additional pods for log collection.")
	cmd.Flags().StringVar(&params.SysdumpOptions.HubbleLabelSelector, "sysdump-hubble-label-selector", sysdump.DefaultHubbleLabelSelector, "The labels used to target Hubble pods")
	cmd.Flags().Int64Var(&params.SysdumpOptions.HubbleFlowsCount, "sysdump-hubble-flows-count", sysdump.DefaultHubbleFlowsCount, "Number of Hubble flows to collect. Setting to zero disables collecting Hubble flows.")
	cmd.Flags().DurationVar(&params.SysdumpOptions.HubbleFlowsTimeout, "sysdump-hubble-flows-timeout", sysdump.DefaultHubbleFlowsTimeout, "Timeout for collecting Hubble flows")
	cmd.Flags().StringVar(&params.SysdumpOptions.HubbleRelayLabelSelector, "sysdump-hubble-relay-labels", sysdump.DefaultHubbleRelayLabelSelector, "The labels used to target Hubble Relay pods")
	cmd.Flags().StringVar(&params.SysdumpOptions.HubbleUILabelSelector, "sysdump-hubble-ui-labels", sysdump.DefaultHubbleUILabelSelector, "The labels used to target Hubble UI pods")
	cmd.Flags().Int64Var(&params.SysdumpOptions.LogsLimitBytes, "sysdump-logs-limit-bytes", sysdump.DefaultLogsLimitBytes, "The limit on the number of bytes to retrieve when collecting logs")
	cmd.Flags().DurationVar(&params.SysdumpOptions.LogsSinceTime, "sysdump-logs-since-time", sysdump.DefaultLogsSinceTime, "How far back in time to go when collecting logs")
	cmd.Flags().StringVar(&params.SysdumpOptions.NodeList, "sysdump-node-list", sysdump.DefaultNodeList, "Comma-separated list of node IPs or names to filter pods for which to collect gops and logs")
	cmd.Flags().StringVar(&params.SysdumpOptions.OutputFileName, "sysdump-output-filename", sysdump.DefaultOutputFileName, "The name of the resulting file (without extension)\n'<ts>' can be used as the placeholder for the timestamp")
	cmd.Flags().BoolVar(&params.SysdumpOptions.Quick, "sysdump-quick", sysdump.DefaultQuick, "Whether to enable quick mode (i.e. skip collection of 'cilium-bugtool' output and logs)")
	cmd.Flags().IntVar(&params.SysdumpOptions.WorkerCount, "sysdump-worker-count", sysdump.DefaultWorkerCount, "The number of workers to use\nNOTE: There is a lower bound requirement on the number of workers for the sysdump operation to be effective. Therefore, for low values, the actual number of workers may be adjusted upwards.")
	cmd.Flags().StringArrayVar(&params.SysdumpOptions.CiliumBugtoolFlags, "sysdump-cilium-bugtool-flags", nil, "Optional set of flags to pass to cilium-bugtool command.")
	cmd.Flags().BoolVar(&params.SysdumpOptions.DetectGopsPID, "sysdump-detect-gops-pid", false, "Whether to automatically detect the gops agent PID.")
	cmd.Flags().StringVar(&params.SysdumpOptions.CNIConfigDirectory, "sysdump-cni-config-directory", sysdump.DefaultCNIConfigDirectory, "Directory where CNI configs are located")
	cmd.Flags().StringVar(&params.SysdumpOptions.CNIConfigMapName, "sysdump-cni-configmap-name", sysdump.DefaultCNIConfigMapName, "The name of the CNI config map")
	cmd.Flags().StringVar(&params.SysdumpOptions.TetragonNamespace, "sysdump-tetragon-namespace", sysdump.DefaultTetragonNamespace, "The namespace Tetragon is running in")
	cmd.Flags().StringVar(&params.SysdumpOptions.TetragonLabelSelector, "sysdump-tetragon-label-selector", sysdump.DefaultTetragonLabelSelector, "The labels used to target Tetragon pods")

	return cmd
}
