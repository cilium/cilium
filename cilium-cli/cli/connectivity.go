// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/cilium-cli/api"
	"github.com/cilium/cilium/cilium-cli/connectivity"
	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/sysdump"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/tools/testowners/codeowners"
)

func newCmdConnectivity(hooks api.Hooks) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "connectivity",
		Short: "Connectivity troubleshooting",
		Long:  ``,
	}

	cmd.AddCommand(newCmdConnectivityTest(hooks))
	cmd.AddCommand(newCmdConnectivityPerf(hooks))

	return cmd
}

var params = check.Parameters{
	ExternalDeploymentPort: 8090,
	EchoServerHostPort:     4000,
	Writer:                 os.Stdout,
	SysdumpOptions: sysdump.Options{
		LargeSysdumpAbortTimeout: sysdump.DefaultLargeSysdumpAbortTimeout,
		LargeSysdumpThreshold:    sysdump.DefaultLargeSysdumpThreshold,
		Writer:                   os.Stdout,
	},
}

var tests []string

func RunE(hooks api.Hooks) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, _ []string) error {
		params.CiliumNamespace = RootParams.Namespace
		params.ImpersonateAs = RootParams.ImpersonateAs
		params.ImpersonateGroups = RootParams.ImpersonateGroups

		for _, test := range tests {
			if after, ok := strings.CutPrefix(test, "!"); ok {
				rgx, err := regexp.Compile(after)
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

		if params.PrintImageArtifacts {
			if cmd.Use == "test" {
				fmt.Fprintln(params.Writer, params.CurlImage)
				fmt.Fprintln(params.Writer, params.JSONMockImage)
				fmt.Fprintln(params.Writer, params.DNSTestServerImage)
				fmt.Fprintln(params.Writer, params.TestConnDisruptImage)
				fmt.Fprintln(params.Writer, params.FRRImage)
				fmt.Fprintln(params.Writer, params.SocatImage)
			} else if cmd.Use == "perf" {
				fmt.Fprintln(params.Writer, params.PerfParameters.Image)
			}
			return nil
		}

		var owners *codeowners.Ruleset
		if params.LogCodeOwners {
			var err error

			owners, err = codeowners.Load(params.CodeOwners)
			if err != nil {
				return fmt.Errorf("❗ Failed to load code owners: %w", err)
			}

			owners = owners.WithExcludedOwners(params.ExcludeCodeOwners)
		}

		logger := check.NewConcurrentLogger(params.Writer)
		connTests, err := newConnectivityTests(params, hooks, logger, owners)
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
			connTests[0].Logf("Cancellation request (%s) received, cancelling tests...", context.Cause(ctx))
		}()

		logger.Start()
		defer logger.Stop()
		return connectivity.Run(ctx, connTests, hooks)
	}
}

func newCmdConnectivityTest(hooks api.Hooks) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Validate connectivity in cluster",
		Long:  ``,
		RunE:  RunE(hooks),
	}

	cmd.Flags().BoolVar(&params.SingleNode, "single-node", false, "Limit to tests able to run on a single node")
	cmd.Flags().BoolVar(&params.PrintFlows, "print-flows", false, "Print flow logs for each test")
	cmd.Flags().DurationVar(&params.PostTestSleepDuration, "post-test-sleep", 0, "Wait time after each test before next test starts")
	cmd.Flags().BoolVar(&params.ForceDeploy, "force-deploy", false, "Force re-deploying test artifacts")
	cmd.Flags().BoolVar(&params.Hubble, "hubble", true, "Automatically use Hubble for flow validation & troubleshooting")
	cmd.Flags().StringVar(&params.HubbleServer, "hubble-server", "localhost:4245", "Address of the Hubble endpoint for flow validation")
	cmd.Flags().StringVar(&params.AgentDaemonSetName, "agent-daemonset-name", defaults.AgentDaemonSetName, "Name of cilium agent daemonset")
	cmd.Flags().StringVar(&params.AgentPodSelector, "agent-pod-selector", defaults.AgentPodSelector, "Label on cilium-agent pods to select with")
	cmd.Flags().StringVar(&params.CiliumPodSelector, "cilium-pod-selector", defaults.CiliumPodSelector, "Label selector matching all cilium-related pods")
	cmd.Flags().Var(option.NewMapOptions(&params.NodeSelector), "node-selector", "Restrict connectivity pods to nodes matching this label")
	cmd.Flags().StringVar(&params.MultiCluster, "multi-cluster", "", "Test across clusters to given context")
	cmd.Flags().StringSliceVar(&tests, "test", []string{}, "Run tests that match one of the given regular expressions, skip tests by starting the expression with '!', target Scenarios with e.g. '/pod-to-cidr'")
	cmd.Flags().StringVar(&params.FlowValidation, "flow-validation", check.FlowValidationModeWarning, "Enable Hubble flow validation { disabled | warning | strict }")
	cmd.Flags().BoolVar(&params.AllFlows, "all-flows", false, "Print all flows during flow validation")
	cmd.Flags().StringVar(&params.AssumeCiliumVersion, "assume-cilium-version", "", "Assume Cilium version for connectivity tests")
	cmd.Flags().BoolVarP(&params.Verbose, "verbose", "v", false, "Show informational messages and don't buffer any lines")
	cmd.Flags().BoolVarP(&params.Timestamp, "timestamp", "t", false, "Show timestamp in messages")
	cmd.Flags().BoolVarP(&params.PauseOnFail, "pause-on-fail", "p", false, "Pause execution on test failure")
	cmd.Flags().BoolVar(&params.ExternalTargetIPv6Capable, "external-target-ipv6-capable", false, "External target is IPv6 capable")
	cmd.Flags().StringVar(&params.ExternalTarget, "external-target", "one.one.one.one.", "Domain name to use as external target in connectivity tests")
	cmd.Flags().StringVar(&params.ExternalOtherTarget, "external-other-target", "k8s.io.", "Domain name to use as a second external target in connectivity tests")
	cmd.Flags().StringVar(&params.ExternalTargetCANamespace, "external-target-ca-namespace", "", "Namespace of the CA secret for the external target.")
	cmd.Flags().StringVar(&params.ExternalTargetCAName, "external-target-ca-name", "cabundle", "Name of the CA secret for the external target.")
	cmd.Flags().StringVar(&params.ExternalCIDRv4, "external-cidr", "1.0.0.0/8", "IPv4 CIDR to use as external target in connectivity tests")
	cmd.Flags().StringVar(&params.ExternalCIDRv6, "external-cidrv6", "2606:4700:4700::/96", "IPv6 CIDR to use as external target in connectivity tests")
	cmd.Flags().StringVar(&params.ExternalIPv4, "external-ip", "1.1.1.1", "IPv4 to use as external target in connectivity tests")
	cmd.Flags().StringVar(&params.ExternalIPv6, "external-ipv6", "2606:4700:4700::1111", "IPv6 to use as external target in connectivity tests")
	cmd.Flags().StringVar(&params.ExternalOtherIPv4, "external-other-ip", "1.0.0.1", "Other IPv4 to use as external target in connectivity tests")
	cmd.Flags().StringVar(&params.ExternalOtherIPv6, "external-other-ipv6", "2606:4700:4700::1001", "Other IPv6 to use as external target in connectivity tests")
	cmd.Flags().StringVar(&params.ServiceType, "service-type", "NodePort", "Type of Kubernetes Services created for connectivity tests")
	cmd.Flags().StringSliceVar(&params.NodeCIDRs, "node-cidr", nil, "one or more CIDRs that cover all nodes in the cluster")
	cmd.Flags().StringVar(&params.JunitFile, "junit-file", "", "Generate junit report and write to file")
	cmd.Flags().Var(option.NewMapOptions(&params.JunitProperties), "junit-property", "Add key=value properties to the generated junit file")
	cmd.Flags().BoolVar(&params.IncludeUnsafeTests, "include-unsafe-tests", false, "Include tests which can modify cluster nodes state")
	cmd.Flags().MarkHidden("include-unsafe-tests")
	cmd.Flags().BoolVar(&params.K8sLocalHostTest, "k8s-localhost-test", false, "Include tests which test for policy enforcement for the k8s entity on its own host")
	cmd.Flags().MarkHidden("k8s-localhost-test")

	cmd.Flags().StringVar(&params.K8sVersion, "k8s-version", "", "Kubernetes server version in case auto-detection fails")
	cmd.Flags().StringVar(&params.HelmChartDirectory, "chart-directory", "", "Helm chart directory")
	cmd.Flags().StringVar(&params.HelmValuesSecretName, "helm-values-secret-name", defaults.HelmValuesSecretName, "Secret name to store the auto-generated helm values file. The namespace is the same as where Cilium will be installed")

	cmd.Flags().StringVar(&params.CurlImage, "curl-image", defaults.ConnectivityCheckImagesTest["ConnectivityCheckAlpineCurlImage"], "Image path to use for curl")
	cmd.Flags().StringVar(&params.JSONMockImage, "json-mock-image", defaults.ConnectivityCheckImagesTest["ConnectivityCheckJSONMockImage"], "Image path to use for json mock")
	cmd.Flags().StringVar(&params.DNSTestServerImage, "dns-test-server-image", defaults.ConnectivityCheckImagesTest["ConnectivityDNSTestServerImage"], "Image path to use for CoreDNS")
	cmd.Flags().StringVar(&params.TestConnDisruptImage, "test-conn-disrupt-image", defaults.ConnectivityCheckImagesTest["ConnectivityTestConnDisruptImage"], "Image path to use for connection disruption tests")
	cmd.Flags().StringVar(&params.FRRImage, "frr-image", defaults.ConnectivityCheckImagesTest["ConnectivityTestFRRImage"], "Image path to use for FRR")
	cmd.Flags().StringVar(&params.SocatImage, "socat-image", defaults.ConnectivityCheckImagesTest["ConnectivityTestSocatImage"], "Image path to use for multicast tests")
	cmd.Flags().StringVar(&params.EchoImage, "echo-image", defaults.ConnectivityCheckOptionalImagesTest["ConnectivityTestEchoImage"], "Image path to use for echo server")

	cmd.Flags().UintVar(&params.Retry, "retry", defaults.ConnectRetry, "Number of retries on connection failure to external targets")
	cmd.Flags().DurationVar(&params.RetryDelay, "retry-delay", defaults.ConnectRetryDelay, "Delay between retries for external targets")

	cmd.Flags().DurationVar(&params.ConnectTimeout, "connect-timeout", defaults.ConnectTimeout, "Maximum time to allow initiation of the connection to take")
	cmd.Flags().DurationVar(&params.RequestTimeout, "request-timeout", defaults.RequestTimeout, "Maximum time to allow a request to take")
	cmd.Flags().BoolVar(&params.CurlInsecure, "curl-insecure", false, "Pass --insecure to curl")
	cmd.Flags().UintVar(&params.CurlParallel, "curl-parallel", defaults.CurlParallel, "Number of parallel requests in curl commands (0 to disable)")

	cmd.Flags().BoolVar(&params.CollectSysdumpOnFailure, "collect-sysdump-on-failure", false, "Collect sysdump after a test fails")

	sysdump.InitSysdumpFlags(cmd, &params.SysdumpOptions, "sysdump-", hooks)

	cmd.Flags().BoolVar(&params.IncludeConnDisruptTest, "include-conn-disrupt-test", false, "Include conn disrupt test")
	cmd.Flags().BoolVar(&params.IncludeConnDisruptTestNSTraffic, "include-conn-disrupt-test-ns-traffic", false, "Include conn disrupt test for NS traffic")
	cmd.Flags().BoolVar(&params.IncludeConnDisruptTestEgressGateway, "include-conn-disrupt-test-egw", false, "Include conn disrupt test for Egress Gateway")
	cmd.Flags().BoolVar(&params.IncludeConnDisruptTestL7Traffic, "include-conn-disrupt-test-l7-traffic", false, "Include conn disrupt test for L7 traffic")
	cmd.Flags().BoolVar(&params.ConnDisruptTestSetup, "conn-disrupt-test-setup", false, "Set up conn disrupt test dependencies")
	cmd.Flags().StringVar(&params.ConnDisruptTestRestartsPath, "conn-disrupt-test-restarts-path", "/tmp/cilium-conn-disrupt-restarts", "Conn disrupt test temporary result file (used internally)")
	cmd.Flags().StringVar(&params.ConnDisruptTestXfrmErrorsPath, "conn-disrupt-test-xfrm-errors-path", "/tmp/cilium-conn-disrupt-xfrm-errors", "Conn disrupt test temporary result file (used internally)")
	cmd.Flags().DurationVar(&params.ConnDisruptDispatchInterval, "conn-disrupt-dispatch-interval", 0, "TCP packet dispatch interval")

	cmd.Flags().StringSliceVar(&params.ExpectedDropReasons, "expected-drop-reasons", defaults.ExpectedDropReasons, "List of expected drop reasons")
	cmd.Flags().MarkHidden("expected-drop-reasons")
	cmd.Flags().StringSliceVar(&params.ExpectedXFRMErrors, "expected-xfrm-errors", defaults.ExpectedXFRMErrors, "List of expected XFRM errors")
	cmd.Flags().MarkHidden("expected-xfrm-errors")

	cmd.Flags().StringSliceVar(&params.CodeOwners, "code-owners", []string{}, "Use the code owners defined in these files for --log-code-owners")
	cmd.Flags().MarkHidden("code-owners")
	cmd.Flags().BoolVar(&params.LogCodeOwners, "log-code-owners", defaults.LogCodeOwners, "Log code owners for tests that fail")
	cmd.Flags().MarkHidden("log-code-owners")
	cmd.Flags().StringSliceVar(&params.ExcludeCodeOwners, "exclude-code-owners", []string{}, "Exclude specific code owners from --log-code-owners")
	cmd.Flags().MarkHidden("exclude-code-owners")
	cmd.Flags().StringSliceVar(&params.LogCheckLevels, "log-check-levels", defaults.LogCheckLevels, "Log levels to check for in log messages")
	cmd.Flags().MarkHidden("log-check-levels")

	cmd.Flags().BoolVar(&params.FlushCT, "flush-ct", false, "Flush conntrack of Cilium on each node")
	cmd.Flags().MarkHidden("flush-ct")
	cmd.Flags().StringVar(&params.SecondaryNetworkIface, "secondary-network-iface", "", "Secondary network iface name (e.g., to test NodePort BPF on multiple networks)")

	cmd.Flags().DurationVar(&params.Timeout, "timeout", defaults.ConnectivityTestSuiteTimeout, "Maximum time to allow the connectivity test suite to take")

	cmd.Flags().IntVar(&params.TestConcurrency, "test-concurrency", 1, "Count of namespaces to perform the connectivity tests in parallel (value <= 0 will be treated as 1)")
	cmd.Flags().StringSliceVar(&params.IPFamilies, "ip-families", []string{features.IPFamilyV4.String(), features.IPFamilyV6.String()}, "Restrict test actions to specific IP families")

	hooks.AddConnectivityTestFlags(cmd.Flags())

	registerCommonFlags(cmd.Flags())

	return cmd
}

func newCmdConnectivityPerf(hooks api.Hooks) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "perf",
		Short: "Test network performance",
		Long:  ``,
		PreRunE: func(_ *cobra.Command, _ []string) error {
			// This is a bit of hack that allows us to override default values
			// of these parameters that are not visible in perf subcommand options
			// as we can't have different defaults specified in test and perf subcommands
			// and both of these commands share the same RunE for now.
			params.Perf = true
			params.ForceDeploy = true
			params.Hubble = false

			if reportDir := params.PerfParameters.ReportDir; reportDir != "" {
				if err := os.MkdirAll(reportDir, 0755); err != nil {
					return fmt.Errorf("could not create report dir %q: %w", reportDir, err)
				}
			} else if params.PerfParameters.KernelProfiles {
				fmt.Println("⚠️  Requested kernel profiles, but report-dir is unset, skipping")
				params.PerfParameters.KernelProfiles = false
			}

			return nil
		},
		RunE: RunE(hooks),
	}

	cmd.Flags().DurationVar(&params.PerfParameters.Duration, "duration", 10*time.Second, "Duration for the Performance test to run")
	cmd.Flags().DurationVar(&params.PerfParameters.SetupDelay, "setup-delay", 0, "Extra delay before starting the performance tests")
	cmd.Flags().IntVar(&params.PerfParameters.MessageSize, "msg-size", 1024, "Size of message to use in UDP test")
	cmd.Flags().BoolVar(&params.PerfParameters.CRR, "crr", false, "Run CRR test")
	cmd.Flags().BoolVar(&params.PerfParameters.RR, "rr", true, "Run RR test")
	cmd.Flags().BoolVar(&params.PerfParameters.UDP, "udp", false, "Run UDP tests")
	cmd.Flags().BoolVar(&params.PerfParameters.Throughput, "throughput", true, "Run throughput test")
	cmd.Flags().BoolVar(&params.PerfParameters.ThroughputMulti, "throughput-multi", true, "Run throughput test with multiple streams")
	cmd.Flags().IntVar(&params.PerfParameters.Samples, "samples", 1, "Number of Performance samples to capture (how many times to run each test)")
	cmd.Flags().UintVar(&params.PerfParameters.Streams, "streams", 4, "The parallelism of tests with multiple streams")
	cmd.Flags().BoolVar(&params.PerfParameters.HostNet, "host-net", true, "Test host network")
	cmd.Flags().BoolVar(&params.PerfParameters.PodNet, "pod-net", true, "Test pod network")
	cmd.Flags().BoolVar(&params.PerfParameters.PodToHost, "pod-to-host", false, "Test pod-to-host traffic")
	cmd.Flags().BoolVar(&params.PerfParameters.HostToPod, "host-to-pod", false, "Test host-to-pod traffic")
	cmd.Flags().BoolVar(&params.PerfParameters.SameNode, "same-node", true, "Run tests in which the client and the server are hosted on the same node")
	cmd.Flags().BoolVar(&params.PerfParameters.OtherNode, "other-node", true, "Run tests in which the client and the server are hosted on difference nodes")
	cmd.Flags().BoolVar(&params.PerfParameters.NetQos, "net-qos", false, "Test pod network Quality of Service")
	cmd.Flags().BoolVar(&params.PerfParameters.Bandwidth, "bandwidth", false, "Test pod network bandwidth manage")

	cmd.Flags().BoolVar(&params.PerfParameters.KernelProfiles, "unsafe-capture-kernel-profiles", false,
		"Capture kernel profiles during test execution. Warning: run on disposable nodes only, as it installs additional software and modifies their configuration")

	cmd.Flags().Var(option.NewMapOptions(&params.PerfParameters.NodeSelectorServer),
		"node-selector-server", "Node selector for the server pod (and client same-node)")
	cmd.Flags().Var(option.NewMapOptions(&params.PerfParameters.NodeSelectorClient),
		"node-selector-client", "Node selector for the other-node client pod")

	cmd.Flags().StringVar(&params.PerfParameters.Image, "performance-image", defaults.ConnectivityCheckImagesPerf["ConnectivityPerformanceImage"], "Image path to use for performance")
	cmd.Flags().StringVar(&params.PerfParameters.ReportDir, "report-dir", "", "Directory to save perf results in json format")
	registerCommonFlags(cmd.Flags())

	return cmd
}

func registerCommonFlags(flags *pflag.FlagSet) {
	flags.BoolVarP(&params.Debug, "debug", "d", false, "Show debug messages")
	flags.StringSliceVar(&params.Tolerations, "tolerations", nil, "Extra NoSchedule tolerations added to test pods")
	flags.StringVar(&params.TestNamespace, "test-namespace", defaults.ConnectivityCheckNamespace, "Namespace to perform the connectivity in (always suffixed with a sequence number to be compliant with test-concurrency param, e.g.: cilium-test-1)")
	flags.Var(option.NewMapOptions(&params.NamespaceLabels), "namespace-labels", "Add labels to the connectivity test namespace")
	flags.Var(option.NewMapOptions(&params.NamespaceAnnotations), "namespace-annotations", "Add annotations to the connectivity test namespace")
	flags.MarkHidden("namespace-annotations")
	flags.Var(&params.DeploymentAnnotations, "deployment-pod-annotations", "Add annotations to the connectivity pods, e.g. '{\"client\":{\"foo\":\"bar\"}}'")
	flags.MarkHidden("deployment-pod-annotations")
	flags.BoolVar(&params.PrintImageArtifacts, "print-image-artifacts", false, "Prints the used image artifacts")
}

func newConnectivityTests(
	params check.Parameters,
	hooks api.Hooks,
	logger *check.ConcurrentLogger,
	owners *codeowners.Ruleset,
) ([]*check.ConnectivityTest, error) {
	if params.TestConcurrency < 1 {
		fmt.Printf("--test-concurrency parameter value is invalid [%d], using 1 instead\n", params.TestConcurrency)
		params.TestConcurrency = 1
	}

	connTests := make([]*check.ConnectivityTest, 0, params.TestConcurrency)
	for i := range params.TestConcurrency {
		params := params
		params.TestNamespace = fmt.Sprintf("%s-%d", params.TestNamespace, i+1)
		params.TestNamespaceIndex = i
		if params.ExternalTargetCANamespace == "" {
			params.ExternalTargetCANamespace = params.TestNamespace
		}
		params.ExternalDeploymentPort += i
		params.EchoServerHostPort += i
		cc, err := check.NewConnectivityTest(RootK8sClient, params, hooks, logger, owners)
		if err != nil {
			return nil, err
		}
		connTests = append(connTests, cc)
	}
	return connTests, nil
}
