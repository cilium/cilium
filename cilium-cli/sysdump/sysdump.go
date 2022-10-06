// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sysdump

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/workerpool"
	"github.com/mholt/archiver/v3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/utils"
	"github.com/cilium/cilium-cli/k8s"
)

const sysdumpLogFile = "cilium-sysdump.log"

// Options groups together the set of options required to collect a sysdump.
type Options struct {
	// The labels used to target Cilium pods.
	CiliumLabelSelector string
	// The namespace Cilium is running in.
	CiliumNamespace string
	// The namespace Cilium operator is running in.
	CiliumOperatorNamespace string
	// The labels used to target Cilium daemon set. Usually, this label is same as CiliumLabelSelector.
	CiliumDaemonSetSelector string
	// The labels used to target Cilium operator pods.
	CiliumOperatorLabelSelector string
	// The labels used to target 'clustermesh-apiserver' pods.
	ClustermeshApiserverLabelSelector string
	// Whether to enable debug logging.
	Debug bool
	// The labels used to target additional pods
	ExtraLabelSelectors []string
	// The labels used to target Hubble pods.
	HubbleLabelSelector string
	// Number of Hubble flows to collect.
	HubbleFlowsCount int64
	// Timeout for collecting Hubble flows.
	HubbleFlowsTimeout time.Duration
	// The labels used to target Hubble Relay pods.
	HubbleRelayLabelSelector string
	// The labels used to target Hubble UI pods.
	HubbleUILabelSelector string
	// The amount of time to wait for the user to cancel the sysdump on a large cluster.
	LargeSysdumpAbortTimeout time.Duration
	// The threshold on the number of nodes present in the cluster that triggers a warning message.
	LargeSysdumpThreshold int
	// The limit on the number of bytes to retrieve when collecting logs
	LogsLimitBytes int64
	// How far back in time to go when collecting logs.
	LogsSinceTime time.Duration
	// Comma-separated list of node IPs or names to filter pods for which to collect gops and logs.
	NodeList string
	// The name of the resulting file (without extension)\n'<ts>' can be used as the placeholder for the timestamp.
	OutputFileName string
	// Whether to enable quick mode (i.e. skip collection of 'cilium-bugtool' output and logs).
	Quick bool
	// A 'RESTClientGetter' that can be used to create REST clients for the Kubernetes API.
	// Required at least for getting the proper output of 'kubectl get pod -o wide' without actually using 'kubectl'.
	RESTClientGetter genericclioptions.RESTClientGetter
	// The number of workers to use.
	WorkerCount int
	// The writer used for logging.
	Writer io.Writer
	// Flags to pass to cilium-bugtool command
	CiliumBugtoolFlags []string
	// Whether to automatically detect the gops agent PID
	DetectGopsPID bool
	// Directory where CNI configs are located
	CNIConfigDirectory string
	// The name of the CNI config map
	CNIConfigMapName string
	// The labels used to target Tetragon pods.
	TetragonLabelSelector string
	// The namespace Namespace is running in.
	TetragonNamespace string
}

// Task defines a task for the sysdump collector to execute.
type Task struct {
	// MUST be set to true if the task submits additional tasks to the worker pool.
	CreatesSubtasks bool
	// The description of the task.
	Description string
	// Whether this task runs when running in quick mode.
	Quick bool
	// The task itself.
	Task func(context.Context) error
}

// Collector knows how to collect information required to troubleshoot issues with Cilium and Hubble.
type Collector struct {
	Client  KubernetesClient
	Options Options
	Pool    *workerpool.WorkerPool
	// logFile is the log file for the sydump log messages.
	logFile *os.File
	// logWriter is the io.Writer used for logging.
	logWriter io.Writer
	// subtasksWg is used to wait for subtasks to be submitted to the pool before calling 'Drain'.
	// It is required since we don't know beforehand how many sub-tasks will be created, as they depend on the number of Cilium/Hubble/... pods found by "main" tasks.
	subtasksWg sync.WaitGroup
	// startTime keeps track of the time this sysdump collector got initialized. This timestamp
	// is used to substitute '<ts>' in filenames.
	startTime time.Time
	// Directory to collect sysdump in.
	sysdumpDir string
	// allNodes is a list of all the node names in the cluster.
	allNodes *corev1.NodeList
	// NodeList is a list of nodes to collect sysdump information from.
	NodeList []string
	// additionalTasks keeps track of additional tasks added via AddTasks.
	additionalTasks []Task
}

// NewCollector returns a new sysdump collector.
func NewCollector(k KubernetesClient, o Options, startTime time.Time, cliVersion string) (*Collector, error) {
	c := Collector{
		Client:    k,
		Options:   o,
		startTime: startTime,
	}
	tmp, err := os.MkdirTemp("", "*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}
	c.sysdumpDir = filepath.Join(tmp, c.replaceTimestamp(c.Options.OutputFileName))
	if err = os.MkdirAll(c.sysdumpDir, dirMode); err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}
	if err = c.setupLogging(o.Writer); err != nil {
		return nil, err
	}
	c.logDebug("Using %v as a temporary directory", c.sysdumpDir)
	c.logTask("Collecting sysdump with cilium-cli version: %s, args: %s", cliVersion, os.Args[1:])

	if o.CiliumNamespace == "" {
		ns, err := detectCiliumNamespace(k)
		if err != nil {
			return nil, err
		}
		c.logDebug("Detected Cilium installation in namespace %q", ns)
		o.CiliumNamespace = ns
	}

	// Grab the Kubernetes nodes for the target cluster.
	c.logTask("Collecting Kubernetes nodes")
	c.allNodes, err = c.Client.ListNodes(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to collect Kubernetes nodes: %w", err)
	}
	c.logDebug("Finished collecting Kubernetes nodes")

	// Exit if there are no nodes, as there's nothing to do.
	if len(c.allNodes.Items) == 0 {
		return nil, fmt.Errorf("no nodes found in the current cluster")
	}
	// If there are many nodes and no filters are specified, issue a warning and wait for a while before proceeding so the user can cancel the process.
	if len(c.allNodes.Items) > c.Options.LargeSysdumpThreshold && (c.Options.NodeList == DefaultNodeList && c.Options.LogsLimitBytes == DefaultLogsLimitBytes && c.Options.LogsSinceTime == DefaultLogsSinceTime) {
		c.logWarn("Detected a large cluster (%d nodes)", len(c.allNodes.Items))
		c.logWarn("Consider using a node filter, a custom log size limit and/or a custom log time range to decrease the size of the sysdump")
		c.logWarn("Waiting for %s before continuing", c.Options.LargeSysdumpAbortTimeout)
		t := time.NewTicker(c.Options.LargeSysdumpAbortTimeout)
		defer t.Stop()
		<-t.C
	}

	// Build the list of node names in which the user is interested.
	c.NodeList, err = buildNodeNameList(c.allNodes, c.Options.NodeList)
	if err != nil {
		return nil, fmt.Errorf("failed to build node list: %w", err)
	}
	c.logDebug("Restricting bugtool and logs collection to pods in %v", c.NodeList)

	return &c, nil
}

// setupLogging sets up sysdump collector loggging.
func (c *Collector) setupLogging(w io.Writer) error {
	var err error
	c.logFile, err = os.Create(filepath.Join(c.sysdumpDir, sysdumpLogFile))
	if err != nil {
		return fmt.Errorf("failed to create sysdump log file: %w", err)
	}
	// Log to stdout and to a file in the sysdump itself
	c.logWriter = io.MultiWriter(w, c.logFile)
	return nil
}

// teardownLogging flushes writes to the sysdump collector log file and closes it.
func (c *Collector) teardownLogging() {
	// flush writes to log file
	c.logFile.Sync()
	// ...and close the log file
	c.logFile.Close()
	// rewire logger for the remaining log messages which won't make it into to log file
	c.logWriter = os.Stdout
}

// replaceTimestamp can be used to replace the special timestamp placeholder in file and directory names.
func (c *Collector) replaceTimestamp(f string) string {
	return strings.Replace(f, timestampPlaceholderFileName, c.startTime.Format(timeFormat), -1)
}

// AbsoluteTempPath returns the absolute path where to store the specified filename temporarily.
func (c *Collector) AbsoluteTempPath(f string) string {
	return path.Join(c.sysdumpDir, c.replaceTimestamp(f))
}

// WriteYAML writes a kubernetes object to a file as YAML.
func (c *Collector) WriteYAML(filename string, o runtime.Object) error {
	return writeYaml(c.AbsoluteTempPath(filename), o)
}

// WriteString writes a string to a file.
func (c *Collector) WriteString(filename string, value string) error {
	return writeString(c.AbsoluteTempPath(filename), value)
}

// WriteBytes writes a byte array to a file.
func (c *Collector) WriteBytes(filename string, value []byte) error {
	return writeBytes(c.AbsoluteTempPath(filename), value)
}

// WriteTable writes a kubernetes table to a file.
func (c *Collector) WriteTable(filename string, value *metav1.Table) error {
	return writeTable(c.AbsoluteTempPath(filename), value)
}

// Run performs the actual sysdump collection.
func (c *Collector) Run() error {
	// tasks is the list of base tasks to be run.
	tasks := []Task{

		{
			Description: "Collect Kubernetes nodes",
			Quick:       true,
			Task: func(_ context.Context) error {
				if err := c.WriteYAML(kubernetesNodesFileName, c.allNodes); err != nil {
					return fmt.Errorf("failed to collect Kubernetes nodes: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collect Kubernetes version",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.Client.GetVersion(ctx)
				if err != nil {
					return fmt.Errorf("failed to collect Kubernetes version: %w", err)
				}
				if err := c.WriteString(kubernetesVersionInfoFileName, v); err != nil {
					return fmt.Errorf("failed to dump Kubernetes version: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Kubernetes events",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.Client.ListEvents(ctx, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Kubernetes events: %w", err)
				}
				if err := c.WriteYAML(kubernetesEventsFileName, v); err != nil {
					return fmt.Errorf("failed to collect Kubernetes events: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Kubernetes namespaces",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.Client.ListNamespaces(ctx, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Kubernetes namespaces: %w", err)
				}
				if err := c.WriteYAML(kubernetesNamespacesFileName, v); err != nil {
					return fmt.Errorf("failed to collect Kubernetes namespaces: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Kubernetes pods",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.Client.ListPods(ctx, corev1.NamespaceAll, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Kubernetes pods: %w", err)
				}
				if err := c.WriteYAML(kubernetesPodsFileName, v); err != nil {
					return fmt.Errorf("failed to collect Kubernetes pods: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Kubernetes pods summary",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.Client.GetPodsTable(ctx)
				if err != nil {
					return fmt.Errorf("failed to collect Kubernetes pods summary: %w", err)
				}
				if err := c.WriteTable(kubernetesPodsSummaryFileName, v); err != nil {
					return fmt.Errorf("failed to collect Kubernetes pods summary: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Kubernetes services",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.Client.ListServices(ctx, corev1.NamespaceAll, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Kubernetes services: %w", err)
				}
				if err := c.WriteYAML(kubernetesServicesFileName, v); err != nil {
					return fmt.Errorf("failed to collect Kubernetes services: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Kubernetes network policies",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.Client.ListNetworkPolicies(ctx, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Kubernetes network policies: %w", err)
				}
				if err := c.WriteYAML(kubernetesNetworkPoliciesFileName, v); err != nil {
					return fmt.Errorf("failed to collect Kubernetes network policies: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Kubernetes endpoints",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.Client.ListEndpoints(ctx, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Kubernetes endpoints: %w", err)
				}
				if err := c.WriteYAML(kubernetesEndpointsFileName, v); err != nil {
					return fmt.Errorf("failed to collect Kubernetes endpoints: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Kubernetes leases",
			Quick:       true,
			Task: func(ctx context.Context) error {
				n := corev1.NamespaceAll
				v, err := c.Client.ListUnstructured(ctx, k8sLeases, &n, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Kubernetes leases: %w", err)
				}
				if err := c.WriteYAML(kubernetesLeasesFileName, v); err != nil {
					return fmt.Errorf("failed to collect Kubernetes leases: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Cilium network policies",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.Client.ListCiliumNetworkPolicies(ctx, corev1.NamespaceAll, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Cilium network policies: %w", err)
				}
				if err := c.WriteYAML(ciliumNetworkPoliciesFileName, v); err != nil {
					return fmt.Errorf("failed to collect Cilium network policies: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Cilium cluster-wide network policies",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.Client.ListCiliumClusterwideNetworkPolicies(ctx, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Cilium cluster-wide network policies: %w", err)
				}
				if err := c.WriteYAML(ciliumClusterWideNetworkPoliciesFileName, v); err != nil {
					return fmt.Errorf("failed to collect Cilium cluster-wide network policies: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Cilium egress NAT policies",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.Client.ListCiliumEgressNATPolicies(ctx, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Cilium egress NAT policies: %w", err)
				}
				if err := c.WriteYAML(ciliumEgressNATPoliciesFileName, v); err != nil {
					return fmt.Errorf("failed to collect Cilium egress NAT policies: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Cilium local redirect policies",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.Client.ListCiliumLocalRedirectPolicies(ctx, corev1.NamespaceAll, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Cilium local redirect policies: %w", err)
				}
				if err := c.WriteYAML(ciliumLocalRedirectPoliciesFileName, v); err != nil {
					return fmt.Errorf("failed to collect Cilium local redirect policies: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Cilium endpoints",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.Client.ListCiliumEndpoints(ctx, corev1.NamespaceAll, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Cilium endpoints: %w", err)
				}
				if err := c.WriteYAML(ciliumEndpointsFileName, v); err != nil {
					return fmt.Errorf("failed to collect Cilium endpoints: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Cilium identities",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.Client.ListCiliumIdentities(ctx)
				if err != nil {
					return fmt.Errorf("failed to collect Cilium identities: %w", err)
				}
				if err := c.WriteYAML(ciliumIdentitiesFileName, v); err != nil {
					return fmt.Errorf("failed to collect Cilium identities: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Cilium nodes",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.Client.ListCiliumNodes(ctx)
				if err != nil {
					return fmt.Errorf("failed to collect Cilium nodes: %w", err)
				}
				if err := c.WriteYAML(ciliumNodesFileName, v); err != nil {
					return fmt.Errorf("failed to collect Cilium nodes: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Ingresses",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.Client.ListIngresses(ctx, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Ingresses: %w", err)
				}
				if err := c.WriteYAML(ciliumIngressesFileName, v); err != nil {
					return fmt.Errorf("failed to collect Ingresses: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting CiliumClusterwideEnvoyConfigs",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.Client.ListCiliumClusterwideEnvoyConfigs(ctx, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect CiliumClusterwideEnvoyConfigs: %w", err)
				}
				if err := c.WriteYAML(ciliumClusterwideEnvoyConfigsFileName, v); err != nil {
					return fmt.Errorf("failed to collect CiliumClusterwideEnvoyConfigs: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting CiliumEnvoyConfigs",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.Client.ListCiliumEnvoyConfigs(ctx, corev1.NamespaceAll, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect CiliumEnvoyConfigs: %w", err)
				}
				if err := c.WriteYAML(ciliumEnvoyConfigsFileName, v); err != nil {
					return fmt.Errorf("failed to collect CiliumEnvoyConfigs: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Cilium etcd secret",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.Client.GetSecret(ctx, c.Options.CiliumNamespace, ciliumEtcdSecretsSecretName, metav1.GetOptions{})
				if err != nil {
					if errors.IsNotFound(err) {
						c.logDebug("Secret %q not found in namespace %q - this is expected when using the CRD KVStore", ciliumEtcdSecretsSecretName, c.Options.CiliumNamespace)
						return nil
					}
					return fmt.Errorf("failed to collect Cilium etcd secret: %w", err)
				}
				// Redact the actual values.
				for k := range v.Data {
					v.Data[k] = []byte(redacted)
				}
				if err := c.WriteYAML(ciliumEtcdSecretFileName, v); err != nil {
					return fmt.Errorf("failed to collect Cilium etcd secret: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting the Cilium configuration",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.Client.GetConfigMap(ctx, c.Options.CiliumNamespace, ciliumConfigMapName, metav1.GetOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect the Cilium configuration: %w", err)
				}
				if err := c.WriteYAML(ciliumConfigMapFileName, v); err != nil {
					return fmt.Errorf("failed to collect the Cilium configuration: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting the Cilium daemonset(s)",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.Client.ListDaemonSet(ctx, c.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: c.Options.CiliumDaemonSetSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to list Cilium daemonsets: %w", err)
				}
				if len(v.Items) == 0 {
					return fmt.Errorf("failed to find Cilium daemonsets with label %q in namespace %q", c.Options.CiliumDaemonSetSelector, c.Options.CiliumNamespace)
				}
				if err = c.WriteYAML(ciliumDaemonSetFileName, v); err != nil {
					return fmt.Errorf("failed to collect the Cilium daemonsets: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting the Hubble daemonset",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.Client.GetDaemonSet(ctx, c.Options.CiliumNamespace, hubbleDaemonSetName, metav1.GetOptions{})
				if err != nil {
					if errors.IsNotFound(err) {
						c.logDebug("Daemonset %q not found in namespace %q - this is expected in recent versions of Cilium", hubbleDaemonSetName, c.Options.CiliumNamespace)
						return nil
					}
					return fmt.Errorf("failed to collect the Hubble daemonset: %w", err)
				}
				if err := c.WriteYAML(hubbleDaemonsetFileName, v); err != nil {
					return fmt.Errorf("failed to collect the Hubble daemonset: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting the Hubble Relay configuration",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.Client.GetConfigMap(ctx, c.Options.CiliumNamespace, hubbleRelayConfigMapName, metav1.GetOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect the Hubble Relay configuration: %w", err)
				}
				if err := c.WriteYAML(hubbleRelayConfigMapFileName, v); err != nil {
					return fmt.Errorf("failed to collect the Hubble Relay configuration: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting the Hubble Relay deployment",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.Client.GetDeployment(ctx, c.Options.CiliumNamespace, hubbleRelayDeploymentName, metav1.GetOptions{})
				if err != nil {
					if errors.IsNotFound(err) {
						c.logWarn("Deployment %q not found in namespace %q - this is expected if Hubble is not enabled", hubbleRelayDeploymentName, c.Options.CiliumNamespace)
						return nil
					}
					return fmt.Errorf("failed to collect the Hubble Relay deployment: %w", err)
				}
				if err := c.WriteYAML(hubbleRelayDeploymentFileName, v); err != nil {
					return fmt.Errorf("failed to collect the Hubble Relay deployment: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting the Hubble UI deployment",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.Client.GetDeployment(ctx, c.Options.CiliumNamespace, hubbleUIDeploymentName, metav1.GetOptions{})
				if err != nil {
					if errors.IsNotFound(err) {
						c.logWarn("Deployment %q not found in namespace %q - this is expected if Hubble UI is not enabled", hubbleUIDeploymentName, c.Options.CiliumNamespace)
						return nil
					}
					return fmt.Errorf("failed to collect the Hubble UI deployment: %w", err)
				}
				if err := c.WriteYAML(hubbleUIDeploymentFileName, v); err != nil {
					return fmt.Errorf("failed to collect the Hubble UI deployment: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting the Cilium operator deployment",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.Client.GetDeployment(ctx, c.Options.CiliumOperatorNamespace, ciliumOperatorDeploymentName, metav1.GetOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect the Cilium operator deployment: %w", err)
				}
				if err := c.WriteYAML(ciliumOperatorDeploymentFileName, v); err != nil {
					return fmt.Errorf("failed to collect the Cilium operator deployment: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting the 'clustermesh-apiserver' deployment",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.Client.GetDeployment(ctx, c.Options.CiliumNamespace, clustermeshApiserverDeploymentName, metav1.GetOptions{})
				if err != nil {
					if errors.IsNotFound(err) {
						c.logWarn("Deployment %q not found in namespace %q - this is expected if 'clustermesh-apiserver' isn't enabled", clustermeshApiserverDeploymentName, c.Options.CiliumNamespace)
						return nil
					}
					return fmt.Errorf("failed to collect the 'clustermesh-apiserver' deployment: %w", err)
				}
				if err := c.WriteYAML(clustermeshApiserverDeploymentFileName, v); err != nil {
					return fmt.Errorf("failed to collect the 'clustermesh-apiserver' deployment: %w", err)
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting the CNI configuration files from Cilium pods",
			Quick:           true,
			Task: func(ctx context.Context) error {
				p, err := c.Client.ListPods(ctx, c.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: c.Options.CiliumLabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to list Cilium pods: %w", err)
				}
				if err := c.SubmitCniConflistSubtask(ctx, FilterPods(p, c.NodeList), ciliumAgentContainerName); err != nil {
					return fmt.Errorf("failed to collect CNI configuration files: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting the CNI configmap",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.Client.GetConfigMap(ctx, c.Options.CiliumNamespace, c.Options.CNIConfigMapName, metav1.GetOptions{})
				if err != nil && errors.IsNotFound(err) {
					c.logDebug("CNI configmap %s not found: %w", c.Options.CNIConfigMapName, err)
					return nil
				}
				if err != nil {
					return fmt.Errorf("failed to collect the CNI configuration configmap: %w", err)
				}
				if err := c.WriteYAML(cniConfigMapFileName, v); err != nil {
					return fmt.Errorf("failed to write CNI configuration configmap: %w", err)
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting gops stats from Cilium pods",
			Quick:           true,
			Task: func(ctx context.Context) error {
				p, err := c.Client.ListPods(ctx, c.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: c.Options.CiliumLabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get Cilium pods: %w", err)
				}
				if err := c.SubmitGopsSubtasks(ctx, FilterPods(p, c.NodeList), ciliumAgentContainerName); err != nil {
					return fmt.Errorf("failed to collect Cilium gops: %w", err)
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting gops stats from Hubble pods",
			Quick:           true,
			Task: func(ctx context.Context) error {
				p, err := c.Client.ListPods(ctx, c.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: c.Options.HubbleLabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get Hubble pods: %w", err)
				}
				if err := c.SubmitGopsSubtasks(ctx, FilterPods(p, c.NodeList), hubbleContainerName); err != nil {
					return fmt.Errorf("failed to collect Hubble gops: %w", err)
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting gops stats from Hubble Relay pods",
			Quick:           true,
			Task: func(ctx context.Context) error {
				p, err := c.Client.ListPods(ctx, c.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: c.Options.HubbleRelayLabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get Hubble Relay pods: %w", err)
				}
				if err := c.SubmitGopsSubtasks(ctx, FilterPods(p, c.NodeList), hubbleRelayContainerName); err != nil {
					return fmt.Errorf("failed to collect Hubble Relay gops: %w", err)
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting bugtool output from Cilium pods",
			Quick:           false,
			Task: func(ctx context.Context) error {
				p, err := c.Client.ListPods(ctx, c.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: c.Options.CiliumLabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get Cilium pods: %w", err)
				}
				if err := c.submitCiliumBugtoolTasks(ctx, FilterPods(p, c.NodeList)); err != nil {
					return fmt.Errorf("failed to collect 'cilium-bugtool': %w", err)
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting logs from Cilium pods",
			Quick:           false,
			Task: func(ctx context.Context) error {
				p, err := c.Client.ListPods(ctx, c.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: c.Options.CiliumLabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get logs from Cilium pods")
				}
				if err := c.SubmitLogsTasks(ctx, FilterPods(p, c.NodeList), c.Options.LogsSinceTime, c.Options.LogsLimitBytes); err != nil {
					return fmt.Errorf("failed to collect logs from Cilium pods")
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting logs from Cilium operator pods",
			Quick:           false,
			Task: func(ctx context.Context) error {
				p, err := c.Client.ListPods(ctx, c.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: c.Options.CiliumOperatorLabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get logs from Cilium operator pods")
				}
				if err := c.SubmitLogsTasks(ctx, FilterPods(p, c.NodeList), c.Options.LogsSinceTime, c.Options.LogsLimitBytes); err != nil {
					return fmt.Errorf("failed to collect logs from Cilium operator pods")
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting logs from 'clustermesh-apiserver' pods",
			Quick:           false,
			Task: func(ctx context.Context) error {
				p, err := c.Client.ListPods(ctx, c.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: c.Options.ClustermeshApiserverLabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get logs from 'clustermesh-apiserver' pods")
				}
				if err := c.SubmitLogsTasks(ctx, FilterPods(p, c.NodeList), c.Options.LogsSinceTime, c.Options.LogsLimitBytes); err != nil {
					return fmt.Errorf("failed to collect logs from 'clustermesh-apiserver' pods")
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting logs from Hubble pods",
			Quick:           false,
			Task: func(ctx context.Context) error {
				p, err := c.Client.ListPods(ctx, c.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: c.Options.HubbleLabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get logs from Hubble pods")
				}
				if err := c.SubmitLogsTasks(ctx, FilterPods(p, c.NodeList), c.Options.LogsSinceTime, c.Options.LogsLimitBytes); err != nil {
					return fmt.Errorf("failed to collect logs from Hubble pods")
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting logs from Hubble Relay pods",
			Quick:           false,
			Task: func(ctx context.Context) error {
				p, err := c.Client.ListPods(ctx, c.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: c.Options.HubbleRelayLabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get logs from Hubble Relay pods")
				}
				if err := c.SubmitLogsTasks(ctx, FilterPods(p, c.NodeList), c.Options.LogsSinceTime, c.Options.LogsLimitBytes); err != nil {
					return fmt.Errorf("failed to collect logs from Hubble Relay pods")
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting logs from Hubble UI pods",
			Quick:           false,
			Task: func(ctx context.Context) error {
				p, err := c.Client.ListPods(ctx, c.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: c.Options.HubbleUILabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get logs from Hubble UI pods")
				}
				if err := c.SubmitLogsTasks(ctx, FilterPods(p, c.NodeList), c.Options.LogsSinceTime, c.Options.LogsLimitBytes); err != nil {
					return fmt.Errorf("failed to collect logs from Hubble UI pods")
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting bugtool output from Tetragon pods",
			Quick:           false,
			Task: func(ctx context.Context) error {
				p, err := c.Client.ListPods(ctx, c.Options.TetragonNamespace, metav1.ListOptions{
					LabelSelector: c.Options.TetragonLabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get Tetragon pods: %w", err)
				}
				if err := c.submitTetragonBugtoolTasks(ctx, FilterPods(p, c.NodeList)); err != nil {
					return fmt.Errorf("failed to collect 'tetragon-bugtool': %w", err)
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting platform-specific data",
			Quick:           true,
			Task: func(ctx context.Context) error {
				f := c.Client.AutodetectFlavor(ctx)
				c.logDebug("Detected flavor %q", f.Kind)
				if err := c.submitFlavorSpecificTasks(ctx, f); err != nil {
					return fmt.Errorf("failed to collect platform-specific data: %w", err)
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting kvstore data",
			Quick:           true,
			Task: func(ctx context.Context) error {
				cm, err := c.Client.GetConfigMap(ctx, c.Options.CiliumNamespace, ciliumConfigMapName, metav1.GetOptions{})
				if err != nil {
					return fmt.Errorf("failed to get cilium-config ConfigMap: %w", err)
				}
				// Check if kvstore is enabled, if not skip this dump.
				if v, ok := cm.Data["kvstore"]; !ok || v != "etcd" {
					c.logDebug("KVStore not enabled, skipping kvstore dump")
					return nil
				}
				ps, err := c.Client.ListPods(ctx, c.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: c.Options.CiliumLabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to list Pods for gathering kvstore data: %w", err)
				}
				if len(ps.Items) == 0 {
					return fmt.Errorf("could not find Cilium Agent Pod to run kvstore get, Cilium Pod list was empty")
				}
				for _, pod := range ps.Items {
					if pod.Status.Phase == "Running" {
						return c.submitKVStoreTasks(ctx, pod.DeepCopy())
					}
				}
				return fmt.Errorf("could not find running Cilium Pod")
			},
		},
	}
	for _, selector := range c.Options.ExtraLabelSelectors {
		tasks = append(tasks, Task{
			CreatesSubtasks: true,
			Description:     fmt.Sprintf("Collecting logs from extra pods %q", selector),
			Quick:           false,
			Task: func(ctx context.Context) error {
				p, err := c.Client.ListPods(ctx, c.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: selector,
				})
				if err != nil {
					return fmt.Errorf("failed to get logs from pods matching selector %q", selector)
				}
				if err := c.SubmitLogsTasks(ctx, FilterPods(p, c.NodeList), c.Options.LogsSinceTime, c.Options.LogsLimitBytes); err != nil {
					return fmt.Errorf("failed to collect logs from pods matching selector %q", selector)
				}
				return nil
			},
		})
	}
	if c.Options.HubbleFlowsCount > 0 {
		tasks = append(tasks, Task{
			CreatesSubtasks: true,
			Description:     "Collecting Hubble flows from Cilium pods",
			Quick:           false,
			Task: func(ctx context.Context) error {
				p, err := c.Client.ListPods(ctx, c.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: c.Options.CiliumLabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get Cilium pods: %w", err)
				}
				if err := c.submitHubbleFlowsTasks(ctx, FilterPods(p, c.NodeList), ciliumAgentContainerName); err != nil {
					return fmt.Errorf("failed to collect hubble flows: %w", err)
				}
				return nil
			},
		})
	}
	// Append tasks added by AddTasks.
	tasks = append(tasks, c.additionalTasks...)

	// Adjust the worker count to make enough headroom for tasks that submit sub-tasks.
	// This is necessary because 'Submit' is blocking.
	wc := 1
	for _, t := range tasks {
		if t.CreatesSubtasks && !c.shouldSkipTask(t) {
			wc++
		}
	}
	// Take the maximum between the specified worker count and the minimum number of workers required.
	if wc < c.Options.WorkerCount {
		wc = c.Options.WorkerCount
	}
	c.Pool = workerpool.New(wc)
	c.logDebug("Using %d workers (requested: %d)", wc, c.Options.WorkerCount)

	// Add the tasks to the worker pool.
	for i, t := range tasks {
		t := t
		if c.shouldSkipTask(t) {
			c.logDebug("Skipping %q", t.Description)
			continue
		}
		if t.CreatesSubtasks {
			c.subtasksWg.Add(1)
		}
		if err := c.Pool.Submit(fmt.Sprintf("[%d] %s", i, t.Description), func(ctx context.Context) error {
			if t.CreatesSubtasks {
				defer c.subtasksWg.Done()
			}
			c.logTask(t.Description)
			defer c.logDebug("Finished %q", t.Description)
			return t.Task(ctx)
		}); err != nil {
			return fmt.Errorf("failed to submit task to the worker pool: %w", err)
		}
	}

	// Wait for the all subtasks to be submitted and then call 'Drain' to wait for everything to finish.
	c.subtasksWg.Wait()
	r, err := c.Pool.Drain()
	if err != nil {
		return fmt.Errorf("failed to drain the worker pool: %w", err)
	}
	// Close the worker Pool.
	if err := c.Pool.Close(); err != nil {
		return fmt.Errorf("failed to close the worker pool: %w", err)
	}

	loggedStart := false
	// Check if any errors occurred and warn the user.
	for _, res := range r {
		if err := res.Err(); err != nil {
			if !loggedStart {
				c.logWarn("The following tasks failed, the sysdump may be incomplete:")
				loggedStart = true
			}
			c.logWarn("%s: %v", res.String(), err)
		}
	}

	if loggedStart {
		c.logWarn("Please note that depending on your Cilium version and installation options, this may be expected")
	}

	c.teardownLogging()

	// Create the zip file in the current directory.
	c.log("🗳 Compiling sysdump")
	p, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}
	f := filepath.Join(p, c.replaceTimestamp(c.Options.OutputFileName)+".zip")
	if err := archiver.Archive([]string{c.sysdumpDir}, f); err != nil {
		return fmt.Errorf("failed to create zip file: %w", err)
	}
	c.log("✅ The sysdump has been saved to %s", f)

	// Try to remove the temporary directory.
	c.logDebug("Removing the temporary directory %s", c.sysdumpDir)
	if err := os.RemoveAll(c.sysdumpDir); err != nil {
		c.logWarn("failed to remove temporary directory %s: %v", c.sysdumpDir, err)
	}
	return nil
}

func (c *Collector) log(msg string, args ...interface{}) {
	fmt.Fprintf(c.logWriter, msg+"\n", args...)
}

func (c *Collector) logDebug(msg string, args ...interface{}) {
	if c.Options.Debug {
		c.log("🩺 "+msg, args...)
	}
}

func (c *Collector) logTask(msg string, args ...interface{}) {
	c.log("🔍 "+msg, args...)
}

func (c *Collector) logWarn(msg string, args ...interface{}) {
	c.log("⚠️ "+msg, args...)
}

func (c *Collector) shouldSkipTask(t Task) bool {
	return c.Options.Quick && !t.Quick
}

func (c *Collector) submitTetragonBugtoolTasks(ctx context.Context, pods []*corev1.Pod) error {
	for _, p := range pods {
		p := p
		workerID := fmt.Sprintf("%s-%s", tetragonBugtoolPrefix, p.Name)
		if err := c.Pool.Submit(workerID, func(ctx context.Context) error {
			p, containerName, cleanupFunc, err := c.ensureExecTarget(ctx, p, tetragonAgentContainerName)
			if err != nil {
				return fmt.Errorf("failed to pick exec target: %w", err)
			}
			defer func() {
				err := cleanupFunc(ctx)
				if err != nil {
					c.logWarn("Failed to clean up exec target: %v", err)
				}
			}()

			tarGzFile := fmt.Sprintf("%s-%s.tar.gz", tetragonBugtoolPrefix, time.Now().Format(timeFormat))
			// Run 'tetra bugtool' in the pod.
			command := []string{tetragonCliCommand, "bugtool", "--out", tarGzFile}

			c.logDebug("Executing 'tetragon-bugtool' command: %v", command)
			_, e, err := c.Client.ExecInPodWithStderr(ctx, p.Namespace, p.Name, containerName, command)
			if err != nil {
				return fmt.Errorf("failed to collect 'tetragon-bugtool' output for %q in namespace %q: %w: %s", p.Name, p.Namespace, err, e.String())
			}

			// Dump the resulting file's contents to the temporary directory.
			f := c.AbsoluteTempPath(fmt.Sprintf("%s-%s-<ts>.tar.gz", tetragonBugtoolPrefix, p.Name))
			err = c.Client.CopyFromPod(ctx, p.Namespace, p.Name, containerName, tarGzFile, f)
			if err != nil {
				return fmt.Errorf("failed to collect 'tetragon-bugtool' output for %q: %w", p.Name, err)
			}
			// Untar the resulting file.
			t := archiver.TarGz{
				Tar: &archiver.Tar{
					StripComponents: 1,
				},
			}
			if err := t.Unarchive(f, strings.Replace(f, ".tar.gz", "", -1)); err != nil {
				c.logWarn("Failed to unarchive 'tetragon-bugtool' output for %q: %v", p.Name, err)
				return nil
			}
			// Remove the file we've copied from the pod.
			if err := os.Remove(f); err != nil {
				c.logWarn("Failed to remove original 'tetragon-bugtool' file: %v", err)
				return nil
			}
			if _, err = c.Client.ExecInPod(ctx, p.Namespace, p.Name, containerName, []string{rmCommand, tarGzFile}); err != nil {
				c.logWarn("Failed to delete 'tetragon-bugtool' output from pod %q in namespace %q: %w", p.Name, p.Namespace, err)
				return nil
			}
			return nil
		}); err != nil {
			return fmt.Errorf("failed to submit 'tetragon-bugtool' task for %q: %w", p.Name, err)
		}
	}
	return nil
}

func (c *Collector) submitCiliumBugtoolTasks(ctx context.Context, pods []*corev1.Pod) error {
	for _, p := range pods {
		p := p
		if err := c.Pool.Submit(fmt.Sprintf("cilium-bugtool-"+p.Name), func(ctx context.Context) error {
			p, containerName, cleanupFunc, err := c.ensureExecTarget(ctx, p, ciliumAgentContainerName)
			if err != nil {
				return fmt.Errorf("failed to pick exec target: %w", err)
			}
			defer func() {
				err := cleanupFunc(ctx)
				if err != nil {
					c.logWarn("Failed to clean up exec target: %v", err)
				}
			}()

			// Run 'cilium-bugtool' in the pod.
			command := append([]string{ciliumBugtoolCommand, "--archiveType=gz"}, c.Options.CiliumBugtoolFlags...)

			c.logDebug("Executing cilium-bugtool command: %v", command)
			o, e, err := c.Client.ExecInPodWithStderr(ctx, p.Namespace, p.Name, containerName, command)
			if err != nil {
				return fmt.Errorf("failed to collect 'cilium-bugtool' output for %q in namespace %q: %w: %s", p.Name, p.Namespace, err, e.String())
			}
			// Capture the path to the resulting archive.
			outString := o.String() + e.String()
			m := ciliumBugtoolFileNameRegex.FindStringSubmatch(outString)
			if len(m) != 2 || len(m[1]) == 0 {
				return fmt.Errorf("failed to collect 'cilium-bugtool' output for %q in namespace %q: output doesn't contain archive name: %s", p.Name, p.Namespace, outString)
			}
			tarGzFile := m[1]

			// Dump the resulting file's contents to the temporary directory.
			f := c.AbsoluteTempPath(fmt.Sprintf(ciliumBugtoolFileName, p.Name))
			err = c.Client.CopyFromPod(ctx, p.Namespace, p.Name, containerName, tarGzFile, f)
			if err != nil {
				return fmt.Errorf("failed to collect 'cilium-bugtool' output for %q: %w", p.Name, err)
			}
			// Untar the resulting file.
			t := archiver.TarGz{
				Tar: &archiver.Tar{
					StripComponents: 1,
				},
			}
			if err := t.Unarchive(f, strings.Replace(f, ".tar.gz", "", -1)); err != nil {
				c.logWarn("Failed to unarchive 'cilium-bugtool' output for %q: %v", p.Name, err)
				return nil
			}
			// Remove the file we've copied from the pod.
			if err := os.Remove(f); err != nil {
				c.logWarn("Failed to remove original 'cilium-bugtool' file: %v", err)
				return nil
			}
			// Remove the file from the pod.
			if _, err = c.Client.ExecInPod(ctx, p.Namespace, p.Name, containerName, []string{rmCommand, tarGzFile}); err != nil {
				c.logWarn("Failed to delete 'cilium-bugtool' output from pod %q in namespace %q: %w", p.Name, p.Namespace, err)
				return nil
			}
			return nil
		}); err != nil {
			return fmt.Errorf("failed to submit 'cilium-bugtool' task for %q: %w", p.Name, err)
		}
	}
	return nil
}

func (c *Collector) submitHubbleFlowsTasks(_ context.Context, pods []*corev1.Pod, containerName string) error {
	hubbleFlowsTimeout := strconv.FormatInt(int64(c.Options.HubbleFlowsTimeout/time.Second), 10)
	for _, p := range pods {
		p := p
		if err := c.Pool.Submit(fmt.Sprintf("hubble-flows-"+p.Name), func(ctx context.Context) error {
			// HACK: Run hubble observe with --follow to avoid hitting the code path that triggers
			// https://github.com/cilium/cilium/issues/17036.
			b, e, err := c.Client.ExecInPodWithStderr(ctx, p.Namespace, p.Name, containerName, []string{
				"timeout", "--signal", "SIGINT", "--preserve-status", hubbleFlowsTimeout, "bash", "-c",
				fmt.Sprintf("hubble observe --follow --last %d --debug -o jsonpb", c.Options.HubbleFlowsCount),
			})
			if err != nil {
				return fmt.Errorf("failed to collect hubble flows for %q in namespace %q: %w: %s", p.Name, p.Namespace, err, e.String())
			}
			// Dump the resulting file's contents to the temporary directory.
			if err := c.WriteBytes(fmt.Sprintf(hubbleFlowsFileName, p.Name), b.Bytes()); err != nil {
				return fmt.Errorf("failed to write hubble flows for %q in namespace %q: %w", p.Name, p.Namespace, err)
			}
			// Dump the stderr from the hubble observe command to the temporary directory.
			if err := c.WriteBytes(fmt.Sprintf(hubbleObserveFileName, p.Name), e.Bytes()); err != nil {
				return fmt.Errorf("failed to write hubble stderr for %q in namespace %q: %w", p.Name, p.Namespace, err)
			}
			c.logDebug("Finished collecting hubble flows from %s/%s", p.Namespace, p.Name)
			return nil
		}); err != nil {
			return fmt.Errorf("failed to submit 'hubble-flows' task for %q: %w", p.Name, err)
		}
	}
	return nil
}

func extractGopsPID(output string) (string, error) {
	entries := strings.Split(output, "\n")
	for _, entry := range entries {
		match := gopsRegexp.FindStringSubmatch(entry)
		if len(match) > 0 {
			result := make(map[string]string)
			for i, name := range gopsRegexp.SubexpNames() {
				if i != 0 && name != "" {
					result[name] = match[i]
				}
			}
			return result["pid"], nil
		}
	}

	return "", fmt.Errorf("failed to extract pid from output: %q", output)
}

func (c *Collector) SubmitCniConflistSubtask(ctx context.Context, pods []*corev1.Pod, containerName string) error {
	for _, p := range pods {
		p := p
		if err := c.Pool.Submit(fmt.Sprintf("cniconflist-%s", p.GetName()), func(ctx context.Context) error {
			outputStr, err := c.Client.ExecInPod(ctx, p.GetNamespace(), p.GetName(), containerName, []string{
				lsCommand,
				c.Options.CNIConfigDirectory,
			})
			if err != nil {
				return err
			}
			cniConfigFileNames := strings.Split(strings.TrimSpace(outputStr.String()), "\n")
			for _, cniFileName := range cniConfigFileNames {
				cniConfigPath := path.Join(c.Options.CNIConfigDirectory, cniFileName)
				cniConfigFileContent, err := c.Client.ExecInPod(ctx, p.GetNamespace(), p.GetName(), containerName, []string{
					catCommand,
					cniConfigPath,
				})
				if err != nil {
					return fmt.Errorf("failed to copy CNI config file %q from directory %q: %w", cniFileName, c.Options.CNIConfigDirectory, err)
				}
				if err := c.WriteBytes(fmt.Sprintf(cniConfigFileName, cniFileName, p.GetName()), cniConfigFileContent.Bytes()); err != nil {
					return fmt.Errorf("failed to write CNI configuration %q for %q in namespace %q: %w", cniFileName, p.GetName(), p.Namespace, err)
				}
			}
			return nil
		}); err != nil {
			return fmt.Errorf("failed to submit cniconflist task for %q: %w", p.Name, err)
		}
	}
	return nil
}

// SubmitGopsSubtasks submits tasks to collect kubernetes logs from pods.
func (c *Collector) SubmitGopsSubtasks(ctx context.Context, pods []*corev1.Pod, containerName string) error {
	for _, p := range pods {
		p := p
		for _, g := range gopsStats {
			g := g
			if err := c.Pool.Submit(fmt.Sprintf("gops-%s-%s", p.Name, g), func(ctx context.Context) error {
				// Run 'gops' on the pod.
				gopsOutput, err := c.Client.ExecInPod(ctx, p.Namespace, p.Name, containerName, []string{
					gopsCommand,
				})
				if err != nil {
					return fmt.Errorf("failed to list processes %q (%q) in namespace %q: %w", p.Name, containerName, p.Namespace, err)
				}
				agentPID := gopsPID
				if c.Options.DetectGopsPID {
					var err error
					outputStr := gopsOutput.String()
					agentPID, err = extractGopsPID(outputStr)
					if err != nil {
						return err
					}
				}
				o, err := c.Client.ExecInPod(ctx, p.Namespace, p.Name, containerName, []string{
					gopsCommand,
					g,
					agentPID,
				})
				if err != nil {
					return fmt.Errorf("failed to collect gops for %q (%q) in namespace %q: %w", p.Name, containerName, p.Namespace, err)
				}
				// Dump the output to the temporary directory.
				if err := c.WriteBytes(fmt.Sprintf(gopsFileName, p.Name, containerName, g), o.Bytes()); err != nil {
					return fmt.Errorf("failed to collect gops for %q (%q) in namespace %q: %w", p.Name, containerName, p.Namespace, err)
				}
				return nil
			}); err != nil {
				return fmt.Errorf("failed to submit %s gops task for %q: %w", g, p.Name, err)
			}
		}
	}
	return nil
}

// SubmitLogsTasks submits tasks to collect kubernetes logs from pods.
func (c *Collector) SubmitLogsTasks(ctx context.Context, pods []*corev1.Pod, since time.Duration, limitBytes int64) error {
	t := time.Now().Add(-since)
	for _, p := range pods {
		p := p
		allContainers := append(p.Spec.Containers, p.Spec.InitContainers...)
		for _, d := range allContainers {
			d := d
			if err := c.Pool.Submit(fmt.Sprintf("logs-%s-%s", p.Name, d.Name), func(ctx context.Context) error {
				l, err := c.Client.GetLogs(ctx, p.Namespace, p.Name, d.Name, t, limitBytes, false)
				if err != nil {
					return fmt.Errorf("failed to collect logs for %q (%q) in namespace %q: %w", p.Name, d.Name, p.Namespace, err)
				}
				if err := c.WriteString(fmt.Sprintf(ciliumLogsFileName, p.Name, d.Name), l); err != nil {
					return fmt.Errorf("failed to collect logs for %q (%q) in namespace %q: %w", p.Name, d.Name, p.Namespace, err)
				}
				// Check if this container has restarted, in which case we should gather the previous one's logs too.
				previous := false
				for _, s := range p.Status.ContainerStatuses {
					s := s
					if s.Name == d.Name && s.RestartCount > 0 {
						previous = true
					}
				}
				if previous {
					c.logDebug("Collecting logs for restarted container %q in pod %q in namespace %q", d.Name, p.Name, p.Namespace)
					u, err := c.Client.GetLogs(ctx, p.Namespace, p.Name, d.Name, t, limitBytes, true)
					if err != nil {
						return fmt.Errorf("failed to collect previous logs for %q (%q) in namespace %q: %w", p.Name, d.Name, p.Namespace, err)
					}
					if err := c.WriteString(fmt.Sprintf(ciliumPreviousLogsFileName, p.Name, d.Name), u); err != nil {
						return fmt.Errorf("failed to collect previous logs for %q (%q) in namespace %q: %w", p.Name, d.Name, p.Namespace, err)
					}
				}
				return nil
			}); err != nil {
				return fmt.Errorf("failed to submit logs task for %q (%q): %w", p.Name, d.Name, err)
			}
		}
	}
	return nil
}

func (c *Collector) submitFlavorSpecificTasks(ctx context.Context, f k8s.Flavor) error {
	switch f.Kind {
	case k8s.KindEKS:
		if err := c.Pool.Submit(awsNodeDaemonSetName, func(ctx context.Context) error {
			// Collect the 'kube-system/aws-node' DaemonSet.
			d, err := c.Client.GetDaemonSet(ctx, awsNodeDaemonSetNamespace, awsNodeDaemonSetName, metav1.GetOptions{})
			if err != nil {
				if errors.IsNotFound(err) {
					c.logDebug("DaemonSet %q not found in namespace %q - this is expected when running in ENI mode", awsNodeDaemonSetName, awsNodeDaemonSetNamespace)
					return nil
				}
				return fmt.Errorf("failed to collect daemonset %q in namespace %q: %w", awsNodeDaemonSetName, awsNodeDaemonSetNamespace, err)
			}
			if err := c.WriteYAML(awsNodeDaemonSetFileName, d); err != nil {
				return fmt.Errorf("failed to collect daemonset %q in namespace %q: %w", awsNodeDaemonSetName, awsNodeDaemonSetNamespace, err)
			}
			// Only if the 'kube-system/aws-node' Daemonset is present...
			// ... collect any "SecurityGroupPolicy" resources.
			n := corev1.NamespaceAll
			l, err := c.Client.ListUnstructured(ctx, awsSecurityGroupPoliciesGVR, &n, metav1.ListOptions{})
			if err != nil {
				return fmt.Errorf("failed to collect security group policies: %w", err)
			}
			if err := c.WriteYAML(securityGroupPoliciesFileName, l); err != nil {
				return fmt.Errorf("failed to collect security group policies: %w", err)
			}
			// ... collect any "ENIConfigs" resources.
			l, err = c.Client.ListUnstructured(ctx, awsENIConfigsGVR, nil, metav1.ListOptions{})
			if err != nil {
				return fmt.Errorf("failed to collect ENI configs: %w", err)
			}
			if err := c.WriteYAML(eniconfigsFileName, l); err != nil {
				return fmt.Errorf("failed to collect ENI configs: %w", err)
			}
			return nil
		}); err != nil {
			return fmt.Errorf("failed to submit %q task: %w", awsNodeDaemonSetName, err)
		}
		return nil
	default:
		c.logDebug("No flavor-specific data to collect for %q", f.Kind.String())
		return nil
	}
}

func (c *Collector) submitKVStoreTasks(ctx context.Context, pod *corev1.Pod) error {
	for _, dump := range []struct {
		name   string
		prefix string
	}{
		{
			name:   "identities",
			prefix: "state/identities",
		},
		{
			name:   "ips",
			prefix: "state/ip",
		},
		{
			name:   "nodes",
			prefix: "state/nodes",
		},
		{
			name:   "cnpstatuses",
			prefix: "state/cnpstatuses",
		},
		{
			name:   "heartbeat",
			prefix: ".heartbeat",
		},
		{
			name:   "services",
			prefix: "state/services",
		},
	} {
		stdout, stderr, err := c.Client.ExecInPodWithStderr(ctx, pod.Namespace, pod.Name, defaults.AgentContainerName, []string{
			"cilium", "kvstore", "get", "cilium/" + dump.prefix, "--recursive", "-o", "json",
		})
		if err != nil {
			return fmt.Errorf("failed to collect kvstore data in %q in namespace %q: %w: %s", pod.Name, pod.Namespace, err, stderr.String())
		}
		filename := "kvstore-" + dump.name + ".json"
		if err := c.WriteString(filename, stdout.String()); err != nil {
			return fmt.Errorf("failed writing kvstore dump for prefix %q to file %q: %w", dump.prefix, filename, err)
		}
	}

	return nil
}

func buildNodeNameList(nodes *corev1.NodeList, filter string) ([]string, error) {
	w := strings.Split(strings.TrimSpace(filter), ",")
	r := make([]string, 0)
	for _, node := range nodes.Items {
		if len(w) == 0 || w[0] == "" {
			r = append(r, node.Name)
			continue
		}
		if isNodeInWhitelist(node, w) {
			r = append(r, node.Name)
			continue
		}
	}
	return r, nil
}

// FilterPods filters a list of pods by node names.
func FilterPods(l *corev1.PodList, n []string) []*corev1.Pod {
	r := make([]*corev1.Pod, 0)
	for _, p := range l.Items {
		p := p
		if utils.Contains(n, p.Spec.NodeName) {
			r = append(r, &p)
		}
	}
	return r
}

func isNodeInWhitelist(node corev1.Node, w []string) bool {
	for _, n := range w {
		if node.Name == n {
			return true
		}
		for _, a := range node.Status.Addresses {
			if a.Address == n {
				return true
			}
		}
	}
	return false
}

// AddTasks adds extra tasks for the collector to execute. Must be called before Run().
func (c *Collector) AddTasks(tasks []Task) {
	c.additionalTasks = append(c.additionalTasks, tasks...)
}

func detectCiliumNamespace(k KubernetesClient) (string, error) {
	for _, ns := range DefaultCiliumNamespaces {
		ctx := context.Background()
		ns, err := k.GetNamespace(ctx, ns, metav1.GetOptions{})
		if errors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("failed to detect Cilium namespace: %w", err)
		}

		_, err = k.GetDaemonSet(ctx, ns.Name, "cilium", metav1.GetOptions{})
		if errors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("failed to check for Cilium DaemonSet: %w", err)
		}
		return ns.Name, nil
	}
	return "", fmt.Errorf("failed to detect Cilium namespace, could not find Cilium installation in namespaces: %v", DefaultCiliumNamespaces)
}
