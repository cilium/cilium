// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package sysdump

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium-cli/internal/k8s"
	"github.com/cilium/cilium-cli/internal/utils"

	"github.com/cilium/workerpool"
	archiver "github.com/mholt/archiver/v3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/genericclioptions"
)

// Options groups together the set of options required to collect a sysdump.
type Options struct {
	// The labels used to target Cilium pods.
	CiliumLabelSelector string
	// The namespace Cilium is running in.
	CiliumNamespace string
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
func NewCollector(k KubernetesClient, o Options, startTime time.Time) (*Collector, error) {
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
	c.logDebug("Using %v as a temporary directory", c.sysdumpDir)

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
			Description: "Collecting the Cilium daemonset",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.Client.GetDaemonSet(ctx, c.Options.CiliumNamespace, ciliumDaemonSetName, metav1.GetOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect the Cilium daemonset: %w", err)
				}
				if err := c.WriteYAML(ciliumDaemonSetFileName, v); err != nil {
					return fmt.Errorf("failed to collect the Cilium daemonset: %w", err)
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
				v, err := c.Client.GetDeployment(ctx, c.Options.CiliumNamespace, ciliumOperatorDeploymentName, metav1.GetOptions{})
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
			Description:     "Collecting 'cilium-bugtool' output from Cilium pods",
			Quick:           false,
			Task: func(ctx context.Context) error {
				p, err := c.Client.ListPods(ctx, c.Options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: c.Options.CiliumLabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get Cilium pods: %w", err)
				}
				if err := c.submitBugtoolTasks(ctx, FilterPods(p, c.NodeList), ciliumAgentContainerName); err != nil {
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
			Description:     "Collecting platform-specific data",
			Quick:           true,
			Task: func(ctx context.Context) error {
				f, err := c.Client.AutodetectFlavor(ctx)
				if err != nil {
					c.logWarn("Failed to autodetect Kubernetes flavor: %v", err)
					return nil
				}
				c.logDebug("Detected flavor %q", f.Kind)
				if err := c.submitFlavorSpecificTasks(ctx, f); err != nil {
					return fmt.Errorf("failed to collect platform-specific data: %w", err)
				}
				return nil
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
	fmt.Fprintf(c.Options.Writer, msg+"\n", args...)
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

func (c *Collector) submitBugtoolTasks(ctx context.Context, pods []*corev1.Pod, containerName string) error {
	for _, p := range pods {
		p := p
		if err := c.Pool.Submit(fmt.Sprintf("cilium-bugtool-"+p.Name), func(ctx context.Context) error {
			// Run 'cilium-bugtool' in the pod.
			_, e, err := c.Client.ExecInPodWithStderr(ctx, p.Namespace, p.Name, containerName, []string{ciliumBugtoolCommand})
			if err != nil {
				return fmt.Errorf("failed to collect 'cilium-bugtool' output for %q in namespace %q: %w", p.Name, p.Namespace, err)
			}
			// Capture the path to the resulting archive.
			m := ciliumBugtoolFileNameRegex.FindStringSubmatch(e.String())
			if len(m) != 2 || len(m[1]) == 0 {
				return fmt.Errorf("failed to collect 'cilium-bugtool' output for %q in namespace %q: output doesn't contain archive name", p.Name, p.Namespace)
			}
			// Grab the resulting archive's contents from the pod.
			b, err := c.Client.ExecInPod(ctx, p.Namespace, p.Name, containerName, []string{"cat", m[1]})
			if err != nil {
				return fmt.Errorf("failed to collect 'cilium-bugtool' output for %q: %w", p.Name, err)
			}
			// Dump the resulting file's contents to the temporary directory.
			f := c.AbsoluteTempPath(fmt.Sprintf(ciliumBugtoolFileName, p.Name))
			if err := writeBytes(f, b.Bytes()); err != nil {
				return fmt.Errorf("failed to collect 'cilium-bugtool' output for %q: %w", p.Name, err)
			}
			// Untar the resulting file.
			t := archiver.Tar{
				StripComponents: 1,
			}
			if err := t.Unarchive(f, strings.Replace(f, ".tar", "", -1)); err != nil {
				c.logWarn("Failed to unarchive 'cilium-bugtool' output for %q: %v", p.Name, err)
				return nil
			}
			// Remove the file we've copied from the pod.
			if err := os.Remove(f); err != nil {
				c.logWarn("Failed to remove original 'cilium-bugtool' file: %v", err)
				return nil
			}
			// Remove the file from the pod.
			if _, err = c.Client.ExecInPod(ctx, p.Namespace, p.Name, containerName, []string{rmCommand, m[1]}); err != nil {
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
	for _, p := range pods {
		p := p
		if err := c.Pool.Submit(fmt.Sprintf("hubble-flows-"+p.Name), func(ctx context.Context) error {
			// HACK: Run hubble observe with --follow to avoid hitting the code path that triggers
			// https://github.com/cilium/cilium/issues/17036.
			b, e, err := c.Client.ExecInPodWithStderr(ctx, p.Namespace, p.Name, containerName, []string{
				"timeout", "--signal", "SIGINT", "--preserve-status", "5", "bash", "-c",
				fmt.Sprintf("hubble observe --follow --last %d -o jsonpb", c.Options.HubbleFlowsCount),
			})
			if err != nil {
				return fmt.Errorf("failed to collect hubble flows for %q in namespace %q: %w: %s", p.Name, p.Namespace, err, e.String())
			}
			// Dump the resulting file's contents to the temporary directory.
			if err := c.WriteBytes(fmt.Sprintf(hubbleFlowsFileName, p.Name), b.Bytes()); err != nil {
				return fmt.Errorf("failed to collect hubble flows for %q in namespace %q: %w", p.Name, p.Namespace, err)
			}
			return nil
		}); err != nil {
			return fmt.Errorf("failed to submit 'hubble-flows' task for %q: %w", p.Name, err)
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
				o, err := c.Client.ExecInPod(ctx, p.Namespace, p.Name, containerName, []string{
					gopsCommand,
					g,
					gopsPID,
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
