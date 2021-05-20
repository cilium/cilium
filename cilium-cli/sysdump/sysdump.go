// Copyright 2021 Authors of Cilium
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

	"github.com/cilium/cilium-cli/internal/utils"
	"github.com/cilium/workerpool"
	"github.com/hashicorp/go-multierror"
	archiver "github.com/mholt/archiver/v3"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	// The namespace Cilium operator is running in.
	CiliumOperatorNamespace string
	// Whether to enable debug logging.
	Debug bool
	// The labels used to target Hubble pods.
	HubbleLabelSelector string
	// The namespace Hubble is running in.
	HubbleNamespace string
	// The labels used to target Hubble Relay pods.
	HubbleRelayLabelSelector string
	// The namespace Hubble Relay is running in.
	HubbleRelayNamespace string
	// The labels used to target Hubble UI pods.
	HubbleUILabelSelector string
	// The namespace Hubble UI is running in.
	HubbleUINamespace string
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

type sysdumpTask struct {
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
	client  KubernetesClient
	options Options
	pool    *workerpool.WorkerPool
	// subtasksWg is used to wait for subtasks to be submitted to the pool before calling 'Drain'.
	// It is required since we don't know beforehand how many sub-tasks will be created, as they depend on the number of Cilium/Hubble/... pods found by "main" tasks.
	subtasksWg sync.WaitGroup
}

// NewCollector returns a new sysdump collector.
func NewCollector(k KubernetesClient, o Options) *Collector {
	return &Collector{
		client:  k,
		options: o,
		pool:    workerpool.New(o.WorkerCount),
	}
}

// Run performs the actual sysdump collection.
func (c *Collector) Run() error {
	// Grab the current timestamp and create a temporary directory to hold the files.
	t := time.Now()

	// replaceTimestamp can be used to replace the special timestamp placeholder in file and directory names.
	replaceTimestamp := func(f string) string {
		return strings.Replace(f, timestampPlaceholderFileName, t.Format(timeFormat), -1)
	}

	d, err := os.MkdirTemp("", "*")
	if err != nil {
		return fmt.Errorf("failed to create temporary directory: %w", err)
	}
	d = filepath.Join(d, replaceTimestamp(c.options.OutputFileName))
	if err := os.MkdirAll(d, dirMode); err != nil {
		return fmt.Errorf("failed to create temporary directory: %w", err)
	}
	c.logDebug("Using %v as a temporary directory", d)

	// absoluteTempPath returns the absolute path where to store the specified filename temporarily.
	absoluteTempPath := func(f string) string {
		return path.Join(d, replaceTimestamp(f))
	}

	// Grab the Kubernetes nodes for the target cluster.
	c.logTask("Collecting Kubernetes nodes")
	n, err := c.client.ListNodes(context.Background(), metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to collect Kubernetes nodes: %w", err)
	}
	c.logDebug("Finished collecting Kubernetes nodes")

	// Exit if there are no nodes, as there's nothing to do.
	if len(n.Items) == 0 {
		c.logTask("No nodes found in the current cluster")
		return nil
	}
	// If there are many nodes and no filters are specified, issue a warning and wait for a while before proceeding so the user can cancel the process.
	if len(n.Items) > c.options.LargeSysdumpThreshold && (c.options.NodeList == DefaultNodeList && c.options.LogsLimitBytes == DefaultLogsLimitBytes && c.options.LogsSinceTime == DefaultLogsSinceTime) {
		c.logWarn("Detected a large cluster (%d nodes)", len(n.Items))
		c.logWarn("Consider using a node filter, a custom log size limit and/or a custom log time range to decrease the size of the sysdump")
		c.logWarn("Waiting for %s before continuing", c.options.LargeSysdumpAbortTimeout)
		t := time.NewTicker(c.options.LargeSysdumpAbortTimeout)
		defer t.Stop()
		<-t.C
	}

	// Build the list of node names in which the user is interested.
	l, err := buildNodeNameList(n, c.options.NodeList)
	if err != nil {
		return fmt.Errorf("failed to build node list: %w", err)
	}
	nodeList := l
	c.logDebug("Restricting bugtool and logs collection to pods in %v", nodeList)

	// tasks is the list of base tasks to be run.
	tasks := []sysdumpTask{
		{
			Description: "Collect Kubernetes nodes",
			Quick:       true,
			Task: func(_ context.Context) error {
				if err := writeYaml(absoluteTempPath(kubernetesNodesFileName), n); err != nil {
					return fmt.Errorf("failed to collect Kubernetes nodes: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collect Kubernetes version",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.client.GetVersion(ctx)
				if err != nil {
					return fmt.Errorf("failed to collect Kubernetes version: %w", err)
				}
				if err := writeString(absoluteTempPath(kubernetesVersionInfoFileName), v); err != nil {
					return fmt.Errorf("failed to dump Kubernetes version: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Kubernetes events",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.client.ListEvents(ctx, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Kubernetes events: %w", err)
				}
				if err := writeYaml(absoluteTempPath(kubernetesEventsFileName), v); err != nil {
					return fmt.Errorf("failed to collect Kubernetes events: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Kubernetes namespaces",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.client.ListNamespaces(ctx, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Kubernetes namespaces: %w", err)
				}
				if err := writeYaml(absoluteTempPath(kubernetesNamespacesFileName), v); err != nil {
					return fmt.Errorf("failed to collect Kubernetes namespaces: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Kubernetes pods",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.client.ListPods(ctx, corev1.NamespaceAll, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Kubernetes pods: %w", err)
				}
				if err := writeYaml(absoluteTempPath(kubernetesPodsFileName), v); err != nil {
					return fmt.Errorf("failed to collect Kubernetes pods: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Kubernetes pods summary",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.client.GetPodsTable(ctx)
				if err != nil {
					return fmt.Errorf("failed to collect Kubernetes pods summary: %w", err)
				}
				if err := writeTable(absoluteTempPath(kubernetesPodsSummaryFileName), v); err != nil {
					return fmt.Errorf("failed to collect Kubernetes pods summary: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Kubernetes services",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.client.ListServices(ctx, corev1.NamespaceAll, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Kubernetes services: %w", err)
				}
				if err := writeYaml(absoluteTempPath(kubernetesServicesFileName), v); err != nil {
					return fmt.Errorf("failed to collect Kubernetes services: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Kubernetes network policies",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.client.ListNetworkPolicies(ctx, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Kubernetes network policies: %w", err)
				}
				if err := writeYaml(absoluteTempPath(kubernetesNetworkPoliciesFileName), v); err != nil {
					return fmt.Errorf("failed to collect Kubernetes network policies: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Cilium network policies",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.client.ListCiliumNetworkPolicies(ctx, corev1.NamespaceAll, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Cilium network policies: %w", err)
				}
				if err := writeYaml(absoluteTempPath(ciliumNetworkPoliciesFileName), v); err != nil {
					return fmt.Errorf("failed to collect Cilium network policies: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Cilium cluster-wide network policies",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.client.ListCiliumClusterwideNetworkPolicies(ctx, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Cilium cluster-wide network policies: %w", err)
				}
				if err := writeYaml(absoluteTempPath(ciliumClusterWideNetworkPoliciesFileName), v); err != nil {
					return fmt.Errorf("failed to collect Cilium cluster-wide network policies: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Cilium endpoints",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.client.ListCiliumEndpoints(ctx, corev1.NamespaceAll, metav1.ListOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect Cilium endpoints: %w", err)
				}
				if err := writeYaml(absoluteTempPath(ciliumEndpointsFileName), v); err != nil {
					return fmt.Errorf("failed to collect Cilium endpoints: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Cilium identities",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.client.ListCiliumIdentities(ctx)
				if err != nil {
					return fmt.Errorf("failed to collect Cilium identities: %w", err)
				}
				if err := writeYaml(absoluteTempPath(ciliumIdentitiesFileName), v); err != nil {
					return fmt.Errorf("failed to collect Cilium identities: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Cilium nodes",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.client.ListCiliumNodes(ctx)
				if err != nil {
					return fmt.Errorf("failed to collect Cilium nodes: %w", err)
				}
				if err := writeYaml(absoluteTempPath(ciliumNodesFileName), v); err != nil {
					return fmt.Errorf("failed to collect Cilium nodes: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting Cilium etcd secret",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.client.GetSecret(ctx, c.options.CiliumNamespace, ciliumEtcdSecretsSecretName, metav1.GetOptions{})
				if err != nil {
					if errors.IsNotFound(err) {
						c.logWarn("secret %q not found in namespace %q - this is expected when using the CRD KVStore", ciliumEtcdSecretsSecretName, c.options.CiliumNamespace)
						return nil
					}
					return fmt.Errorf("failed to collect Cilium etcd secret: %w", err)
				}
				// Redact the actual values.
				for k := range v.Data {
					v.Data[k] = []byte(redacted)
				}
				if err := writeYaml(absoluteTempPath(ciliumEtcdSecretFileName), v); err != nil {
					return fmt.Errorf("failed to collect Cilium etcd secret: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting the Cilium configuration",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.client.GetConfigMap(ctx, c.options.CiliumNamespace, ciliumConfigConfigMapName, metav1.GetOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect the Cilium configuration: %w", err)
				}
				if err := writeYaml(absoluteTempPath(ciliumConfigMapFileName), v); err != nil {
					return fmt.Errorf("failed to collect the Cilium configuration: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting the Cilium daemonset",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.client.GetDaemonSet(ctx, c.options.CiliumNamespace, ciliumDaemonSetName, metav1.GetOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect the Cilium daemonset: %w", err)
				}
				if err := writeYaml(absoluteTempPath(ciliumDaemonSetFileName), v); err != nil {
					return fmt.Errorf("failed to collect the Cilium daemonset: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting the Hubble daemonset",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.client.GetDaemonSet(ctx, c.options.HubbleNamespace, hubbleDaemonSetName, metav1.GetOptions{})
				if err != nil {
					if errors.IsNotFound(err) {
						c.logWarn("daemonset %q not found in namespace %q - this is expected in recent versions of Cilium", hubbleDaemonSetName, c.options.HubbleNamespace)
						return nil
					}
					return fmt.Errorf("failed to collect the Hubble daemonset: %w", err)
				}
				if err := writeYaml(absoluteTempPath(hubbleDaemonsetFileName), v); err != nil {
					return fmt.Errorf("failed to collect the Hubble daemonset: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting the Hubble Relay deployment",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.client.GetDeployment(ctx, c.options.HubbleRelayNamespace, hubbleRelayDeploymentName, metav1.GetOptions{})
				if err != nil {
					if errors.IsNotFound(err) {
						c.logWarn("deployment %q not found in namespace %q", hubbleRelayDeploymentName, c.options.HubbleRelayNamespace)
						return nil
					}
					return fmt.Errorf("failed to collect the Hubble Relay deployment: %w", err)
				}
				if err := writeYaml(absoluteTempPath(hubbleRelayDeploymentFileName), v); err != nil {
					return fmt.Errorf("failed to collect the Hubble Relay deployment: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting the Hubble UI deployment",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.client.GetDeployment(ctx, c.options.HubbleUINamespace, hubbleUIDeploymentName, metav1.GetOptions{})
				if err != nil {
					if errors.IsNotFound(err) {
						c.logWarn("deployment %q not found in namespace %q", hubbleUIDeploymentName, c.options.HubbleUINamespace)
						return nil
					}
					return fmt.Errorf("failed to collect the Hubble UI deployment: %w", err)
				}
				if err := writeYaml(absoluteTempPath(hubbleUIDeploymentFileName), v); err != nil {
					return fmt.Errorf("failed to collect the Hubble UI deployment: %w", err)
				}
				return nil
			},
		},
		{
			Description: "Collecting the Cilium operator deployment",
			Quick:       true,
			Task: func(ctx context.Context) error {
				v, err := c.client.GetDeployment(ctx, c.options.CiliumNamespace, ciliumOperatorDeploymentName, metav1.GetOptions{})
				if err != nil {
					return fmt.Errorf("failed to collect the Cilium operator deployment: %w", err)
				}
				if err := writeYaml(absoluteTempPath(ciliumOperatorDeploymentFileName), v); err != nil {
					return fmt.Errorf("failed to collect the Cilium operator deployment: %w", err)
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting gops stats from Cilium pods",
			Quick:           true,
			Task: func(ctx context.Context) error {
				p, err := c.client.ListPods(ctx, c.options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: c.options.CiliumLabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get Cilium pods: %w", err)
				}
				if err := c.submitGopsSubtasks(ctx, filterPods(p, nodeList), ciliumAgentContainerName, absoluteTempPath); err != nil {
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
				p, err := c.client.ListPods(ctx, c.options.HubbleNamespace, metav1.ListOptions{
					LabelSelector: c.options.HubbleLabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get Hubble pods: %w", err)
				}
				if err := c.submitGopsSubtasks(ctx, filterPods(p, nodeList), hubbleContainerName, absoluteTempPath); err != nil {
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
				p, err := c.client.ListPods(ctx, c.options.HubbleNamespace, metav1.ListOptions{
					LabelSelector: c.options.HubbleRelayLabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get Hubble Relay pods: %w", err)
				}
				if err := c.submitGopsSubtasks(ctx, filterPods(p, nodeList), hubbleRelayContainerName, absoluteTempPath); err != nil {
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
				p, err := c.client.ListPods(ctx, c.options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: c.options.CiliumLabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get Cilium pods: %w", err)
				}
				if err := c.submitBugtoolTasks(ctx, filterPods(p, nodeList), ciliumAgentContainerName, absoluteTempPath); err != nil {
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
				p, err := c.client.ListPods(ctx, c.options.CiliumNamespace, metav1.ListOptions{
					LabelSelector: c.options.CiliumLabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get logs from Cilium pods")
				}
				if err := c.submitLogsTasks(ctx, filterPods(p, nodeList), c.options.LogsSinceTime, c.options.LogsLimitBytes, absoluteTempPath); err != nil {
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
				p, err := c.client.ListPods(ctx, c.options.CiliumOperatorNamespace, metav1.ListOptions{
					LabelSelector: c.options.CiliumOperatorLabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get logs from Cilium operator pods")
				}
				if err := c.submitLogsTasks(ctx, filterPods(p, nodeList), c.options.LogsSinceTime, c.options.LogsLimitBytes, absoluteTempPath); err != nil {
					return fmt.Errorf("failed to collect logs from Cilium operator pods")
				}
				return nil
			},
		},
		{
			CreatesSubtasks: true,
			Description:     "Collecting logs from Hubble pods",
			Quick:           false,
			Task: func(ctx context.Context) error {
				p, err := c.client.ListPods(ctx, c.options.HubbleNamespace, metav1.ListOptions{
					LabelSelector: c.options.HubbleLabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get logs from Hubble pods")
				}
				if err := c.submitLogsTasks(ctx, filterPods(p, nodeList), c.options.LogsSinceTime, c.options.LogsLimitBytes, absoluteTempPath); err != nil {
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
				p, err := c.client.ListPods(ctx, c.options.HubbleRelayNamespace, metav1.ListOptions{
					LabelSelector: c.options.HubbleRelayLabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get logs from Hubble Relay pods")
				}
				if err := c.submitLogsTasks(ctx, filterPods(p, nodeList), c.options.LogsSinceTime, c.options.LogsLimitBytes, absoluteTempPath); err != nil {
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
				p, err := c.client.ListPods(ctx, c.options.HubbleNamespace, metav1.ListOptions{
					LabelSelector: c.options.HubbleLabelSelector,
				})
				if err != nil {
					return fmt.Errorf("failed to get logs from Hubble UI pods")
				}
				if err := c.submitLogsTasks(ctx, filterPods(p, nodeList), c.options.LogsSinceTime, c.options.LogsLimitBytes, absoluteTempPath); err != nil {
					return fmt.Errorf("failed to collect logs from Hubble UI pods")
				}
				return nil
			},
		},
	}

	// Add the tasks to the worker pool.
	for i, t := range tasks {
		t := t
		if c.options.Quick && !t.Quick {
			c.logDebug("Skipping %q", t.Description)
			continue
		}
		if t.CreatesSubtasks {
			c.subtasksWg.Add(1)
		}
		if err := c.pool.Submit(fmt.Sprintf("%d", i), func(ctx context.Context) error {
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
	var merr error
	r, err := c.pool.Drain()
	if err != nil {
		return fmt.Errorf("failed to drain the worker pool :%w", err)
	}
	for _, res := range r {
		if err := res.Err(); err != nil {
			merr = multierror.Append(merr, err)
		}
	}

	// Close the worker pool.
	if err := c.pool.Close(); err != nil {
		return fmt.Errorf("failed to close the worker pool: %w", err)
	}

	// Check if any errors occurred and warn the user.
	if merr != nil {
		c.logWarn("The sysdump may be incomplete — %s", merr.Error())
		c.logWarn("Please note that depending on your Cilium version and installation options, this may be expected")
	}

	// Create the zip file in the current directory.
	c.log("🗳 Compiling sysdump")
	p, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}
	f := filepath.Join(p, replaceTimestamp(c.options.OutputFileName)+".zip")
	if err := archiver.Archive([]string{d}, f); err != nil {
		return fmt.Errorf("failed to create zip file: %w", err)
	}
	c.log("✅ The sysdump has been saved to %s", f)

	// Try to remove the temporary directory.
	c.logDebug("Removing the temporary directory %s", d)
	if err := os.RemoveAll(d); err != nil {
		c.logWarn("failed to remove temporary directory %s: %v", d, err)
	}
	return nil
}

func (c *Collector) log(msg string, args ...interface{}) {
	fmt.Fprintf(c.options.Writer, msg+"\n", args...)
}

func (c *Collector) logDebug(msg string, args ...interface{}) {
	if c.options.Debug {
		c.log("🩺 "+msg, args...)
	}
}

func (c *Collector) logTask(msg string, args ...interface{}) {
	c.log("🔍 "+msg, args...)
}

func (c *Collector) logWarn(msg string, args ...interface{}) {
	c.log("⚠️ "+msg, args...)
}

func (c *Collector) submitBugtoolTasks(ctx context.Context, pods []*corev1.Pod, containerName string, path func(string) string) error {
	for _, p := range pods {
		p := p
		if err := c.pool.Submit(fmt.Sprintf("cilium-bugtool-"+p.Name), func(ctx context.Context) error {
			// Run 'cilium-bugtool' in the pod.
			_, e, err := c.client.ExecInPodWithStderr(ctx, p.Namespace, p.Name, containerName, []string{ciliumBugtoolCommand})
			if err != nil {
				return fmt.Errorf("failed to collect 'cilium-bugtool' output for %q in namespace %q: %w", p.Name, p.Namespace, err)
			}
			// Capture the path to the resulting archive.
			m := ciliumBugtoolFileNameRegex.FindStringSubmatch(e.String())
			if len(m) != 2 || len(m[1]) == 0 {
				return fmt.Errorf("failed to collect 'cilium-bugtool' output for %q in namespace %q: output doesn't contain archive name", p.Name, p.Namespace)
			}
			// Grab the resulting archive's contents from the pod.
			b, err := c.client.ExecInPod(ctx, p.Namespace, p.Name, containerName, []string{"cat", m[1]})
			if err != nil {
				return fmt.Errorf("failed to collect 'cilium-bugtool' output for %q: %w", p.Name, err)
			}
			// Dump the resulting file's contents to the temporary directory.
			f := path(fmt.Sprintf(ciliumBugtoolFileName, p.Name))
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
			if _, err = c.client.ExecInPod(ctx, p.Namespace, p.Name, containerName, []string{rmCommand, m[1]}); err != nil {
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

func (c *Collector) submitGopsSubtasks(ctx context.Context, pods []*corev1.Pod, containerName string, path func(string) string) error {
	for _, p := range pods {
		p := p
		for _, g := range gopsStats {
			g := g
			if err := c.pool.Submit(fmt.Sprintf("gops-%s-%s", p.Name, g), func(ctx context.Context) error {
				// Run 'gops' on the pod.
				o, err := c.client.ExecInPod(ctx, p.Namespace, p.Name, containerName, []string{
					gopsCommand,
					g,
					gopsPID,
				})
				if err != nil {
					return fmt.Errorf("failed to collect gops for %q (%q) in namespace %q: %w", p.Name, containerName, p.Namespace, err)
				}
				// Dump the output to the temporary directory.
				if err := writeBytes(path(fmt.Sprintf(gopsFileName, p.Name, containerName, g)), o.Bytes()); err != nil {
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

func (c *Collector) submitLogsTasks(ctx context.Context, pods []*corev1.Pod, since time.Duration, limitBytes int64, path func(string) string) error {
	t := time.Now().Add(-since)
	for _, p := range pods {
		p := p
		for _, d := range p.Spec.Containers {
			d := d
			if err := c.pool.Submit(fmt.Sprintf("logs-%s-%s", p.Name, d.Name), func(ctx context.Context) error {
				l, err := c.client.GetLogs(ctx, p.Namespace, p.Name, d.Name, t, limitBytes, false)
				if err != nil {
					return fmt.Errorf("failed to collect logs for %q (%q) in namespace %q: %w", p.Name, d.Name, p.Namespace, err)
				}
				if err := writeString(path(fmt.Sprintf(ciliumLogsFileName, p.Name, d.Name)), l); err != nil {
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
					u, err := c.client.GetLogs(ctx, p.Namespace, p.Name, d.Name, t, limitBytes, true)
					if err != nil {
						return fmt.Errorf("failed to collect previous logs for %q (%q) in namespace %q: %w", p.Name, d.Name, p.Namespace, err)
					}
					if err := writeString(path(fmt.Sprintf(ciliumPreviousLogsFileName, p.Name, d.Name)), u); err != nil {
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

func filterPods(l *corev1.PodList, n []string) []*corev1.Pod {
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
