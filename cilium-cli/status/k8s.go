// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package status

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/workerpool"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/internal/helm"
	"github.com/cilium/cilium-cli/internal/utils"
	"github.com/cilium/cilium-cli/k8s"
)

const (
	// DefaultWorkerCount is the number of the max workers used to gather the status
	DefaultWorkerCount int = 5
)

type K8sStatusParameters struct {
	Namespace    string
	Wait         bool
	WaitDuration time.Duration
	// WarningFreePods specifies a list of pods which are required to be
	// warning free. This takes precedence over IgnoreWarnings and is only
	// used if Wait is true.
	WarningFreePods []string
	// IgnoreWarnings will, if set to true, ignore any warnings on pods to
	// determine the readiness. This is only used if Wait is true and
	// WarningFreePods is empty. If WarningFreePods is non-empty, the value
	// of this flag is meaningless.
	IgnoreWarnings bool

	// The number of workers to use.
	WorkerCount int

	// The output format
	Output string
}

type K8sStatusCollector struct {
	client k8sImplementation
	params K8sStatusParameters
}

type k8sImplementation interface {
	CiliumStatus(ctx context.Context, namespace, pod string) (*models.StatusResponse, error)
	GetDaemonSet(ctx context.Context, namespace, name string, options metav1.GetOptions) (*appsv1.DaemonSet, error)
	GetDeployment(ctx context.Context, namespace, name string, options metav1.GetOptions) (*appsv1.Deployment, error)
	ListPods(ctx context.Context, namespace string, options metav1.ListOptions) (*corev1.PodList, error)
	ListCiliumEndpoints(ctx context.Context, namespace string, options metav1.ListOptions) (*ciliumv2.CiliumEndpointList, error)
	CiliumLogs(ctx context.Context, namespace, pod string, since time.Time, filter *regexp.Regexp) (string, error)
}

func NewK8sStatusCollector(client k8sImplementation, params K8sStatusParameters) (*K8sStatusCollector, error) {
	return &K8sStatusCollector{
		client: client,
		params: params,
	}, nil
}

type ClusterMeshAgentConnectivityStatus struct {
	GlobalServices int64
	Clusters       map[string]*models.RemoteCluster
	Errors         ErrorCountMap
}

func (k *K8sStatusCollector) ClusterMeshConnectivity(ctx context.Context, ciliumPod string) (*ClusterMeshAgentConnectivityStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, k.params.waitTimeout())
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		s, err := k.clusterMeshConnectivity(ctx, ciliumPod)
		if err != nil {
			if k.params.Wait {
				time.Sleep(defaults.WaitRetryInterval)
				continue
			}
		}

		// If we are waiting for a successful status then all clusters need to
		// be ready
		if k.params.Wait {
			for _, cluster := range s.Clusters {
				if !cluster.Ready {
					time.Sleep(defaults.WaitRetryInterval)
					continue
				}
			}
		}

		return s, err
	}
}

// ErrClusterMeshStatusNotAvailable is a sentinel.
var ErrClusterMeshStatusNotAvailable = errors.New("ClusterMesh status is not available")

func (k *K8sStatusCollector) clusterMeshConnectivity(ctx context.Context, ciliumPod string) (*ClusterMeshAgentConnectivityStatus, error) {
	c := &ClusterMeshAgentConnectivityStatus{
		Clusters: map[string]*models.RemoteCluster{},
	}

	status, err := k.client.CiliumStatus(ctx, k.params.Namespace, ciliumPod)
	if err != nil {
		return nil, fmt.Errorf("unable to determine cilium status: %w", err)
	}

	if status.ClusterMesh == nil {
		return nil, ErrClusterMeshStatusNotAvailable
	}

	c.GlobalServices = status.ClusterMesh.NumGlobalServices
	for _, cluster := range status.ClusterMesh.Clusters {
		c.Clusters[cluster.Name] = cluster
	}

	return c, nil
}

func (k *K8sStatusCollector) deploymentStatus(ctx context.Context, status *Status, name string) (bool, error) {
	d, err := k.client.GetDeployment(ctx, k.params.Namespace, name, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		return true, nil
	}

	if err != nil {
		return false, err
	}

	if d == nil {
		return false, fmt.Errorf("deployment %s is not available", name)
	}

	stateCount := PodStateCount{Type: "Deployment"}
	stateCount.Desired = int(d.Status.Replicas)
	stateCount.Ready = int(d.Status.ReadyReplicas)
	stateCount.Available = int(d.Status.AvailableReplicas)
	stateCount.Unavailable = int(d.Status.UnavailableReplicas)

	status.mutex.Lock()
	defer status.mutex.Unlock()

	status.PodState[name] = stateCount

	notReady := stateCount.Desired - stateCount.Ready
	if notReady > 0 {
		status.AddAggregatedError(name, name, fmt.Errorf("%d pods of Deployment %s are not ready", notReady, name))
	}

	if unavailable := stateCount.Unavailable - notReady; unavailable > 0 {
		status.AddAggregatedWarning(name, name, fmt.Errorf("%d pods of Deployment %s are not available", unavailable, name))
	}

	// ObservedGeneration behind: DeploymentController has not yet noticed the latest change
	if d.Generation != d.Status.ObservedGeneration {
		status.AddAggregatedError(name, name, fmt.Errorf("deployment %s is updated but rollout has not started", name))
	}

	// Deployment change is not fully rolled out
	if d.Status.UpdatedReplicas < d.Status.Replicas {
		status.AddAggregatedError(name, name, fmt.Errorf("deployment %s is rolling out - %d out of %d pods updated", name, d.Status.UpdatedReplicas, d.Status.Replicas))
	}

	return false, nil
}

func (k *K8sStatusCollector) podCount(ctx context.Context, status *Status) error {
	var numberAllPod, numberCiliumPod int

	pods, err := k.client.ListPods(ctx, "", metav1.ListOptions{})
	if err != nil {
		return err
	}

	if pods != nil && len(pods.Items) != 0 {
		for _, pod := range pods.Items {
			if !pod.Spec.HostNetwork && (pod.Status.Phase == corev1.PodRunning || pod.Status.Phase == corev1.PodPending) {
				numberAllPod++
			}
		}
	}

	ciliumEps, err := k.client.ListCiliumEndpoints(ctx, "", metav1.ListOptions{})
	if err != nil {
		return err
	}
	if ciliumEps != nil {
		numberCiliumPod = len(ciliumEps.Items)
	}

	status.PodsCount = PodsCount{
		All:      numberAllPod,
		ByCilium: numberCiliumPod,
	}

	return nil
}

func (k *K8sStatusCollector) daemonSetStatus(ctx context.Context, status *Status, name string) (bool, error) {
	daemonSet, err := k.client.GetDaemonSet(ctx, k.params.Namespace, name, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		return true, err
	}

	if err != nil {
		return false, err
	}

	if daemonSet == nil {
		return false, fmt.Errorf("DaemonSet %s is not available", name)
	}

	stateCount := PodStateCount{Type: "DaemonSet"}
	stateCount.Desired = int(daemonSet.Status.DesiredNumberScheduled)
	stateCount.Ready = int(daemonSet.Status.NumberReady)
	stateCount.Available = int(daemonSet.Status.NumberAvailable)
	stateCount.Unavailable = int(daemonSet.Status.NumberUnavailable)

	status.mutex.Lock()
	defer status.mutex.Unlock()

	status.PodState[name] = stateCount

	notReady := int(daemonSet.Status.DesiredNumberScheduled) - int(daemonSet.Status.NumberReady)
	if notReady > 0 {
		status.AddAggregatedError(name, name, fmt.Errorf("%d pods of DaemonSet %s are not ready", notReady, name))
	}

	if unavailable := int(daemonSet.Status.NumberUnavailable) - notReady; unavailable > 0 {
		status.AddAggregatedWarning(name, name, fmt.Errorf("%d pods of DaemonSet %s are not available", unavailable, name))
	}

	// ObservedGeneration behind: DaemonSetController has not yet noticed the latest change
	if daemonSet.Generation != daemonSet.Status.ObservedGeneration {
		status.AddAggregatedError(name, name, fmt.Errorf("daemonset %s is updated but rollout has not started", name))
	}

	// DaemonSet change is not fully rolled out
	if daemonSet.Status.UpdatedNumberScheduled < daemonSet.Status.DesiredNumberScheduled {
		status.AddAggregatedError(name, name, fmt.Errorf("daemonset %s is rolling out - %d out of %d pods updated", name, daemonSet.Status.UpdatedNumberScheduled, daemonSet.Status.DesiredNumberScheduled))
	}

	return false, nil
}

type podStatusCallback func(ctx context.Context, status *Status, name string, pod *corev1.Pod)

func (k *K8sStatusCollector) podStatus(ctx context.Context, status *Status, name, filter string, callback podStatusCallback) error {
	pods, err := k.client.ListPods(ctx, k.params.Namespace, metav1.ListOptions{LabelSelector: filter})
	if err != nil {
		return err
	}

	if pods == nil {
		return fmt.Errorf("no pods found")
	}

	phaseCount, imageCount := MapCount{}, MapCount{}

	for i, pod := range pods.Items {
		phaseCount[string(pod.Status.Phase)]++

		switch pod.Status.Phase {
		case corev1.PodPending:
			status.AddAggregatedWarning(name, pod.Name, fmt.Errorf("pod is pending"))
		case corev1.PodRunning, corev1.PodSucceeded:
		case corev1.PodFailed:
			status.AddAggregatedError(name, pod.Name, fmt.Errorf("pod has failed: %s - %s", pod.Status.Reason, pod.Status.Message))
		}

		for _, container := range pod.Spec.Containers {
			imageCount[container.Image]++
		}

		if callback != nil {
			callback(ctx, status, name, &pods.Items[i])
		}
	}

	status.PhaseCount[name] = phaseCount
	status.ImageCount[name] = imageCount

	return nil
}

func (s K8sStatusParameters) waitTimeout() time.Duration {
	if s.WaitDuration != time.Duration(0) {
		return s.WaitDuration
	}

	return 5 * time.Minute
}

func (k *K8sStatusCollector) statusIsReady(s *Status) bool {
	if s.totalErrors() > 0 {
		return false
	}

	if !k.params.IgnoreWarnings && len(k.params.WarningFreePods) == 0 {
		if s.totalWarnings() > 0 {
			return false
		}
	}

	for _, name := range k.params.WarningFreePods {
		if a := s.Errors[name]; a != nil {
			for _, c := range a {
				if len(c.Warnings) > 0 || len(c.Errors) > 0 {
					return false
				}
			}
		}
	}

	return true
}

func (k *K8sStatusCollector) Status(ctx context.Context) (*Status, error) {
	var mostRecentStatus *Status

	ctx, cancel := context.WithTimeout(ctx, k.params.waitTimeout())
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return mostRecentStatus, fmt.Errorf("timeout while waiting for status to become successful: %w", ctx.Err())
		default:
		}

		s := k.status(ctx)
		// We collect the most recent status that even if the last status call
		// fails, we can still display the most recent status
		if s != nil {
			mostRecentStatus = s
		}
		if !k.statusIsReady(s) && k.params.Wait {
			time.Sleep(defaults.WaitRetryInterval)
			continue
		}

		return mostRecentStatus, nil
	}
}

type statusTask struct {
	name string
	task func(_ context.Context) error
}

func (k *K8sStatusCollector) status(ctx context.Context) *Status {
	status := newStatus()
	tasks := []statusTask{
		{
			name: defaults.AgentDaemonSetName,
			task: func(_ context.Context) error {
				_, err := k.daemonSetStatus(ctx, status, defaults.AgentDaemonSetName)
				status.mutex.Lock()
				defer status.mutex.Unlock()

				if err != nil {
					status.AddAggregatedError(defaults.AgentDaemonSetName, defaults.AgentDaemonSetName, err)
					status.CollectionError(err)
				}

				return err
			},
		},
		{
			name: defaults.EnvoyDaemonSetName,
			task: func(_ context.Context) error {
				disabled, err := k.daemonSetStatus(ctx, status, defaults.EnvoyDaemonSetName)
				status.mutex.Lock()
				defer status.mutex.Unlock()

				if disabled {
					status.SetDisabled(defaults.EnvoyDaemonSetName, defaults.EnvoyDaemonSetName, disabled)
					return nil
				}

				if err != nil {
					status.AddAggregatedError(defaults.EnvoyDaemonSetName, defaults.EnvoyDaemonSetName, err)
					status.CollectionError(err)
				}

				if err := k.podStatus(ctx, status, defaults.EnvoyDaemonSetName, "name=cilium-envoy", nil); err != nil {
					status.CollectionError(err)
				}

				return nil
			},
		},
		{
			name: defaults.OperatorDeploymentName,
			task: func(_ context.Context) error {
				disabled, err := k.deploymentStatus(ctx, status, defaults.OperatorDeploymentName)
				status.mutex.Lock()
				defer status.mutex.Unlock()

				status.SetDisabled(defaults.OperatorDeploymentName, defaults.OperatorDeploymentName, disabled)

				if err != nil {
					status.AddAggregatedError(defaults.OperatorDeploymentName, defaults.OperatorDeploymentName, err)
					status.CollectionError(err)
				}

				err = k.podStatus(ctx, status, defaults.OperatorDeploymentName, "name=cilium-operator", nil)
				return err
			},
		},
		{
			name: defaults.RelayDeploymentName,
			task: func(_ context.Context) error {
				disabled, err := k.deploymentStatus(ctx, status, defaults.RelayDeploymentName)
				status.mutex.Lock()
				defer status.mutex.Unlock()

				status.SetDisabled(defaults.RelayDeploymentName, defaults.RelayDeploymentName, disabled)

				if err != nil {
					if _, ok := status.PodState[defaults.RelayDeploymentName]; !ok {
						status.AddAggregatedWarning(defaults.RelayDeploymentName, defaults.RelayDeploymentName, fmt.Errorf("hubble relay is not deployed"))
					} else {
						status.AddAggregatedError(defaults.RelayDeploymentName, defaults.RelayDeploymentName, err)
						status.CollectionError(err)
					}
				}

				// pod status for relay is only validated if the deployment exists
				if _, ok := status.PodState[defaults.RelayDeploymentName]; ok {
					err = k.podStatus(ctx, status, defaults.RelayDeploymentName, "k8s-app=hubble-relay", nil)
					if err != nil {
						status.mutex.Lock()
						defer status.mutex.Unlock()
						status.CollectionError(err)
					}
				}

				return nil
			},
		},
		{
			name: defaults.HubbleUIDeploymentName,
			task: func(_ context.Context) error {
				disabled, err := k.deploymentStatus(ctx, status, defaults.HubbleUIDeploymentName)
				status.mutex.Lock()
				defer status.mutex.Unlock()

				status.SetDisabled(defaults.HubbleUIDeploymentName, defaults.HubbleUIDeploymentName, disabled)

				if err != nil {
					if _, ok := status.PodState[defaults.HubbleUIDeploymentName]; !ok {
						status.AddAggregatedWarning(defaults.HubbleUIDeploymentName, defaults.HubbleUIDeploymentName, fmt.Errorf("hubble ui is not deployed"))
					} else {
						status.AddAggregatedError(defaults.HubbleUIDeploymentName, defaults.HubbleUIDeploymentName, err)
						status.CollectionError(err)
					}
				}

				// pod status for UI is only validated if the deployment exists
				if _, ok := status.PodState[defaults.HubbleUIDeploymentName]; ok {
					err = k.podStatus(ctx, status, defaults.HubbleUIDeploymentName, "k8s-app=hubble-ui", nil)
					if err != nil {
						status.mutex.Lock()
						defer status.mutex.Unlock()
						status.CollectionError(err)
					}
				}

				return nil
			},
		},
		{
			name: defaults.ClusterMeshDeploymentName,
			task: func(_ context.Context) error {
				disabled, err := k.deploymentStatus(ctx, status, defaults.ClusterMeshDeploymentName)
				status.mutex.Lock()
				defer status.mutex.Unlock()

				status.SetDisabled(defaults.ClusterMeshDeploymentName, defaults.ClusterMeshDeploymentName, disabled)
				if err != nil {
					if _, ok := status.PodState[defaults.ClusterMeshDeploymentName]; !ok {
						status.AddAggregatedWarning(defaults.ClusterMeshDeploymentName, defaults.ClusterMeshDeploymentName, fmt.Errorf("clustermesh is not deployed"))
					} else {
						status.AddAggregatedError(defaults.ClusterMeshDeploymentName, defaults.ClusterMeshDeploymentName, err)
						status.CollectionError(err)
					}
				}

				// pod status for relay is only validated if the deployment exists
				if _, ok := status.PodState[defaults.ClusterMeshDeploymentName]; ok {
					err = k.podStatus(ctx, status, defaults.ClusterMeshDeploymentName, "k8s-app=clustermesh-apiserver", nil)
					if err != nil {
						status.mutex.Lock()
						defer status.mutex.Unlock()
						status.CollectionError(err)
					}
				}

				return nil
			},
		},
		{
			name: defaults.HubbleUIDeploymentName,
			task: func(_ context.Context) error {
				err := k.podCount(ctx, status)
				if err != nil {
					status.mutex.Lock()
					defer status.mutex.Unlock()

					status.CollectionError(err)
				}

				return nil
			},
		},
	}

	if utils.IsInHelmMode() {
		tasks = append(tasks, statusTask{
			name: "Helm chart version",
			task: func(_ context.Context) error {
				client, ok := k.client.(*k8s.Client)
				if !ok {
					return fmt.Errorf("failed to initialize Helm client")
				}
				release, err := helm.Get(client.HelmActionConfig, helm.GetParameters{
					Namespace: k.params.Namespace,
					Name:      defaults.HelmReleaseName,
				})
				if err != nil {
					return err
				}
				status.HelmChartVersion = release.Chart.Metadata.Version
				return nil
			}})
	}

	// for the sake of sanity, don't get pod logs more than once
	var agentLogsOnce = sync.Once{}
	err := k.podStatus(ctx, status, defaults.AgentDaemonSetName, defaults.AgentPodSelector, func(ctx context.Context, status *Status, name string, pod *corev1.Pod) {
		if pod.Status.Phase == corev1.PodRunning {
			// extract container status
			var containerStatus *corev1.ContainerStatus
			for i, cStatus := range pod.Status.ContainerStatuses {
				if cStatus.Name == defaults.AgentContainerName {
					containerStatus = &pod.Status.ContainerStatuses[i]
					break
				}
			}
			tasks = append(tasks, statusTask{
				name: pod.Name,
				task: func(ctx context.Context) error {
					var s *models.StatusResponse
					var err error

					if containerStatus != nil && containerStatus.State.Running != nil {
						// if container is running, execute "cilium status" in the container and parse the result
						s, err = k.client.CiliumStatus(ctx, k.params.Namespace, pod.Name)
					} else {
						// otherwise, generate a useful status message
						desc := "is not running"
						lastLog := fmt.Sprintf("try 'kubectl -n %s logs -c %s %s'",
							pod.Namespace, defaults.AgentContainerName, pod.Name)

						// determine CrashLoopBackOff status and get last log line, if available.
						if containerStatus != nil {
							if containerStatus.State.Waiting != nil && containerStatus.State.Waiting.Reason == "CrashLoopBackOff" {
								desc = "is in CrashLoopBackOff"
							}
							if containerStatus.LastTerminationState.Terminated != nil {
								terminated := containerStatus.LastTerminationState.Terminated
								desc = fmt.Sprintf("%s, exited with code %d", desc, terminated.ExitCode)

								// capture final log line, maybe it's useful
								// either from container message or a separate logs request
								dyingGasp := ""
								if terminated.Message != "" {
									dyingGasp = strings.TrimSpace(terminated.Message)
								} else {
									agentLogsOnce.Do(func() { // in a sync.Once so we don't waste time retrieving lots of logs
										logs, err := k.client.CiliumLogs(ctx, pod.Namespace, pod.Name, terminated.FinishedAt.Time.Add(-2*time.Minute), nil)
										if err == nil && logs != "" {
											dyingGasp = strings.TrimSpace(logs)
										}
									})
								}

								// Only output the last line
								if dyingGasp != "" {
									lines := strings.Split(dyingGasp, "\n")
									lastLog = lines[len(lines)-1]
								}
							}
						}
						err = fmt.Errorf("container %s %s: %s", defaults.AgentContainerName, desc, lastLog)
					}

					status.mutex.Lock()
					defer status.mutex.Unlock()

					status.parseStatusResponse(defaults.AgentDaemonSetName, pod.Name, s, err)
					status.CiliumStatus[pod.Name] = s

					return nil
				},
			})
		}
	})

	if err != nil {
		status.CollectionError(err)
	}

	wc := k.params.WorkerCount
	if wc < 1 {
		wc = DefaultWorkerCount
	}

	wp := workerpool.New(wc)
	for _, task := range tasks {
		if err := wp.Submit(task.name, task.task); err != nil {
			status.CollectionError(err)
		}
	}

	_, err = wp.Drain()
	if err != nil {
		status.CollectionError(err)
	}

	if err := wp.Close(); err != nil {
		status.CollectionError(err)
	}

	return status
}
