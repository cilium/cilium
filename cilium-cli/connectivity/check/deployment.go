// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

package check

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/k8s"
)

const (
	PerfClientName = "PerfClient"
	PerfServerName = "PerfServer"

	PerfClientDeploymentName       = "perf-client"
	PerfClientAcrossDeploymentName = "perf-client-other-node"
	PerfServerDeploymentName       = "perf-server"

	PerfHostNetNamingSuffix = "-host-net"

	ClientDeploymentName  = "client"
	Client2DeploymentName = "client2"

	echoSameNodeDeploymentName  = "echo-same-node"
	echoOtherNodeDeploymentName = "echo-other-node"
	kindEchoName                = "echo"
	kindClientName              = "client"
	kindPerfName                = "perf"
)

// perfDeploymentNameManager provides methods for building deployment names
// based on the given parameters.
// Names returned by the methods will be unique depending on how the deployments
// are expected to be modified for the configured test.
type perfDeploymentNameManager struct {
	clientDeploymentName       string
	clientAcrossDeploymentName string
	serverDeploymentName       string
}

func (nm *perfDeploymentNameManager) ClientName() string {
	return nm.clientDeploymentName
}

func (nm *perfDeploymentNameManager) ClientAcrossName() string {
	return nm.clientAcrossDeploymentName
}

func (nm *perfDeploymentNameManager) ServerName() string {
	return nm.serverDeploymentName
}

func newPerfDeploymentNameManager(params *Parameters) *perfDeploymentNameManager {

	suffix := ""
	if params.PerfHostNet {
		suffix = PerfHostNetNamingSuffix
	}

	return &perfDeploymentNameManager{
		clientDeploymentName:       PerfClientDeploymentName + suffix,
		clientAcrossDeploymentName: PerfClientAcrossDeploymentName + suffix,
		serverDeploymentName:       PerfServerDeploymentName + suffix,
	}
}

type deploymentParameters struct {
	Name           string
	Kind           string
	Image          string
	Replicas       int
	Port           int
	Command        []string
	Affinity       *corev1.Affinity
	ReadinessProbe *corev1.Probe
	Labels         map[string]string
	HostNetwork    bool
}

func newDeployment(p deploymentParameters) *appsv1.Deployment {
	if p.Replicas == 0 {
		p.Replicas = 1
	}
	replicas32 := int32(p.Replicas)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: p.Name,
			Labels: map[string]string{
				"name": p.Name,
				"kind": p.Kind,
			},
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Name: p.Name,
					Labels: map[string]string{
						"name": p.Name,
						"kind": p.Kind,
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name: p.Name,
							Env: []corev1.EnvVar{
								{Name: "PORT", Value: fmt.Sprintf("%d", p.Port)},
							},
							Ports: []corev1.ContainerPort{
								{ContainerPort: int32(p.Port)},
							},
							Image:           p.Image,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Command:         p.Command,
							ReadinessProbe:  p.ReadinessProbe,
							SecurityContext: &corev1.SecurityContext{
								Capabilities: &corev1.Capabilities{
									Add: []corev1.Capability{"NET_RAW"},
								},
							},
						},
					},
					Affinity:    p.Affinity,
					HostNetwork: p.HostNetwork,
				},
			},
			Replicas: &replicas32,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"name": p.Name,
					"kind": p.Kind,
				},
			},
		},
	}

	for k, v := range p.Labels {
		dep.Spec.Template.ObjectMeta.Labels[k] = v
	}

	return dep
}

var serviceLabels = map[string]string{
	"kind": kindEchoName,
}

func newService(name string, selector map[string]string, labels map[string]string, portName string, port int) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeNodePort,
			Ports: []corev1.ServicePort{
				{Name: portName, Port: int32(port)},
			},
			Selector: selector,
		},
	}
}

func newLocalReadinessProbe(port int, path string) *corev1.Probe {
	return &corev1.Probe{
		ProbeHandler: corev1.ProbeHandler{
			HTTPGet: &corev1.HTTPGetAction{
				Path:   path,
				Port:   intstr.FromInt(port),
				Scheme: corev1.URISchemeHTTP,
			},
		},
		TimeoutSeconds:      int32(2),
		SuccessThreshold:    int32(1),
		PeriodSeconds:       int32(1),
		InitialDelaySeconds: int32(1),
		FailureThreshold:    int32(3),
	}
}

// deploy ensures the test Namespace, Services and Deployments are running on the cluster.
func (ct *ConnectivityTest) deploy(ctx context.Context) error {
	if ct.params.ForceDeploy {
		if err := ct.deleteDeployments(ctx, ct.clients.src); err != nil {
			return err
		}
	}

	_, err := ct.clients.src.GetNamespace(ctx, ct.params.TestNamespace, metav1.GetOptions{})
	if err != nil {
		ct.Logf("✨ [%s] Creating namespace for connectivity check...", ct.clients.src.ClusterName())
		_, err = ct.clients.src.CreateNamespace(ctx, ct.params.TestNamespace, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create namespace %s: %s", ct.params.TestNamespace, err)
		}
	}

	if ct.params.MultiCluster != "" {
		if ct.params.ForceDeploy {
			if err := ct.deleteDeployments(ctx, ct.clients.dst); err != nil {
				return err
			}
		}

		_, err = ct.clients.dst.GetNamespace(ctx, ct.params.TestNamespace, metav1.GetOptions{})
		if err != nil {
			ct.Logf("✨ [%s] Creating namespace for connectivity check...", ct.clients.dst.ClusterName())
			_, err = ct.clients.dst.CreateNamespace(ctx, ct.params.TestNamespace, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create namespace %s: %s", ct.params.TestNamespace, err)
			}
		}
	}

	_, err = ct.clients.src.GetService(ctx, ct.params.TestNamespace, echoSameNodeDeploymentName, metav1.GetOptions{})
	if err != nil {
		ct.Logf("✨ [%s] Deploying echo-same-node service...", ct.clients.src.ClusterName())
		svc := newService(echoSameNodeDeploymentName, map[string]string{"name": echoSameNodeDeploymentName}, serviceLabels, "http", 8080)
		_, err = ct.clients.src.CreateService(ctx, ct.params.TestNamespace, svc, metav1.CreateOptions{})
		if err != nil {
			return err
		}
	}

	if ct.params.MultiCluster != "" {
		_, err = ct.clients.src.GetService(ctx, ct.params.TestNamespace, echoOtherNodeDeploymentName, metav1.GetOptions{})
		if err != nil {
			ct.Logf("✨ [%s] Deploying echo-other-node service...", ct.clients.src.ClusterName())
			svc := newService(echoOtherNodeDeploymentName, map[string]string{"name": echoOtherNodeDeploymentName}, serviceLabels, "http", 8080)
			svc.ObjectMeta.Annotations = map[string]string{}
			svc.ObjectMeta.Annotations["io.cilium/global-service"] = "true"

			_, err = ct.clients.src.CreateService(ctx, ct.params.TestNamespace, svc, metav1.CreateOptions{})
			if err != nil {
				return err
			}
		}
	}

	_, err = ct.clients.src.GetDeployment(ctx, ct.params.TestNamespace, echoSameNodeDeploymentName, metav1.GetOptions{})
	if err != nil {
		ct.Logf("✨ [%s] Deploying same-node deployment...", ct.clients.src.ClusterName())
		echoDeployment := newDeployment(deploymentParameters{
			Name:   echoSameNodeDeploymentName,
			Kind:   kindEchoName,
			Port:   8080,
			Image:  defaults.ConnectivityCheckJSONMockImage,
			Labels: map[string]string{"other": "echo"},
			Affinity: &corev1.Affinity{
				PodAffinity: &corev1.PodAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
						{
							LabelSelector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{Key: "name", Operator: metav1.LabelSelectorOpIn, Values: []string{ClientDeploymentName}},
								},
							},
							TopologyKey: "kubernetes.io/hostname",
						},
					},
				},
			},
			ReadinessProbe: newLocalReadinessProbe(8080, "/"),
		})

		_, err = ct.clients.src.CreateDeployment(ctx, ct.params.TestNamespace, echoDeployment, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create deployment %s: %s", echoSameNodeDeploymentName, err)
		}
	}

	if ct.params.Perf {
		// For performance workloads, we want to ensure the client/server are in the same zone
		// If a zone has > 1 node, use that zone
		zones := map[string]int{}
		zone := ""
		lz := ""
		n, hasNodes := ct.client.ListNodes(ctx, metav1.ListOptions{})
		if hasNodes != nil {
			return fmt.Errorf("unable to query nodes")
		}
		for _, l := range n.Items {
			if _, ok := zones[l.GetLabels()["topology.kubernetes.io/zone"]]; ok {
				zone = l.GetLabels()["topology.kubernetes.io/zone"]
				break
			} else {
				zones[l.GetLabels()["topology.kubernetes.io/zone"]] = 1
				lz = l.GetLabels()["topology.kubernetes.io/zone"]
			}
		}
		// No zone had > 1, use the last zone.
		if zone == "" {
			ct.Warn("Each zone only has a single node - could impact the performance test results")
			zone = lz
		}

		if ct.params.PerfHostNet {
			ct.Info("Deploying Perf deployments using host networking")
		}

		nm := newPerfDeploymentNameManager(&ct.params)

		// Need to capture the IP of the Server Deployment, and pass to the client to execute benchmark
		_, err = ct.clients.src.GetDeployment(ctx, ct.params.TestNamespace, nm.ClientName(), metav1.GetOptions{})
		if err != nil {
			ct.Logf("✨ [%s] Deploying Perf Client deployment...", ct.clients.src.ClusterName())
			perfClientDeployment := newDeployment(deploymentParameters{
				Name:  nm.ClientName(),
				Kind:  kindPerfName,
				Port:  80,
				Image: defaults.ConnectivityPerformanceImage,
				Labels: map[string]string{
					"client": "role",
				},
				Command: []string{"/bin/bash", "-c", "sleep 10000000"},
				Affinity: &corev1.Affinity{
					NodeAffinity: &corev1.NodeAffinity{
						PreferredDuringSchedulingIgnoredDuringExecution: []corev1.PreferredSchedulingTerm{
							{
								Weight: 100,
								Preference: corev1.NodeSelectorTerm{
									MatchExpressions: []corev1.NodeSelectorRequirement{
										{Key: "topology.kubernetes.io/zone", Operator: corev1.NodeSelectorOpIn, Values: []string{zone}},
									},
								},
							},
						},
					},
				},
				HostNetwork: ct.params.PerfHostNet,
			})
			_, err = ct.clients.src.CreateDeployment(ctx, ct.params.TestNamespace, perfClientDeployment, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create deployment %s: %w", perfClientDeployment, err)
			}
		}

		_, err = ct.clients.src.GetDeployment(ctx, ct.params.TestNamespace, nm.ServerName(), metav1.GetOptions{})
		if err != nil {
			ct.Logf("✨ [%s] Deploying Perf Server deployment...", ct.clients.src.ClusterName())
			perfServerDeployment := newDeployment(deploymentParameters{
				Name: nm.ServerName(),
				Kind: kindPerfName,
				Labels: map[string]string{
					"server": "role",
				},
				Port:    5001,
				Image:   defaults.ConnectivityPerformanceImage,
				Command: []string{"/bin/bash", "-c", "netserver;sleep 10000000"},
				Affinity: &corev1.Affinity{
					NodeAffinity: &corev1.NodeAffinity{
						PreferredDuringSchedulingIgnoredDuringExecution: []corev1.PreferredSchedulingTerm{
							{
								Weight: 100,
								Preference: corev1.NodeSelectorTerm{
									MatchExpressions: []corev1.NodeSelectorRequirement{
										{Key: "topology.kubernetes.io/zone", Operator: corev1.NodeSelectorOpIn, Values: []string{zone}},
									},
								},
							},
						},
					},
					PodAffinity: &corev1.PodAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
							{
								LabelSelector: &metav1.LabelSelector{
									MatchExpressions: []metav1.LabelSelectorRequirement{
										{Key: "name", Operator: metav1.LabelSelectorOpIn, Values: []string{nm.ClientName()}},
									},
								},
								TopologyKey: "kubernetes.io/hostname",
							},
						},
					},
				},
				HostNetwork: ct.params.PerfHostNet,
			})
			_, err = ct.clients.src.CreateDeployment(ctx, ct.params.TestNamespace, perfServerDeployment, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create deployment %s: %w", perfServerDeployment, err)
			}
		}

		// Deploy second client on a different node
		if !ct.params.SingleNode {
			_, err := ct.clients.src.GetDeployment(ctx, ct.params.TestNamespace, nm.ClientAcrossName(), metav1.GetOptions{})
			if err != nil {
				ct.Logf("✨ [%s] Deploying Perf Client deployment...", ct.clients.src.ClusterName())
				perfClientDeployment := newDeployment(deploymentParameters{
					Name: nm.ClientAcrossName(),
					Kind: kindPerfName,
					Port: 5001,
					Labels: map[string]string{
						"client": "role",
					},
					Image:   defaults.ConnectivityPerformanceImage,
					Command: []string{"/bin/bash", "-c", "sleep 10000000"},
					Affinity: &corev1.Affinity{
						NodeAffinity: &corev1.NodeAffinity{
							PreferredDuringSchedulingIgnoredDuringExecution: []corev1.PreferredSchedulingTerm{
								{
									Weight: 100,
									Preference: corev1.NodeSelectorTerm{
										MatchExpressions: []corev1.NodeSelectorRequirement{
											{Key: "topology.kubernetes.io/zone", Operator: corev1.NodeSelectorOpIn, Values: []string{zone}},
										},
									},
								},
							},
						},
						PodAntiAffinity: &corev1.PodAntiAffinity{
							PreferredDuringSchedulingIgnoredDuringExecution: []corev1.WeightedPodAffinityTerm{
								{Weight: 100, PodAffinityTerm: corev1.PodAffinityTerm{
									LabelSelector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
										{Key: "name", Operator: metav1.LabelSelectorOpIn, Values: []string{nm.ClientName()}}}},
									TopologyKey: "kubernetes.io/hostname"}}}},
					},
					HostNetwork: ct.params.PerfHostNet,
				})
				_, err = ct.clients.src.CreateDeployment(ctx, ct.params.TestNamespace, perfClientDeployment, metav1.CreateOptions{})
				if err != nil {
					return fmt.Errorf("unable to create deployment %s: %s", perfClientDeployment, err)
				}
			}
		}
	}
	_, err = ct.clients.src.GetDeployment(ctx, ct.params.TestNamespace, ClientDeploymentName, metav1.GetOptions{})
	if err != nil {
		ct.Logf("✨ [%s] Deploying client deployment...", ct.clients.src.ClusterName())
		clientDeployment := newDeployment(deploymentParameters{
			Name:    ClientDeploymentName,
			Kind:    kindClientName,
			Port:    8080,
			Image:   defaults.ConnectivityCheckAlpineCurlImage,
			Command: []string{"/bin/ash", "-c", "sleep 10000000"},
		})
		_, err = ct.clients.src.CreateDeployment(ctx, ct.params.TestNamespace, clientDeployment, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create deployment %s: %s", ClientDeploymentName, err)
		}
	}

	// 2nd client with label other=client
	_, err = ct.clients.src.GetDeployment(ctx, ct.params.TestNamespace, Client2DeploymentName, metav1.GetOptions{})
	if err != nil {
		ct.Logf("✨ [%s] Deploying client2 deployment...", ct.clients.src.ClusterName())
		clientDeployment := newDeployment(deploymentParameters{
			Name:    Client2DeploymentName,
			Kind:    kindClientName,
			Port:    8080,
			Image:   defaults.ConnectivityCheckAlpineCurlImage,
			Command: []string{"/bin/ash", "-c", "sleep 10000000"},
			Labels:  map[string]string{"other": "client"},
			Affinity: &corev1.Affinity{
				PodAffinity: &corev1.PodAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
						{
							LabelSelector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{Key: "name", Operator: metav1.LabelSelectorOpIn, Values: []string{ClientDeploymentName}},
								},
							},
							TopologyKey: "kubernetes.io/hostname",
						},
					},
				},
			},
		})
		_, err = ct.clients.src.CreateDeployment(ctx, ct.params.TestNamespace, clientDeployment, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create deployment %s: %s", Client2DeploymentName, err)
		}
	}

	if !ct.params.SingleNode || ct.params.MultiCluster != "" {
		_, err = ct.clients.dst.GetService(ctx, ct.params.TestNamespace, echoOtherNodeDeploymentName, metav1.GetOptions{})
		if err != nil {
			ct.Logf("✨ [%s] Deploying echo-other-node service...", ct.clients.dst.ClusterName())
			svc := newService(echoOtherNodeDeploymentName, map[string]string{"name": echoOtherNodeDeploymentName}, serviceLabels, "http", 8080)

			if ct.params.MultiCluster != "" {
				svc.ObjectMeta.Annotations = map[string]string{}
				svc.ObjectMeta.Annotations["io.cilium/global-service"] = "true"
			}

			_, err = ct.clients.dst.CreateService(ctx, ct.params.TestNamespace, svc, metav1.CreateOptions{})
			if err != nil {
				return err
			}
		}

		_, err = ct.clients.dst.GetDeployment(ctx, ct.params.TestNamespace, echoOtherNodeDeploymentName, metav1.GetOptions{})
		if err != nil {
			ct.Logf("✨ [%s] Deploying other-node deployment...", ct.clients.dst.ClusterName())
			echoOtherNodeDeployment := newDeployment(deploymentParameters{
				Name:  echoOtherNodeDeploymentName,
				Kind:  kindEchoName,
				Port:  8080,
				Image: defaults.ConnectivityCheckJSONMockImage,
				Affinity: &corev1.Affinity{
					PodAntiAffinity: &corev1.PodAntiAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
							{
								LabelSelector: &metav1.LabelSelector{
									MatchExpressions: []metav1.LabelSelectorRequirement{
										{Key: "name", Operator: metav1.LabelSelectorOpIn, Values: []string{ClientDeploymentName}},
									},
								},
								TopologyKey: "kubernetes.io/hostname",
							},
						},
					},
				},
				ReadinessProbe: newLocalReadinessProbe(8080, "/"),
			})

			_, err = ct.clients.dst.CreateDeployment(ctx, ct.params.TestNamespace, echoOtherNodeDeployment, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create deployment %s: %w", echoOtherNodeDeploymentName, err)
			}
		}
	}

	return nil
}

// deploymentList returns 2 lists of Deployments to be used for running tests with.
func (ct *ConnectivityTest) deploymentList() (srcList []string, dstList []string) {
	if !ct.params.Perf {
		srcList = []string{ClientDeploymentName, Client2DeploymentName, echoSameNodeDeploymentName}
	} else {
		perfDeploymentNameManager := newPerfDeploymentNameManager(&ct.params)
		srcList = []string{perfDeploymentNameManager.ClientName()}
		dstList = append(dstList, perfDeploymentNameManager.ServerName())
	}

	if (ct.params.MultiCluster != "" || !ct.params.SingleNode) && !ct.params.Perf {
		dstList = append(dstList, echoOtherNodeDeploymentName)
	}

	return srcList, dstList
}

func (ct *ConnectivityTest) deleteDeployments(ctx context.Context, client *k8s.Client) error {
	ct.Logf("🔥 [%s] Deleting connectivity check deployments...", client.ClusterName())
	_ = client.DeleteDeployment(ctx, ct.params.TestNamespace, echoSameNodeDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteDeployment(ctx, ct.params.TestNamespace, echoOtherNodeDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteDeployment(ctx, ct.params.TestNamespace, ClientDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteDeployment(ctx, ct.params.TestNamespace, Client2DeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteService(ctx, ct.params.TestNamespace, echoSameNodeDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteService(ctx, ct.params.TestNamespace, echoOtherNodeDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteNamespace(ctx, ct.params.TestNamespace, metav1.DeleteOptions{})

	_, err := client.GetNamespace(ctx, ct.params.TestNamespace, metav1.GetOptions{})
	if err == nil {
		ct.Logf("⌛ [%s] Waiting for namespace %s to disappear", client.ClusterName(), ct.params.TestNamespace)
		for err == nil {
			time.Sleep(time.Second)
			_, err = client.GetNamespace(ctx, ct.params.TestNamespace, metav1.GetOptions{})
		}
	}

	return nil
}

// validateDeployment checks if the Deployments we created have the expected Pods in them.
func (ct *ConnectivityTest) validateDeployment(ctx context.Context) error {

	ct.Debug("Validating Deployments...")

	srcDeployments, dstDeployments := ct.deploymentList()
	if err := ct.waitForDeployments(ctx, ct.clients.src, srcDeployments); err != nil {
		return err
	}
	if err := ct.waitForDeployments(ctx, ct.clients.dst, dstDeployments); err != nil {
		return err
	}

	for _, client := range ct.clients.clients() {
		ciliumPods, err := client.ListPods(ctx, ct.params.CiliumNamespace, metav1.ListOptions{LabelSelector: "k8s-app=cilium"})
		if err != nil {
			return fmt.Errorf("unable to list Cilium pods: %w", err)
		}
		for _, ciliumPod := range ciliumPods.Items {
			// TODO: Can Cilium pod names collide across clusters?
			ct.ciliumPods[ciliumPod.Name] = Pod{
				K8sClient: client,
				Pod:       ciliumPod.DeepCopy(),
			}
		}
	}

	clientPods, err := ct.client.ListPods(ctx, ct.params.TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + kindClientName})
	if err != nil {
		return fmt.Errorf("unable to list client pods: %s", err)
	}

	for _, pod := range clientPods.Items {
		ctx, cancel := context.WithTimeout(ctx, ct.params.ciliumEndpointTimeout())
		defer cancel()
		if err := ct.waitForCiliumEndpoint(ctx, ct.clients.src, ct.params.TestNamespace, pod.Name); err != nil {
			return err
		}

		ct.clientPods[pod.Name] = Pod{
			K8sClient: ct.client,
			Pod:       pod.DeepCopy(),
		}
	}

	// Set the timeout for all DNS lookup retries
	dnsCtx, cancel := context.WithTimeout(ctx, ct.params.ipCacheTimeout())
	defer cancel()
	for _, cp := range ct.clientPods {
		err := ct.waitForDNS(dnsCtx, cp)
		if err != nil {
			return err
		}
	}

	perfPods, err := ct.client.ListPods(ctx, ct.params.TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + kindPerfName})
	if err != nil {
		return fmt.Errorf("unable to list perf pods: %w", err)
	}
	for _, perfPod := range perfPods.Items {
		// Filter out existing perf pods in cilium-test based on scenario
		if ct.params.PerfHostNet != perfPod.Spec.HostNetwork {
			continue
		}

		// Individual endpoints will not be created for pods using node's network stack
		if !ct.params.PerfHostNet {
			ctx, cancel := context.WithTimeout(ctx, ct.params.ciliumEndpointTimeout())
			defer cancel()
			if err := ct.waitForCiliumEndpoint(ctx, ct.clients.src, ct.params.TestNamespace, perfPod.Name); err != nil {
				return err
			}
		}
		_, hasLabel := perfPod.GetLabels()["server"]
		if hasLabel {
			ct.perfServerPod[perfPod.Name] = Pod{
				K8sClient: ct.client,
				Pod:       perfPod.DeepCopy(),
				port:      5201,
			}
		} else {
			ct.perfClientPods[perfPod.Name] = Pod{
				K8sClient: ct.client,
				Pod:       perfPod.DeepCopy(),
			}
		}
	}

	for _, client := range ct.clients.clients() {
		echoPods, err := client.ListPods(ctx, ct.params.TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + kindEchoName})
		if err != nil {
			return fmt.Errorf("unable to list echo pods: %w", err)
		}
		for _, echoPod := range echoPods.Items {
			ctx, cancel := context.WithTimeout(ctx, ct.params.ciliumEndpointTimeout())
			defer cancel()
			if err := ct.waitForCiliumEndpoint(ctx, client, ct.params.TestNamespace, echoPod.Name); err != nil {
				return err
			}

			ct.echoPods[echoPod.Name] = Pod{
				K8sClient: client,
				Pod:       echoPod.DeepCopy(),
				scheme:    "http",
				port:      8080, // listen port of the echo server inside the container
			}
		}
	}

	for _, client := range ct.clients.clients() {
		echoServices, err := client.ListServices(ctx, ct.params.TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + kindEchoName})
		if err != nil {
			return fmt.Errorf("unable to list echo services: %w", err)
		}

		for _, echoService := range echoServices.Items {
			if ct.params.MultiCluster != "" {
				if _, exists := ct.echoServices[echoService.Name]; exists {
					// ct.clients.clients() lists the client cluster first.
					// If we already have this service (for the client cluster), keep it
					// so that we can rely on the service's ClusterIP being valid for the
					// client pods.
					continue
				}
			}

			ct.echoServices[echoService.Name] = Service{
				Service: echoService.DeepCopy(),
			}
		}
	}

	for _, s := range ct.echoServices {
		if err := ct.waitForService(ctx, s); err != nil {
			return err
		}
	}

	if ct.params.MultiCluster == "" {
		for _, ciliumPod := range ct.ciliumPods {
			hostIP := ciliumPod.Pod.Status.HostIP
			for _, s := range ct.echoServices {
				if err := ct.waitForNodePorts(ctx, hostIP, s); err != nil {
					return err
				}
			}
		}
	}

	var logOnce sync.Once
	for _, client := range ct.clients.clients() {
		externalWorkloads, err := client.ListCiliumExternalWorkloads(ctx, metav1.ListOptions{})
		if k8sErrors.IsNotFound(err) {
			logOnce.Do(func() {
				ct.Log("ciliumexternalworkloads.cilium.io is not defined. Disabling external workload tests")
			})
			continue
		} else if err != nil {
			return fmt.Errorf("unable to list external workloads: %w", err)
		}
		for _, externalWorkload := range externalWorkloads.Items {
			ct.externalWorkloads[externalWorkload.Name] = ExternalWorkload{
				workload: externalWorkload.DeepCopy(),
			}
		}
	}

	// TODO: unconditionally re-enable the IPCache check once
	// https://github.com/cilium/cilium-cli/issues/361 is resolved.
	if ct.params.SkipIPCacheCheck {
		ct.Infof("Skipping IPCache check")
	} else {
		// Set the timeout for all IP cache lookup retries
		ipCacheCtx, cancel := context.WithTimeout(ctx, ct.params.ipCacheTimeout())
		defer cancel()
		for _, cp := range ct.ciliumPods {
			err := ct.waitForIPCache(ipCacheCtx, cp)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// Validate that kube-dns responds and knows about cluster services
func (ct *ConnectivityTest) waitForDNS(ctx context.Context, pod Pod) error {
	ct.Logf("⌛ [%s] Waiting for pod %s to reach default/kubernetes service...", ct.client.ClusterName(), pod.Name())

	for {
		// Don't retry lookups more often than once per second.
		r := time.After(time.Second)

		target := "kubernetes.default"
		stdout, err := pod.K8sClient.ExecInPodWithTTY(ctx, pod.Pod.Namespace, pod.Pod.Name,
			"", []string{"nslookup", target})
		if err == nil {
			return nil
		}

		ct.Debugf("Error looking up %s from pod %s: %s: %s", target, pod.Name(), err, stdout.String())

		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout reached waiting lookup for %s from pod %s to succeed", target, pod.Name())
		default:
		}

		// Wait for the pace timer to avoid busy polling.
		<-r
	}
}

func (ct *ConnectivityTest) waitForIPCache(ctx context.Context, pod Pod) error {
	ct.Logf("⌛ [%s] Waiting for Cilium pod %s to have all the pod IPs in eBPF ipcache...", ct.client.ClusterName(), pod.Name())

	for {
		// Don't retry lookups more often than once per second.
		r := time.After(time.Second)

		stdout, err := pod.K8sClient.ExecInPodWithTTY(ctx, pod.Pod.Namespace, pod.Pod.Name,
			defaults.AgentContainerName, []string{"cilium", "bpf", "ipcache", "list", "-o", "json"})
		if err == nil {
			var ic ipCache

			if err := json.Unmarshal(stdout.Bytes(), &ic); err != nil {
				return fmt.Errorf("unmarshaling Cilium stdout json: %w", err)
			}

			for _, client := range ct.clientPods {
				if _, err := ic.findPodID(client); err != nil {
					ct.Debugf("Couldn't find client Pod %v in ipcache (%s), retrying...", client, err)
					goto retry
				}
			}

			for _, echo := range ct.echoPods {
				if _, err := ic.findPodID(echo); err != nil {
					ct.Debugf("Couldn't find echo Pod %v in ipcache (%s), retrying...", echo, err)
					goto retry
				}
			}

			return nil
		}

		ct.Debugf("Error listing ipcache for Cilium pod %s: %s: %s", pod.Name(), err, stdout.String())

	retry:
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout reached waiting for pod IDs in ipcache of Cilium pod %s", pod.Name())
		default:
		}

		// Wait for the pace timer to avoid busy polling.
		<-r
	}
}

func (ct *ConnectivityTest) waitForDeployments(ctx context.Context, client *k8s.Client, deployments []string) error {
	ct.Logf("⌛ [%s] Waiting for deployments %s to become ready...", client.ClusterName(), deployments)

	ctx, cancel := context.WithTimeout(ctx, ct.params.podReadyTimeout())
	defer cancel()
	for _, name := range deployments {
		for client.CheckDeploymentStatus(ctx, ct.params.TestNamespace, name) != nil {
			select {
			case <-time.After(time.Second):
			case <-ctx.Done():
				return fmt.Errorf("waiting for deployment %s to become ready has been interrupted: %w", name, ctx.Err())
			}
		}
	}

	return nil
}

func (ct *ConnectivityTest) waitForService(ctx context.Context, service Service) error {
	ct.Logf("⌛ [%s] Waiting for Service %s to become ready...", ct.client.ClusterName(), service.Name())

	// Retry the service lookup for the duration of the ready context.
	ctx, cancel := context.WithTimeout(ctx, ct.params.serviceReadyTimeout())
	defer cancel()

	pod := ct.RandomClientPod()
	if pod == nil {
		return fmt.Errorf("no client pod available")
	}

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout reached waiting for %s", service)
		default:
		}

		// Don't retry lookups more often than once per second.
		r := time.After(time.Second)

		stdout, err := ct.client.ExecInPodWithTTY(ctx,
			pod.Pod.Namespace, pod.Pod.Name, pod.Pod.Labels["name"],
			[]string{"nslookup", service.Service.Name}) // BusyBox nslookup doesn't support any arguments.

		// Lookup successful.
		if err == nil {
			svcIP := ""
			switch service.Service.Spec.Type {
			case corev1.ServiceTypeClusterIP, corev1.ServiceTypeNodePort:
				svcIP = service.Service.Spec.ClusterIP
			case corev1.ServiceTypeLoadBalancer:
				if len(service.Service.Status.LoadBalancer.Ingress) > 0 {
					svcIP = service.Service.Status.LoadBalancer.Ingress[0].IP
				}
			}
			if svcIP == "" {
				return nil
			}

			nslookupStr := strings.ReplaceAll(stdout.String(), "\r\n", "\n")
			if strings.Contains(nslookupStr, "Address: "+svcIP+"\n") {
				return nil
			}
			err = fmt.Errorf("Service IP %q not found in nslookup output %q", svcIP, nslookupStr)
		}

		ct.Debugf("Error waiting for service %s: %s: %s", service.Name(), err, stdout.String())

		// Wait for the pace timer to avoid busy polling.
		<-r
	}
}

// waitForNodePorts waits until all the nodeports in a service are available on a given node.
func (ct *ConnectivityTest) waitForNodePorts(ctx context.Context, nodeIP string, service Service) error {
	pod := ct.RandomClientPod()
	if pod == nil {
		return fmt.Errorf("no client pod available")
	}
	ctx, cancel := context.WithTimeout(ctx, ct.params.serviceReadyTimeout())
	defer cancel()

	for _, port := range service.Service.Spec.Ports {
		nodePort := port.NodePort
		if nodePort == 0 {
			continue
		}
		ct.Logf("⌛ [%s] Waiting for NodePort %s:%d (%s) to become ready...",
			ct.client.ClusterName(), nodeIP, nodePort, service.Name())
		for {
			e, err := ct.client.ExecInPodWithTTY(ctx,
				pod.Pod.Namespace, pod.Pod.Name, pod.Pod.Labels["name"],
				[]string{"nc", "-w", "3", "-z", nodeIP, strconv.Itoa(int(nodePort))})
			if err == nil {
				break
			}

			ct.Debugf("Error waiting for NodePort %s:%d (%s): %s: %s", nodeIP, nodePort, service.Name(), err, e.String())

			select {
			case <-ctx.Done():
				return fmt.Errorf("timeout reached waiting for NodePort %s:%d (%s)", nodeIP, nodePort, service.Name())
			case <-time.After(time.Second):
			}
		}
	}
	return nil
}

func (ct *ConnectivityTest) waitForCiliumEndpoint(ctx context.Context, client *k8s.Client, namespace, name string) error {
	ct.Logf("⌛ [%s] Waiting for CiliumEndpoint for pod %s/%s to appear...", client.ClusterName(), namespace, name)
	for {
		_, err := client.GetCiliumEndpoint(ctx, ct.params.TestNamespace, name, metav1.GetOptions{})
		if err == nil {
			return nil
		}

		ct.Debugf("[%s] Error getting CiliumEndpoint for pod %s/%s: %s", client.ClusterName(), namespace, name, err)

		select {
		case <-ctx.Done():
			return fmt.Errorf("aborted waiting for CiliumEndpoint for pod %s to appear: %w", name, ctx.Err())
		case <-time.After(2 * time.Second):
			continue
		}
	}
}
