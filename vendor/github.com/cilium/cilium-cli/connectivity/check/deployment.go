// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/exp/maps"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium-cli/utils/features"
)

const (
	perfClientDeploymentName       = "perf-client"
	perfClientAcrossDeploymentName = "perf-client-other-node"
	perfServerDeploymentName       = "perf-server"

	perfHostNetNamingSuffix = "-host-net"

	clientDeploymentName  = "client"
	client2DeploymentName = "client2"
	clientCPDeployment    = "client-cp"

	DNSTestServerContainerName = "dns-test-server"

	echoSameNodeDeploymentName     = "echo-same-node"
	echoOtherNodeDeploymentName    = "echo-other-node"
	echoExternalNodeDeploymentName = "echo-external-node"
	corednsConfigMapName           = "coredns-configmap"
	corednsConfigVolumeName        = "coredns-config-volume"
	kindEchoName                   = "echo"
	kindEchoExternalNodeName       = "echo-external-node"
	kindClientName                 = "client"
	kindPerfName                   = "perf"

	hostNetNSDeploymentName          = "host-netns"
	hostNetNSDeploymentNameNonCilium = "host-netns-non-cilium" // runs on non-Cilium test nodes
	kindHostNetNS                    = "host-netns"

	testConnDisruptClientDeploymentName = "test-conn-disrupt-client"
	testConnDisruptServerDeploymentName = "test-conn-disrupt-server"
	testConnDisruptServiceName          = "test-conn-disrupt"
	KindTestConnDisrupt                 = "test-conn-disrupt"

	EchoServerHostPort = 4000

	IngressServiceName         = "ingress-service"
	ingressServiceInsecurePort = "31000"
	ingressServiceSecurePort   = "31001"
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
		suffix = perfHostNetNamingSuffix
	}

	return &perfDeploymentNameManager{
		clientDeploymentName:       perfClientDeploymentName + suffix,
		clientAcrossDeploymentName: perfClientAcrossDeploymentName + suffix,
		serverDeploymentName:       perfServerDeploymentName + suffix,
	}
}

type deploymentParameters struct {
	Name           string
	Kind           string
	Image          string
	Replicas       int
	NamedPort      string
	Port           int
	HostPort       int
	Command        []string
	Affinity       *corev1.Affinity
	NodeSelector   map[string]string
	ReadinessProbe *corev1.Probe
	Labels         map[string]string
	Annotations    map[string]string
	HostNetwork    bool
	Tolerations    []corev1.Toleration
}

func newDeployment(p deploymentParameters) *appsv1.Deployment {
	if p.Replicas == 0 {
		p.Replicas = 1
	}
	if len(p.NamedPort) == 0 {
		p.NamedPort = fmt.Sprintf("port-%d", p.Port)
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
					Annotations: p.Annotations,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name: p.Name,
							Env: []corev1.EnvVar{
								{Name: "PORT", Value: fmt.Sprintf("%d", p.Port)},
								{Name: "NAMED_PORT", Value: p.NamedPort},
							},
							Ports: []corev1.ContainerPort{
								{Name: p.NamedPort, ContainerPort: int32(p.Port), HostPort: int32(p.HostPort)},
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
					Affinity:           p.Affinity,
					NodeSelector:       p.NodeSelector,
					HostNetwork:        p.HostNetwork,
					Tolerations:        p.Tolerations,
					ServiceAccountName: p.Name,
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

func newDeploymentWithDNSTestServer(p deploymentParameters, DNSTestServerImage string) *appsv1.Deployment {
	dep := newDeployment(p)

	dep.Spec.Template.Spec.Containers = append(
		dep.Spec.Template.Spec.Containers,
		corev1.Container{
			Args: []string{"-conf", "/etc/coredns/Corefile"},
			Name: DNSTestServerContainerName,
			Ports: []corev1.ContainerPort{
				{ContainerPort: 53, Name: "dns-53"},
				{ContainerPort: 53, Name: "dns-udp-53", Protocol: corev1.ProtocolUDP},
			},
			Image:           DNSTestServerImage,
			ImagePullPolicy: corev1.PullIfNotPresent,
			ReadinessProbe:  newLocalReadinessProbe(8181, "/ready"),
			VolumeMounts: []corev1.VolumeMount{
				{
					Name:      corednsConfigVolumeName,
					MountPath: "/etc/coredns",
					ReadOnly:  true,
				},
			},
		},
	)
	dep.Spec.Template.Spec.Volumes = []corev1.Volume{
		{
			Name: corednsConfigVolumeName,
			VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{
					LocalObjectReference: corev1.LocalObjectReference{
						Name: corednsConfigMapName,
					},
					Items: []corev1.KeyToPath{
						{
							Key:  "Corefile",
							Path: "Corefile",
						},
					},
				},
			},
		},
	}

	return dep
}

type daemonSetParameters struct {
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
	Tolerations    []corev1.Toleration
	Capabilities   []corev1.Capability
	NodeSelector   map[string]string
}

func newDaemonSet(p daemonSetParameters) *appsv1.DaemonSet {
	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{
			Name: p.Name,
			Labels: map[string]string{
				"name": p.Name,
				"kind": p.Kind,
			},
		},
		Spec: appsv1.DaemonSetSpec{
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
							Name:            p.Name,
							Image:           p.Image,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Command:         p.Command,
							ReadinessProbe:  p.ReadinessProbe,
							SecurityContext: &corev1.SecurityContext{
								Capabilities: &corev1.Capabilities{
									Add: append([]corev1.Capability{"NET_RAW"}, p.Capabilities...),
								},
							},
						},
					},
					Affinity:    p.Affinity,
					HostNetwork: p.HostNetwork,
					Tolerations: p.Tolerations,
				},
			},
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"name": p.Name,
					"kind": p.Kind,
				},
			},
		},
	}

	for k, v := range p.Labels {
		ds.Spec.Template.ObjectMeta.Labels[k] = v
	}

	if p.NodeSelector != nil {
		ds.Spec.Template.Spec.NodeSelector = p.NodeSelector
	}

	return ds
}

var serviceLabels = map[string]string{
	"kind": kindEchoName,
}

func newService(name string, selector map[string]string, labels map[string]string, portName string, port int) *corev1.Service {
	ipFamPol := corev1.IPFamilyPolicyPreferDualStack
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
			Selector:       selector,
			IPFamilyPolicy: &ipFamPol,
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

func newIngress() *networkingv1.Ingress {
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name: IngressServiceName,
			Annotations: map[string]string{
				"ingress.cilium.io/loadbalancer-mode":  "dedicated",
				"ingress.cilium.io/service-type":       "NodePort",
				"ingress.cilium.io/insecure-node-port": ingressServiceInsecurePort,
				"ingress.cilium.io/secure-node-port":   ingressServiceSecurePort,
			},
		},
		Spec: networkingv1.IngressSpec{
			IngressClassName: func(in string) *string {
				return &in
			}(defaults.IngressClassName),
			Rules: []networkingv1.IngressRule{
				{
					IngressRuleValue: networkingv1.IngressRuleValue{
						HTTP: &networkingv1.HTTPIngressRuleValue{
							Paths: []networkingv1.HTTPIngressPath{
								{
									Path: "/",
									PathType: func() *networkingv1.PathType {
										pt := networkingv1.PathTypeImplementationSpecific
										return &pt
									}(),
									Backend: networkingv1.IngressBackend{
										Service: &networkingv1.IngressServiceBackend{
											Name: echoSameNodeDeploymentName,
											Port: networkingv1.ServiceBackendPort{
												Number: 8080,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

// deploy ensures the test Namespace, Services and Deployments are running on the cluster.
func (ct *ConnectivityTest) deploy(ctx context.Context) error {
	var err error

	for _, client := range ct.Clients() {
		if ct.params.ForceDeploy {
			if err := ct.deleteDeployments(ctx, client); err != nil {
				return err
			}
			if err := ct.DeleteConnDisruptTestDeployment(ctx, client); err != nil {
				return err
			}
		}

		_, err := client.GetNamespace(ctx, ct.params.TestNamespace, metav1.GetOptions{})
		if err != nil {
			ct.Logf("✨ [%s] Creating namespace %s for connectivity check...", client.ClusterName(), ct.params.TestNamespace)
			namespace := &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:        ct.params.TestNamespace,
					Annotations: ct.params.NamespaceAnnotations,
				},
			}
			_, err = client.CreateNamespace(ctx, namespace, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create namespace %s: %w", ct.params.TestNamespace, err)
			}
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
			if _, ok := zones[l.GetLabels()[corev1.LabelTopologyZone]]; ok {
				zone = l.GetLabels()[corev1.LabelTopologyZone]
				break
			}
			zones[l.GetLabels()[corev1.LabelTopologyZone]] = 1
			lz = l.GetLabels()[corev1.LabelTopologyZone]
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
			ct.Logf("✨ [%s] Deploying %s deployment...", ct.clients.src.ClusterName(), nm.ClientName())
			perfClientDeployment := newDeployment(deploymentParameters{
				Name:      nm.ClientName(),
				Kind:      kindPerfName,
				NamedPort: "http-80",
				Port:      80,
				Image:     ct.params.PerformanceImage,
				Labels: map[string]string{
					"client": "role",
				},
				Annotations: ct.params.DeploymentAnnotations.Match(nm.ClientName()),
				Command:     []string{"/bin/bash", "-c", "sleep 10000000"},
				Affinity: &corev1.Affinity{
					NodeAffinity: &corev1.NodeAffinity{
						PreferredDuringSchedulingIgnoredDuringExecution: []corev1.PreferredSchedulingTerm{
							{
								Weight: 100,
								Preference: corev1.NodeSelectorTerm{
									MatchExpressions: []corev1.NodeSelectorRequirement{
										{Key: corev1.LabelTopologyZone, Operator: corev1.NodeSelectorOpIn, Values: []string{zone}},
									},
								},
							},
						},
					},
				},
				NodeSelector: ct.params.NodeSelector,
				HostNetwork:  ct.params.PerfHostNet,
			})
			_, err = ct.clients.src.CreateServiceAccount(ctx, ct.params.TestNamespace, k8s.NewServiceAccount(nm.ClientName()), metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create service account %s: %s", nm.ClientName(), err)
			}
			_, err = ct.clients.src.CreateDeployment(ctx, ct.params.TestNamespace, perfClientDeployment, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create deployment %s: %w", perfClientDeployment, err)
			}
		}

		_, err = ct.clients.src.GetDeployment(ctx, ct.params.TestNamespace, nm.ServerName(), metav1.GetOptions{})
		if err != nil {
			ct.Logf("✨ [%s] Deploying %s deployment...", ct.clients.src.ClusterName(), nm.ServerName())
			perfServerDeployment := newDeployment(deploymentParameters{
				Name: nm.ServerName(),
				Kind: kindPerfName,
				Labels: map[string]string{
					"server": "role",
				},
				Annotations: ct.params.DeploymentAnnotations.Match(nm.ServerName()),
				Port:        5001,
				Image:       ct.params.PerformanceImage,
				Command:     []string{"/bin/bash", "-c", "netserver;sleep 10000000"},
				Affinity: &corev1.Affinity{
					NodeAffinity: &corev1.NodeAffinity{
						PreferredDuringSchedulingIgnoredDuringExecution: []corev1.PreferredSchedulingTerm{
							{
								Weight: 100,
								Preference: corev1.NodeSelectorTerm{
									MatchExpressions: []corev1.NodeSelectorRequirement{
										{Key: corev1.LabelTopologyZone, Operator: corev1.NodeSelectorOpIn, Values: []string{zone}},
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
								TopologyKey: corev1.LabelHostname,
							},
						},
					},
				},
				NodeSelector: ct.params.NodeSelector,
				HostNetwork:  ct.params.PerfHostNet,
			})
			_, err = ct.clients.src.CreateServiceAccount(ctx, ct.params.TestNamespace, k8s.NewServiceAccount(nm.ServerName()), metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create service account %s: %s", nm.ServerName(), err)
			}

			_, err = ct.clients.src.CreateDeployment(ctx, ct.params.TestNamespace, perfServerDeployment, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create deployment %s: %w", perfServerDeployment, err)
			}
		}

		// Deploy second client on a different node
		if !ct.params.SingleNode {
			_, err := ct.clients.src.GetDeployment(ctx, ct.params.TestNamespace, nm.ClientAcrossName(), metav1.GetOptions{})
			if err != nil {
				ct.Logf("✨ [%s] Deploying %s deployment...", ct.clients.src.ClusterName(), nm.ClientAcrossName())
				perfOtherClientDeployment := newDeployment(deploymentParameters{
					Name: nm.ClientAcrossName(),
					Kind: kindPerfName,
					Port: 5001,
					Labels: map[string]string{
						"client": "role",
					},
					Annotations: ct.params.DeploymentAnnotations.Match(nm.ClientAcrossName()),
					Image:       ct.params.PerformanceImage,
					Command:     []string{"/bin/bash", "-c", "sleep 10000000"},
					Affinity: &corev1.Affinity{
						NodeAffinity: &corev1.NodeAffinity{
							PreferredDuringSchedulingIgnoredDuringExecution: []corev1.PreferredSchedulingTerm{
								{
									Weight: 100,
									Preference: corev1.NodeSelectorTerm{
										MatchExpressions: []corev1.NodeSelectorRequirement{
											{Key: corev1.LabelTopologyZone, Operator: corev1.NodeSelectorOpIn, Values: []string{zone}},
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
									TopologyKey: corev1.LabelHostname}}}},
					},
					NodeSelector: ct.params.NodeSelector,
					HostNetwork:  ct.params.PerfHostNet,
				})
				_, err = ct.clients.src.CreateServiceAccount(ctx, ct.params.TestNamespace, k8s.NewServiceAccount(nm.ClientAcrossName()), metav1.CreateOptions{})
				if err != nil {
					return fmt.Errorf("unable to create service account %s: %s", nm.ClientAcrossName(), err)
				}

				_, err = ct.clients.src.CreateDeployment(ctx, ct.params.TestNamespace, perfOtherClientDeployment, metav1.CreateOptions{})
				if err != nil {
					return fmt.Errorf("unable to create deployment %s: %s", perfOtherClientDeployment, err)
				}
			}
		}
		return nil
	}

	// Deploy test-conn-disrupt actors
	if ct.params.ConnDisruptTestSetup {
		_, err = ct.clients.src.GetDeployment(ctx, ct.params.TestNamespace, testConnDisruptServerDeploymentName, metav1.GetOptions{})
		if err != nil {
			ct.Logf("✨ [%s] Deploying %s deployment...", ct.clients.src.ClusterName(), testConnDisruptServerDeploymentName)
			readinessProbe := &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					Exec: &corev1.ExecAction{
						Command: []string{"cat", "/tmp/server-ready"},
					},
				},
				PeriodSeconds:       int32(3),
				InitialDelaySeconds: int32(1),
				FailureThreshold:    int32(20),
			}
			testConnDisruptServerDeployment := newDeployment(deploymentParameters{
				Name:           testConnDisruptServerDeploymentName,
				Kind:           KindTestConnDisrupt,
				Image:          "quay.io/cilium/test-connection-disruption:v0.0.5",
				Replicas:       3,
				Labels:         map[string]string{"app": "test-conn-disrupt-server"},
				Command:        []string{"tcd-server", "8000"},
				Port:           8000,
				ReadinessProbe: readinessProbe,
			})
			_, err = ct.clients.src.CreateServiceAccount(ctx, ct.params.TestNamespace, k8s.NewServiceAccount(testConnDisruptServerDeploymentName), metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create service account %s: %w", testConnDisruptServerDeploymentName, err)
			}
			_, err = ct.clients.src.CreateDeployment(ctx, ct.params.TestNamespace, testConnDisruptServerDeployment, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create deployment %s: %w", testConnDisruptServerDeployment, err)
			}
		}

		// Make sure that the server deployment is ready to spread client connections
		err := WaitForDeployment(ctx, ct, ct.clients.src, ct.params.TestNamespace, testConnDisruptServerDeploymentName)
		if err != nil {
			ct.Failf("%s deployment is not ready: %s", testConnDisruptServerDeploymentName, err)
		}

		for _, client := range ct.Clients() {
			_, err = client.GetService(ctx, ct.params.TestNamespace, testConnDisruptServiceName, metav1.GetOptions{})
			if err != nil {
				ct.Logf("✨ [%s] Deploying %s service...", client.ClusterName(), testConnDisruptServiceName)
				svc := newService(testConnDisruptServiceName, map[string]string{"app": "test-conn-disrupt-server"}, nil, "http", 8000)
				svc.ObjectMeta.Annotations = map[string]string{"service.cilium.io/global": "true"}
				_, err = client.CreateService(ctx, ct.params.TestNamespace, svc, metav1.CreateOptions{})
				if err != nil {
					return fmt.Errorf("unable to create service %s: %w", testConnDisruptServiceName, err)
				}
			}
		}

		_, err = ct.clients.dst.GetDeployment(ctx, ct.params.TestNamespace, testConnDisruptClientDeploymentName, metav1.GetOptions{})
		if err != nil {
			ct.Logf("✨ [%s] Deploying %s deployment...", ct.clients.dst.ClusterName(), testConnDisruptClientDeploymentName)
			readinessProbe := &corev1.Probe{
				ProbeHandler: corev1.ProbeHandler{
					Exec: &corev1.ExecAction{
						Command: []string{"cat", "/tmp/client-ready"},
					},
				},
				PeriodSeconds:       int32(3),
				InitialDelaySeconds: int32(1),
				FailureThreshold:    int32(20),
			}
			testConnDisruptClientDeployment := newDeployment(deploymentParameters{
				Name:     testConnDisruptClientDeploymentName,
				Kind:     KindTestConnDisrupt,
				Image:    "quay.io/cilium/test-connection-disruption:v0.0.5",
				Replicas: 5,
				Labels:   map[string]string{"app": "test-conn-disrupt-client"},
				Port:     8000,
				Command: []string{
					"tcd-client",
					"--dispatch-interval", strconv.Itoa(int(ct.params.ConnDisruptDispatchInterval.Milliseconds())),
					fmt.Sprintf("test-conn-disrupt.%s.svc.cluster.local.:8000", ct.params.TestNamespace),
				},
				ReadinessProbe: readinessProbe,
			})

			_, err = ct.clients.dst.CreateServiceAccount(ctx, ct.params.TestNamespace, k8s.NewServiceAccount(testConnDisruptClientDeploymentName), metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create service account %s: %w", testConnDisruptClientDeploymentName, err)
			}
			_, err = ct.clients.dst.CreateDeployment(ctx, ct.params.TestNamespace, testConnDisruptClientDeployment, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create deployment %s: %w", testConnDisruptClientDeployment, err)
			}
		}
	}

	_, err = ct.clients.src.GetService(ctx, ct.params.TestNamespace, echoSameNodeDeploymentName, metav1.GetOptions{})
	if err != nil {
		ct.Logf("✨ [%s] Deploying %s service...", ct.clients.src.ClusterName(), echoSameNodeDeploymentName)
		svc := newService(echoSameNodeDeploymentName, map[string]string{"name": echoSameNodeDeploymentName}, serviceLabels, "http", 8080)
		_, err = ct.clients.src.CreateService(ctx, ct.params.TestNamespace, svc, metav1.CreateOptions{})
		if err != nil {
			return err
		}
	}

	if ct.params.MultiCluster != "" {
		_, err = ct.clients.src.GetService(ctx, ct.params.TestNamespace, echoOtherNodeDeploymentName, metav1.GetOptions{})
		if err != nil {
			ct.Logf("✨ [%s] Deploying %s service...", ct.clients.src.ClusterName(), echoOtherNodeDeploymentName)
			svc := newService(echoOtherNodeDeploymentName, map[string]string{"name": echoOtherNodeDeploymentName}, serviceLabels, "http", 8080)
			svc.ObjectMeta.Annotations = map[string]string{}
			svc.ObjectMeta.Annotations["service.cilium.io/global"] = "true"
			svc.ObjectMeta.Annotations["io.cilium/global-service"] = "true"

			_, err = ct.clients.src.CreateService(ctx, ct.params.TestNamespace, svc, metav1.CreateOptions{})
			if err != nil {
				return err
			}
		}
	}

	hostPort := 0
	if ct.Features[features.HostPort].Enabled {
		hostPort = EchoServerHostPort
	}
	dnsConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name: corednsConfigMapName,
		},
		Data: map[string]string{
			"Corefile": `. {
				local
				ready
				log
			}`,
		},
	}
	_, err = ct.clients.src.GetConfigMap(ctx, ct.params.TestNamespace, corednsConfigMapName, metav1.GetOptions{})
	if err != nil {
		ct.Logf("✨ [%s] Deploying DNS test server configmap...", ct.clients.src.ClusterName())
		_, err = ct.clients.src.CreateConfigMap(ctx, ct.params.TestNamespace, dnsConfigMap, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create configmap %s: %s", corednsConfigMapName, err)
		}
	}
	if ct.params.MultiCluster != "" {
		_, err = ct.clients.dst.GetConfigMap(ctx, ct.params.TestNamespace, corednsConfigMapName, metav1.GetOptions{})
		if err != nil {
			ct.Logf("✨ [%s] Deploying DNS test server configmap...", ct.clients.dst.ClusterName())
			_, err = ct.clients.dst.CreateConfigMap(ctx, ct.params.TestNamespace, dnsConfigMap, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create configmap %s: %s", corednsConfigMapName, err)
			}
		}
	}

	_, err = ct.clients.src.GetDeployment(ctx, ct.params.TestNamespace, echoSameNodeDeploymentName, metav1.GetOptions{})
	if err != nil {
		ct.Logf("✨ [%s] Deploying same-node deployment...", ct.clients.src.ClusterName())
		containerPort := 8080
		echoDeployment := newDeploymentWithDNSTestServer(deploymentParameters{
			Name:        echoSameNodeDeploymentName,
			Kind:        kindEchoName,
			Port:        containerPort,
			NamedPort:   "http-8080",
			HostPort:    hostPort,
			Image:       ct.params.JSONMockImage,
			Labels:      map[string]string{"other": "echo"},
			Annotations: ct.params.DeploymentAnnotations.Match(echoSameNodeDeploymentName),
			Affinity: &corev1.Affinity{
				PodAffinity: &corev1.PodAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
						{
							LabelSelector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{Key: "name", Operator: metav1.LabelSelectorOpIn, Values: []string{clientDeploymentName}},
								},
							},
							TopologyKey: corev1.LabelHostname,
						},
					},
				},
			},
			ReadinessProbe: newLocalReadinessProbe(containerPort, "/"),
		}, ct.params.DNSTestServerImage)
		_, err = ct.clients.src.CreateServiceAccount(ctx, ct.params.TestNamespace, k8s.NewServiceAccount(echoSameNodeDeploymentName), metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create service account %s: %s", echoSameNodeDeploymentName, err)
		}
		_, err = ct.clients.src.CreateDeployment(ctx, ct.params.TestNamespace, echoDeployment, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create deployment %s: %s", echoSameNodeDeploymentName, err)
		}
	}

	_, err = ct.clients.src.GetDeployment(ctx, ct.params.TestNamespace, clientDeploymentName, metav1.GetOptions{})
	if err != nil {
		ct.Logf("✨ [%s] Deploying %s deployment...", ct.clients.src.ClusterName(), clientDeploymentName)
		clientDeployment := newDeployment(deploymentParameters{
			Name:         clientDeploymentName,
			Kind:         kindClientName,
			NamedPort:    "http-8080",
			Port:         8080,
			Image:        ct.params.CurlImage,
			Command:      []string{"/bin/ash", "-c", "sleep 10000000"},
			Annotations:  ct.params.DeploymentAnnotations.Match(clientDeploymentName),
			NodeSelector: ct.params.NodeSelector,
		})
		_, err = ct.clients.src.CreateServiceAccount(ctx, ct.params.TestNamespace, k8s.NewServiceAccount(clientDeploymentName), metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create service account %s: %s", clientDeploymentName, err)
		}
		_, err = ct.clients.src.CreateDeployment(ctx, ct.params.TestNamespace, clientDeployment, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create deployment %s: %s", clientDeploymentName, err)
		}
	}

	// 2nd client with label other=client
	_, err = ct.clients.src.GetDeployment(ctx, ct.params.TestNamespace, client2DeploymentName, metav1.GetOptions{})
	if err != nil {
		ct.Logf("✨ [%s] Deploying %s deployment...", ct.clients.src.ClusterName(), client2DeploymentName)
		clientDeployment := newDeployment(deploymentParameters{
			Name:        client2DeploymentName,
			Kind:        kindClientName,
			NamedPort:   "http-8080",
			Port:        8080,
			Image:       ct.params.CurlImage,
			Command:     []string{"/bin/ash", "-c", "sleep 10000000"},
			Labels:      map[string]string{"other": "client"},
			Annotations: ct.params.DeploymentAnnotations.Match(client2DeploymentName),
			Affinity: &corev1.Affinity{
				PodAffinity: &corev1.PodAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
						{
							LabelSelector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{Key: "name", Operator: metav1.LabelSelectorOpIn, Values: []string{clientDeploymentName}},
								},
							},
							TopologyKey: corev1.LabelHostname,
						},
					},
				},
			},
			NodeSelector: ct.params.NodeSelector,
		})
		_, err = ct.clients.src.CreateServiceAccount(ctx, ct.params.TestNamespace, k8s.NewServiceAccount(client2DeploymentName), metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create service account %s: %s", client2DeploymentName, err)
		}
		_, err = ct.clients.src.CreateDeployment(ctx, ct.params.TestNamespace, clientDeployment, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create deployment %s: %s", client2DeploymentName, err)
		}
	}

	// 3rd client scheduled on the control plane
	if ct.params.K8sLocalHostTest {
		ct.Logf("✨ [%s] Deploying %s deployment...", ct.clients.src.ClusterName(), clientCPDeployment)
		clientDeployment := newDeployment(deploymentParameters{
			Name:        clientCPDeployment,
			Kind:        kindClientName,
			NamedPort:   "http-8080",
			Port:        8080,
			Image:       ct.params.CurlImage,
			Command:     []string{"/bin/ash", "-c", "sleep 10000000"},
			Labels:      map[string]string{"other": "client"},
			Annotations: ct.params.DeploymentAnnotations.Match(client2DeploymentName),
			NodeSelector: map[string]string{
				"node-role.kubernetes.io/control-plane": "",
			},
			Replicas: len(ct.ControlPlaneNodes()),
			Tolerations: []corev1.Toleration{
				{Key: "node-role.kubernetes.io/control-plane"},
			},
		})
		_, err = ct.clients.src.CreateServiceAccount(ctx, ct.params.TestNamespace, k8s.NewServiceAccount(clientCPDeployment), metav1.CreateOptions{})
		if err != nil && !errors.IsAlreadyExists(err) {
			return fmt.Errorf("unable to create service account %s: %s", clientCPDeployment, err)
		}
		_, err = ct.clients.src.CreateDeployment(ctx, ct.params.TestNamespace, clientDeployment, metav1.CreateOptions{})
		if err != nil && !errors.IsAlreadyExists(err) {
			return fmt.Errorf("unable to create deployment %s: %s", clientCPDeployment, err)
		}
	}

	if !ct.params.SingleNode || ct.params.MultiCluster != "" {
		_, err = ct.clients.dst.GetService(ctx, ct.params.TestNamespace, echoOtherNodeDeploymentName, metav1.GetOptions{})
		if err != nil {
			ct.Logf("✨ [%s] Deploying echo-other-node service...", ct.clients.dst.ClusterName())
			svc := newService(echoOtherNodeDeploymentName, map[string]string{"name": echoOtherNodeDeploymentName}, serviceLabels, "http", 8080)

			if ct.params.MultiCluster != "" {
				svc.ObjectMeta.Annotations = map[string]string{}
				svc.ObjectMeta.Annotations["service.cilium.io/global"] = "true"
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
			containerPort := 8080
			echoOtherNodeDeployment := newDeploymentWithDNSTestServer(deploymentParameters{
				Name:        echoOtherNodeDeploymentName,
				Kind:        kindEchoName,
				NamedPort:   "http-8080",
				Port:        containerPort,
				HostPort:    hostPort,
				Image:       ct.params.JSONMockImage,
				Labels:      map[string]string{"first": "echo"},
				Annotations: ct.params.DeploymentAnnotations.Match(echoOtherNodeDeploymentName),
				Affinity: &corev1.Affinity{
					PodAntiAffinity: &corev1.PodAntiAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
							{
								LabelSelector: &metav1.LabelSelector{
									MatchExpressions: []metav1.LabelSelectorRequirement{
										{Key: "name", Operator: metav1.LabelSelectorOpIn, Values: []string{clientDeploymentName}},
									},
								},
								TopologyKey: corev1.LabelHostname,
							},
						},
					},
				},
				NodeSelector:   ct.params.NodeSelector,
				ReadinessProbe: newLocalReadinessProbe(containerPort, "/"),
			}, ct.params.DNSTestServerImage)
			_, err = ct.clients.dst.CreateServiceAccount(ctx, ct.params.TestNamespace, k8s.NewServiceAccount(echoOtherNodeDeploymentName), metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create service account %s: %s", echoOtherNodeDeploymentName, err)
			}
			_, err = ct.clients.dst.CreateDeployment(ctx, ct.params.TestNamespace, echoOtherNodeDeployment, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create deployment %s: %w", echoOtherNodeDeploymentName, err)
			}
		}

		for _, client := range ct.clients.clients() {
			_, err = client.GetDaemonSet(ctx, ct.params.TestNamespace, hostNetNSDeploymentName, metav1.GetOptions{})
			if err != nil {
				ct.Logf("✨ [%s] Deploying %s daemonset...", hostNetNSDeploymentName, client.ClusterName())
				ds := newDaemonSet(daemonSetParameters{
					Name:        hostNetNSDeploymentName,
					Kind:        kindHostNetNS,
					Image:       ct.params.CurlImage,
					Port:        8080,
					Labels:      map[string]string{"other": "host-netns"},
					Command:     []string{"/bin/ash", "-c", "sleep 10000000"},
					HostNetwork: true,
				})
				_, err = client.CreateDaemonSet(ctx, ct.params.TestNamespace, ds, metav1.CreateOptions{})
				if err != nil {
					return fmt.Errorf("unable to create daemonset %s: %w", hostNetNSDeploymentName, err)
				}
			}
		}

		_, err = ct.clients.src.GetDaemonSet(ctx, ct.params.TestNamespace, hostNetNSDeploymentNameNonCilium, metav1.GetOptions{})
		if err != nil {
			ct.Logf("✨ [%s] Deploying %s daemonset...", hostNetNSDeploymentNameNonCilium, ct.clients.src.ClusterName())
			ds := newDaemonSet(daemonSetParameters{
				Name:        hostNetNSDeploymentNameNonCilium,
				Kind:        kindHostNetNS,
				Image:       ct.params.CurlImage,
				Port:        8080,
				Labels:      map[string]string{"other": "host-netns"},
				Command:     []string{"/bin/ash", "-c", "sleep 10000000"},
				HostNetwork: true,
				Tolerations: []corev1.Toleration{
					{Operator: corev1.TolerationOpExists},
				},
				Capabilities: []corev1.Capability{corev1.Capability("NET_ADMIN")}, // to install IP routes
				NodeSelector: map[string]string{
					defaults.CiliumNoScheduleLabel: "true",
				},
			})
			_, err = ct.clients.src.CreateDaemonSet(ctx, ct.params.TestNamespace, ds, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create daemonset %s: %w", hostNetNSDeploymentNameNonCilium, err)
			}
		}

		if ct.Features[features.NodeWithoutCilium].Enabled {
			_, err = ct.clients.src.GetDeployment(ctx, ct.params.TestNamespace, echoExternalNodeDeploymentName, metav1.GetOptions{})
			if err != nil {
				ct.Logf("✨ [%s] Deploying echo-external-node deployment...", ct.clients.src.ClusterName())
				containerPort := 8080
				echoExternalDeployment := newDeployment(deploymentParameters{
					Name:           echoExternalNodeDeploymentName,
					Kind:           kindEchoExternalNodeName,
					Port:           containerPort,
					NamedPort:      "http-8080",
					HostPort:       8080,
					Image:          ct.params.JSONMockImage,
					Labels:         map[string]string{"external": "echo"},
					Annotations:    ct.params.DeploymentAnnotations.Match(echoExternalNodeDeploymentName),
					NodeSelector:   map[string]string{"cilium.io/no-schedule": "true"},
					ReadinessProbe: newLocalReadinessProbe(containerPort, "/"),
					HostNetwork:    true,
					Tolerations: []corev1.Toleration{
						{Operator: corev1.TolerationOpExists},
					},
				})
				_, err = ct.clients.src.CreateServiceAccount(ctx, ct.params.TestNamespace, k8s.NewServiceAccount(echoExternalNodeDeploymentName), metav1.CreateOptions{})
				if err != nil {
					return fmt.Errorf("unable to create service account %s: %s", echoExternalNodeDeploymentName, err)
				}
				_, err = ct.clients.src.CreateDeployment(ctx, ct.params.TestNamespace, echoExternalDeployment, metav1.CreateOptions{})
				if err != nil {
					return fmt.Errorf("unable to create deployment %s: %s", echoExternalNodeDeploymentName, err)
				}
			}
		} else {
			ct.Infof("Skipping tests that require a node Without Cilium")
		}
	}

	// Create one Ingress service for echo deployment
	if ct.Features[features.IngressController].Enabled {
		_, err = ct.clients.src.GetIngress(ctx, ct.params.TestNamespace, IngressServiceName, metav1.GetOptions{})
		if err != nil {
			ct.Logf("✨ [%s] Deploying Ingress resource...", ct.clients.src.ClusterName())
			_, err = ct.clients.src.CreateIngress(ctx, ct.params.TestNamespace, newIngress(), metav1.CreateOptions{})
			if err != nil {
				return err
			}

			ingressServiceName := fmt.Sprintf("cilium-ingress-%s", IngressServiceName)
			ct.ingressService[ingressServiceName] = Service{
				Service: &corev1.Service{
					ObjectMeta: metav1.ObjectMeta{
						Name: ingressServiceName,
					},
					Spec: corev1.ServiceSpec{
						Ports: []corev1.ServicePort{
							{
								Name:     "http",
								Protocol: corev1.ProtocolTCP,
								Port:     80,
							},
							{
								Name:     "https",
								Protocol: corev1.ProtocolTCP,
								Port:     443,
							},
						},
					},
				},
			}
		}
	}
	return nil
}

// deploymentList returns 2 lists of Deployments to be used for running tests with.
func (ct *ConnectivityTest) deploymentList() (srcList []string, dstList []string) {
	if !ct.params.Perf {
		srcList = []string{clientDeploymentName, client2DeploymentName, echoSameNodeDeploymentName}
	} else {
		perfNm := newPerfDeploymentNameManager(&ct.params)
		srcList = []string{perfNm.ClientName(), perfNm.ServerName()}
		if !ct.params.SingleNode {
			srcList = append(srcList, perfNm.ClientAcrossName())
		}
	}

	if ct.params.IncludeConnDisruptTest {
		// We append the server and client deployment names to two different
		// lists. This matters when running in multi-cluster mode, because
		// the server is deployed in the local cluster (targeted by the "src"
		// client), while the client in the remote one (targeted by the "dst"
		// client). When running against a single cluster, instead, this does
		// not matter much, because the two clients are identical.
		srcList = append(srcList, testConnDisruptServerDeploymentName)
		dstList = append(dstList, testConnDisruptClientDeploymentName)
	}

	if (ct.params.MultiCluster != "" || !ct.params.SingleNode) && !ct.params.Perf {
		dstList = append(dstList, echoOtherNodeDeploymentName)
	}

	if ct.Features[features.NodeWithoutCilium].Enabled {
		dstList = append(dstList, echoExternalNodeDeploymentName)
	}

	return srcList, dstList
}

func (ct *ConnectivityTest) deleteDeployments(ctx context.Context, client *k8s.Client) error {
	ct.Logf("🔥 [%s] Deleting connectivity check deployments...", client.ClusterName())
	_ = client.DeleteDeployment(ctx, ct.params.TestNamespace, echoSameNodeDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteDeployment(ctx, ct.params.TestNamespace, echoOtherNodeDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteDeployment(ctx, ct.params.TestNamespace, clientDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteDeployment(ctx, ct.params.TestNamespace, client2DeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteServiceAccount(ctx, ct.params.TestNamespace, echoSameNodeDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteServiceAccount(ctx, ct.params.TestNamespace, echoOtherNodeDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteServiceAccount(ctx, ct.params.TestNamespace, clientDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteServiceAccount(ctx, ct.params.TestNamespace, client2DeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteService(ctx, ct.params.TestNamespace, echoSameNodeDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteService(ctx, ct.params.TestNamespace, echoOtherNodeDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteConfigMap(ctx, ct.params.TestNamespace, corednsConfigMapName, metav1.DeleteOptions{})
	_ = client.DeleteNamespace(ctx, ct.params.TestNamespace, metav1.DeleteOptions{})

	_, err := client.GetNamespace(ctx, ct.params.TestNamespace, metav1.GetOptions{})
	if err == nil {
		ct.Logf("⌛ [%s] Waiting for namespace %s to disappear", client.ClusterName(), ct.params.TestNamespace)
		for err == nil {
			time.Sleep(time.Second)
			// Retry the namespace deletion in-case the previous delete was
			// rejected, i.e. by yahoo/k8s-namespace-guard
			_ = client.DeleteNamespace(ctx, ct.params.TestNamespace, metav1.DeleteOptions{})
			_, err = client.GetNamespace(ctx, ct.params.TestNamespace, metav1.GetOptions{})
		}
	}

	return nil
}

func (ct *ConnectivityTest) DeleteConnDisruptTestDeployment(ctx context.Context, client *k8s.Client) error {
	ct.Logf("🔥 [%s] Deleting test-conn-disrupt deployments...", client.ClusterName())
	_ = client.DeleteDeployment(ctx, ct.params.TestNamespace, testConnDisruptClientDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteDeployment(ctx, ct.params.TestNamespace, testConnDisruptServerDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteServiceAccount(ctx, ct.params.TestNamespace, testConnDisruptClientDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteServiceAccount(ctx, ct.params.TestNamespace, testConnDisruptServerDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteService(ctx, ct.params.TestNamespace, testConnDisruptServiceName, metav1.DeleteOptions{})

	return nil
}

// validateDeployment checks if the Deployments we created have the expected Pods in them.
func (ct *ConnectivityTest) validateDeployment(ctx context.Context) error {

	ct.Debug("Validating Deployments...")

	srcDeployments, dstDeployments := ct.deploymentList()
	for _, name := range srcDeployments {
		if err := WaitForDeployment(ctx, ct, ct.clients.src, ct.Params().TestNamespace, name); err != nil {
			return err
		}
	}

	for _, name := range dstDeployments {
		if err := WaitForDeployment(ctx, ct, ct.clients.dst, ct.Params().TestNamespace, name); err != nil {
			return err
		}
	}

	if ct.params.Perf {
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
				if err := WaitForCiliumEndpoint(ctx, ct, ct.clients.src, ct.Params().TestNamespace, perfPod.Name); err != nil {
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
		return nil
	}

	clientPods, err := ct.client.ListPods(ctx, ct.params.TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + kindClientName})
	if err != nil {
		return fmt.Errorf("unable to list client pods: %s", err)
	}

	for _, pod := range clientPods.Items {
		if err := WaitForCiliumEndpoint(ctx, ct, ct.clients.src, ct.Params().TestNamespace, pod.Name); err != nil {
			return err
		}

		if strings.Contains(pod.Name, clientCPDeployment) {
			ct.clientCPPods[pod.Name] = Pod{
				K8sClient: ct.client,
				Pod:       pod.DeepCopy(),
			}
		} else {
			ct.clientPods[pod.Name] = Pod{
				K8sClient: ct.client,
				Pod:       pod.DeepCopy(),
			}

		}
	}

	sameNodePods, err := ct.clients.src.ListPods(ctx, ct.params.TestNamespace, metav1.ListOptions{LabelSelector: "name=" + echoSameNodeDeploymentName})
	if err != nil {
		return fmt.Errorf("unable to list same node pods: %w", err)
	}
	if len(sameNodePods.Items) != 1 {
		return fmt.Errorf("unexpected number of same node pods: %d", len(sameNodePods.Items))
	}
	sameNodePod := Pod{
		Pod: sameNodePods.Items[0].DeepCopy(),
	}

	for _, cp := range ct.clientPods {
		err := WaitForPodDNS(ctx, ct, cp, sameNodePod)
		if err != nil {
			return err
		}
	}

	if !ct.params.SingleNode || ct.params.MultiCluster != "" {
		otherNodePods, err := ct.clients.dst.ListPods(ctx, ct.params.TestNamespace, metav1.ListOptions{LabelSelector: "name=" + echoOtherNodeDeploymentName})
		if err != nil {
			return fmt.Errorf("unable to list other node pods: %w", err)
		}
		if len(otherNodePods.Items) != 1 {
			return fmt.Errorf("unexpected number of other node pods: %d", len(otherNodePods.Items))
		}
		otherNodePod := Pod{
			Pod: otherNodePods.Items[0].DeepCopy(),
		}

		for _, cp := range ct.clientPods {
			if err := WaitForPodDNS(ctx, ct, cp, otherNodePod); err != nil {
				return err
			}
		}
	}

	if ct.Features[features.NodeWithoutCilium].Enabled {
		echoExternalNodePods, err := ct.clients.dst.ListPods(ctx, ct.params.TestNamespace, metav1.ListOptions{LabelSelector: "name=" + echoExternalNodeDeploymentName})
		if err != nil {
			return fmt.Errorf("unable to list other node pods: %w", err)
		}

		for _, pod := range echoExternalNodePods.Items {
			ct.echoExternalPods[pod.Name] = Pod{
				K8sClient: ct.client,
				Pod:       pod.DeepCopy(),
				scheme:    "http",
				port:      8080, // listen port of the echo server inside the container
			}
		}
	}

	for _, cp := range ct.clientPods {
		if err := WaitForCoreDNS(ctx, ct, cp); err != nil {
			return err
		}
	}
	for _, cpp := range ct.clientCPPods {
		if err := WaitForCoreDNS(ctx, ct, cpp); err != nil {
			return err
		}
	}
	for _, client := range ct.clients.clients() {
		echoPods, err := client.ListPods(ctx, ct.params.TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + kindEchoName})
		if err != nil {
			return fmt.Errorf("unable to list echo pods: %w", err)
		}
		for _, echoPod := range echoPods.Items {
			if err := WaitForCiliumEndpoint(ctx, ct, client, echoPod.GetNamespace(), echoPod.GetName()); err != nil {
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
		client := ct.RandomClientPod()
		if client == nil {
			return fmt.Errorf("no client pod available")
		}

		if err := WaitForService(ctx, ct, *client, s); err != nil {
			return err
		}

		// Wait until the service is propagated to the cilium agents
		// running on the nodes hosting the client pods.
		nodes := make(map[string]struct{})
		for _, client := range ct.ClientPods() {
			nodes[client.NodeName()] = struct{}{}
		}

		for _, agent := range ct.CiliumPods() {
			if _, ok := nodes[agent.NodeName()]; ok {
				if err := WaitForServiceEndpoints(ctx, ct, agent, s, 1, ct.Features.IPFamilies()); err != nil {
					return err
				}
			}
		}
	}

	if ct.Features[features.IngressController].Enabled {
		ingressServices, err := ct.clients.src.ListServices(ctx, ct.params.TestNamespace, metav1.ListOptions{LabelSelector: "cilium.io/ingress=true"})
		if err != nil {
			return fmt.Errorf("unable to list ingress services: %w", err)
		}

		for _, ingressService := range ingressServices.Items {
			ct.ingressService[ingressService.Name] = Service{
				Service: ingressService.DeepCopy(),
			}
		}
	}

	if ct.params.MultiCluster == "" {
		client := ct.RandomClientPod()
		if client == nil {
			return fmt.Errorf("no client pod available")
		}

		for _, ciliumPod := range ct.ciliumPods {
			hostIP := ciliumPod.Pod.Status.HostIP
			for _, s := range ct.echoServices {
				if err := WaitForNodePorts(ctx, ct, *client, hostIP, s); err != nil {
					return err
				}
			}
		}
	}

	for _, client := range ct.clients.clients() {
		hostNetNSPods, err := client.ListPods(ctx, ct.params.TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + kindHostNetNS})
		if err != nil {
			return fmt.Errorf("unable to list host netns pods: %w", err)
		}

		for _, pod := range hostNetNSPods.Items {
			_, ok := ct.nodesWithoutCilium[pod.Spec.NodeName]
			p := Pod{
				K8sClient: client,
				Pod:       pod.DeepCopy(),
				Outside:   ok,
			}
			ct.hostNetNSPodsByNode[pod.Spec.NodeName] = p

			if iface := ct.params.SecondaryNetworkIface; iface != "" {
				if ct.Features[features.IPv4].Enabled {
					cmd := []string{"/bin/sh", "-c", fmt.Sprintf("ip -family inet -oneline address show dev %s scope global | awk '{print $4}' | cut -d/ -f1", iface)}
					addr, err := client.ExecInPod(ctx, pod.Namespace, pod.Name, "", cmd)
					if err != nil {
						return fmt.Errorf("failed to fetch secondary network ip addr: %w", err)
					}
					ct.secondaryNetworkNodeIPv4[pod.Spec.NodeName] = strings.TrimSuffix(addr.String(), "\n")
				}
				if ct.Features[features.IPv4].Enabled {
					cmd := []string{"/bin/sh", "-c", fmt.Sprintf("ip -family inet6 -oneline address show dev %s scope global | awk '{print $4}' | cut -d/ -f1", iface)}
					addr, err := client.ExecInPod(ctx, pod.Namespace, pod.Name, "", cmd)
					if err != nil {
						return fmt.Errorf("failed to fetch secondary network ip addr: %w", err)
					}
					ct.secondaryNetworkNodeIPv6[pod.Spec.NodeName] = strings.TrimSuffix(addr.String(), "\n")
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
		pods := append(maps.Values(ct.clientPods), maps.Values(ct.echoPods)...)
		// Set the timeout for all IP cache lookup retries
		for _, cp := range ct.ciliumPods {
			if err := WaitForIPCache(ctx, ct, cp, pods); err != nil {
				return err
			}
		}
	}

	return nil
}
