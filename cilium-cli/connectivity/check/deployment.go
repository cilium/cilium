// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium/cilium-cli/utils/features"
	k8sconst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slimcorev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slimmetav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	policyapi "github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/versioncheck"
)

const (
	PerfHostName                            = "-host-net"
	PerfOtherNode                           = "-other-node"
	PerfLowPriority                         = "-low-priority"
	PerfHighPriority                        = "-high-priority"
	PerfProfiling                           = "-profiling"
	perfEgress                              = "-egress"
	perfIngress                             = "-ingress"
	perfClientDeploymentName                = "perf-client"
	perfClientHostNetDeploymentName         = perfClientDeploymentName + PerfHostName
	perfClientAcrossDeploymentName          = perfClientDeploymentName + PerfOtherNode
	perClientLowPriorityDeploymentName      = perfClientDeploymentName + PerfLowPriority
	perClientHighPriorityDeploymentName     = perfClientDeploymentName + PerfHighPriority
	perfClientHostNetAcrossDeploymentName   = perfClientAcrossDeploymentName + PerfHostName
	perfServerDeploymentName                = "perf-server"
	perfServerHostNetDeploymentName         = perfServerDeploymentName + PerfHostName
	PerfServerProfilingDeploymentName       = perfServerDeploymentName + PerfProfiling
	PerfClientProfilingAcrossDeploymentName = perfClientAcrossDeploymentName + PerfProfiling
	perClientEgressDeploymentName           = perfClientDeploymentName + perfEgress
	perClientIngressDeploymentName          = perfClientDeploymentName + perfIngress
	perServerEgressDeploymentName           = perfServerDeploymentName + perfEgress
	perServerIngressDeploymentName          = perfServerDeploymentName + perfIngress

	clientDeploymentName  = "client"
	client2DeploymentName = "client2"
	client3DeploymentName = "client3"
	clientCPDeployment    = "client-cp"

	DNSTestServerContainerName = "dns-test-server"

	echoSameNodeDeploymentName                 = "echo-same-node"
	echoOtherNodeDeploymentName                = "echo-other-node"
	EchoOtherNodeDeploymentHeadlessServiceName = "echo-other-node-headless"
	echoExternalNodeDeploymentName             = "echo-external-node"
	corednsConfigMapName                       = "coredns-configmap"
	corednsConfigVolumeName                    = "coredns-config-volume"
	kindEchoName                               = "echo"
	kindEchoExternalNodeName                   = "echo-external-node"
	kindClientName                             = "client"
	kindPerfName                               = "perf"
	kindL7LBName                               = "l7-lb"
	lrpBackendDeploymentName                   = "lrp-backend"
	lrpClientDeploymentName                    = "lrp-client"
	kindLrpName                                = "lrp"
	ccnpDeploymentName                         = "client-ccnp"
	kindCCNPName                               = "ccnp"
	loadbalancerL7DeploymentName               = "l7-lb"

	hostNetNSDeploymentName          = "host-netns"
	hostNetNSDeploymentNameNonCilium = "host-netns-non-cilium" // runs on non-Cilium test nodes
	kindHostNetNS                    = "host-netns"

	testConnDisruptClientDeploymentName                              = "test-conn-disrupt-client"
	testConnDisruptClientNSTrafficDeploymentName                     = "test-conn-disrupt-client"
	testConnDisruptClientL7TrafficDeploymentName                     = "test-conn-disrupt-client-l7"
	testConnDisruptClientEgressGatewayOnGatewayNodeDeploymentName    = "test-conn-disrupt-client-egw-gw-node"
	testConnDisruptClientEgressGatewayOnNonGatewayNodeDeploymentName = "test-conn-disrupt-client-egw-non-gw-node"
	testConnDisruptServerDeploymentName                              = "test-conn-disrupt-server"
	testConnDisruptServerNSTrafficDeploymentName                     = "test-conn-disrupt-server-ns-traffic"
	testConnDisruptServerL7TrafficDeploymentName                     = "test-conn-disrupt-server-l7-traffic"
	testConnDisruptServerEgressGatewayDeploymentName                 = "test-conn-disrupt-server-egw"
	testConnDisruptServiceName                                       = "test-conn-disrupt"
	testConnDisruptNSTrafficServiceName                              = "test-conn-disrupt-ns-traffic"
	testConnDisruptL7TrafficServiceName                              = "test-conn-disrupt-l7-traffic"
	testConnDisruptEgressGatewayServiceName                          = "test-conn-disrupt-egw"
	testConnDisruptCNPName                                           = "test-conn-disrupt"
	testConnDisruptNSTrafficCNPName                                  = "test-conn-disrupt-ns-traffic"
	testConnDisruptL7TrafficCNPName                                  = "test-conn-disrupt-l7-traffic"
	testConnDisruptEgressGatewayCNPName                              = "test-conn-disrupt-egw"
	testConnDisruptCEGPName                                          = "test-conn-disrupt"
	testConnDisruptServerNSTrafficAppLabel                           = "test-conn-disrupt-server-ns-traffic"
	testConnDisruptServerL7TrafficAppLabel                           = "test-conn-disrupt-server-l7-traffic"
	testConnDisruptClientL7TrafficAppLabel                           = "test-conn-disrupt-client-l7-traffic"
	testConnDisruptServerEgressGatewayAppLabel                       = "test-conn-disrupt-server-egw"
	testConnDisruptClientEgressGatewayOnGatewayNodeAppLabel          = "test-conn-disrupt-client-egw-gw-node"
	testConnDisruptClientEgressGatewayOnNonGatewayNodeAppLabel       = "test-conn-disrupt-client-egw-non-gw-node"
	KindTestConnDisrupt                                              = "test-conn-disrupt"
	KindTestConnDisruptNSTraffic                                     = "test-conn-disrupt-ns-traffic"
	KindTestConnDisruptL7Traffic                                     = "test-conn-disrupt-l7-traffic"
	KindTestConnDisruptEgressGateway                                 = "test-conn-disrupt-egw"

	bwPrioAnnotationString = "bandwidth.cilium.io/priority"

	egressBandwidth  = "kubernetes.io/egress-bandwidth"
	ingressBandwidth = "kubernetes.io/ingress-bandwidth"
)

type perfPodRole string

const (
	perfPodRoleKey       = "role"
	perfPodRoleServer    = perfPodRole("server")
	perfPodRoleClient    = perfPodRole("client")
	perfPodRoleProfiling = perfPodRole("profiling")
)

var appLabels = map[string]string{
	"app.kubernetes.io/name": "cilium-cli",
}

type deploymentParameters struct {
	Name                          string
	Kind                          string
	Image                         string
	Args                          []string
	Replicas                      int
	NamedPort                     string
	Port                          int
	HostPort                      int
	Command                       []string
	Affinity                      *corev1.Affinity
	NodeSelector                  map[string]string
	ReadinessProbe                *corev1.Probe
	Resources                     corev1.ResourceRequirements
	Labels                        map[string]string
	Annotations                   map[string]string
	HostNetwork                   bool
	Tolerations                   []corev1.Toleration
	TerminationGracePeriodSeconds *int64
}

func (p *deploymentParameters) namedPort() string {
	if len(p.NamedPort) == 0 {
		return fmt.Sprintf("port-%d", p.Port)
	}
	return p.NamedPort
}

func (p *deploymentParameters) args() []string {
	return p.Args
}

func (p *deploymentParameters) ports() (ports []corev1.ContainerPort) {
	if p.Port != 0 {
		ports = append(ports, corev1.ContainerPort{
			Name: p.namedPort(), ContainerPort: int32(p.Port), HostPort: int32(p.HostPort),
		})
	}

	return ports
}

func (p *deploymentParameters) envs() (envs []corev1.EnvVar) {
	if p.Port != 0 {
		envs = append(envs,
			corev1.EnvVar{Name: "PORT", Value: fmt.Sprintf("%d", p.Port)},
			corev1.EnvVar{Name: "NAMED_PORT", Value: p.namedPort()},
		)
	}

	return envs
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
					Annotations: p.Annotations,
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:            p.Name,
							Env:             p.envs(),
							Ports:           p.ports(),
							Image:           p.Image,
							ImagePullPolicy: corev1.PullIfNotPresent,
							Command:         p.Command,
							Args:            p.args(),
							ReadinessProbe:  p.ReadinessProbe,
							Resources:       p.Resources,
							SecurityContext: &corev1.SecurityContext{
								Capabilities: &corev1.Capabilities{
									Add: []corev1.Capability{"NET_RAW"},
								},
							},
						},
					},
					Affinity:                      p.Affinity,
					NodeSelector:                  p.NodeSelector,
					HostNetwork:                   p.HostNetwork,
					Tolerations:                   p.Tolerations,
					ServiceAccountName:            p.Name,
					TerminationGracePeriodSeconds: p.TerminationGracePeriodSeconds,
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

	maps.Copy(dep.Spec.Template.ObjectMeta.Labels, p.Labels)

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

	maps.Copy(ds.Spec.Template.ObjectMeta.Labels, p.Labels)

	if p.NodeSelector != nil {
		ds.Spec.Template.Spec.NodeSelector = p.NodeSelector
	}

	return ds
}

var serviceLabels = map[string]string{
	"kind": kindEchoName,
}

func newService(name string, selector map[string]string, labels map[string]string, portName string, port int, serviceType string) *corev1.Service {
	ipFamPol := corev1.IPFamilyPolicyPreferDualStack
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: labels,
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceType(serviceType),
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

func newIngress(name, backend string) *networkingv1.Ingress {
	return &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Annotations: map[string]string{
				"ingress.cilium.io/loadbalancer-mode": "dedicated",
				"ingress.cilium.io/service-type":      "NodePort",
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
											Name: backend,
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

func newConnDisruptCNP(ns string) *ciliumv2.CiliumNetworkPolicy {
	selector := policyapi.EndpointSelector{
		LabelSelector: &slimmetav1.LabelSelector{
			MatchLabels: map[string]string{"kind": KindTestConnDisrupt},
			MatchExpressions: []slimmetav1.LabelSelectorRequirement{
				{
					Key:      "io.cilium.k8s.policy.cluster",
					Operator: slimmetav1.LabelSelectorOpExists,
				},
			},
		},
	}

	ports := []policyapi.PortRule{{
		Ports: []policyapi.PortProtocol{{
			Protocol: policyapi.ProtoTCP,
			Port:     "8000",
		}},
	}}

	return &ciliumv2.CiliumNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       ciliumv2.CNPKindDefinition,
			APIVersion: ciliumv2.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{Name: testConnDisruptCNPName, Namespace: ns},
		Spec: &policyapi.Rule{
			EndpointSelector: selector,
			Egress: []policyapi.EgressRule{
				{
					EgressCommonRule: policyapi.EgressCommonRule{
						ToEndpoints: []policyapi.EndpointSelector{selector},
					},
					ToPorts: ports,
				},
				{
					// Allow access to DNS for service resolution (we don't care
					// of being restrictive here, so we just allow all endpoints).
					ToPorts: []policyapi.PortRule{{
						Ports: []policyapi.PortProtocol{
							{Protocol: policyapi.ProtoUDP, Port: "53"},
							{Protocol: policyapi.ProtoUDP, Port: "5353"},
						},
					}},
				},
			},
			Ingress: []policyapi.IngressRule{{
				IngressCommonRule: policyapi.IngressCommonRule{
					FromEndpoints: []policyapi.EndpointSelector{selector},
				},
				ToPorts: ports,
			}},
		},
	}
}

func newConnDisruptCNPForNSTraffic(ns string) *ciliumv2.CiliumNetworkPolicy {
	selector := policyapi.EndpointSelector{
		LabelSelector: &slimmetav1.LabelSelector{
			MatchLabels: map[string]string{"kind": KindTestConnDisruptNSTraffic},
		},
	}

	ports := []policyapi.PortRule{{
		Ports: []policyapi.PortProtocol{{
			Protocol: policyapi.ProtoTCP,
			Port:     "8000",
		}},
	}}

	return &ciliumv2.CiliumNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       ciliumv2.CNPKindDefinition,
			APIVersion: ciliumv2.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{Name: testConnDisruptNSTrafficCNPName, Namespace: ns},
		Spec: &policyapi.Rule{
			EndpointSelector: selector,
			Ingress: []policyapi.IngressRule{{
				IngressCommonRule: policyapi.IngressCommonRule{
					FromEntities: policyapi.EntitySlice{
						policyapi.EntityWorld,
						policyapi.EntityRemoteNode,
					},
				},
				ToPorts: ports,
			}},
		},
	}
}

func newConnDisruptCNPForL7Traffic(ns string) *ciliumv2.CiliumNetworkPolicy {
	selector := policyapi.EndpointSelector{
		LabelSelector: &slimmetav1.LabelSelector{
			MatchLabels: map[string]string{"kind": KindTestConnDisruptL7Traffic},
		},
	}

	ports := []policyapi.PortRule{{
		Ports: []policyapi.PortProtocol{{
			Protocol: policyapi.ProtoTCP,
			Port:     "8000",
		}},
		Rules: &policyapi.L7Rules{
			HTTP: []policyapi.PortRuleHTTP{{
				Path:   "/echo",
				Method: "GET",
			}},
		},
	}}

	return &ciliumv2.CiliumNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       ciliumv2.CNPKindDefinition,
			APIVersion: ciliumv2.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{Name: testConnDisruptL7TrafficCNPName, Namespace: ns},
		Spec: &policyapi.Rule{
			EndpointSelector: selector,
			Ingress: []policyapi.IngressRule{{
				IngressCommonRule: policyapi.IngressCommonRule{
					FromEntities: policyapi.EntitySlice{
						policyapi.EntityCluster,
					},
				},
				ToPorts: ports,
			}},
		},
	}
}

func newConnDisruptCNPForEgressGateway(ns string) *ciliumv2.CiliumNetworkPolicy {
	selector := policyapi.EndpointSelector{
		LabelSelector: &slimmetav1.LabelSelector{
			MatchLabels: map[string]string{"kind": KindTestConnDisruptEgressGateway},
		},
	}

	ports := []policyapi.PortRule{{
		Ports: []policyapi.PortProtocol{{
			Protocol: policyapi.ProtoTCP,
			Port:     "8000",
		}},
	}}

	return &ciliumv2.CiliumNetworkPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       ciliumv2.CNPKindDefinition,
			APIVersion: ciliumv2.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{Name: testConnDisruptEgressGatewayCNPName, Namespace: ns},
		Spec: &policyapi.Rule{
			EndpointSelector: selector,
			Egress: []policyapi.EgressRule{
				{
					EgressCommonRule: policyapi.EgressCommonRule{
						ToEntities: policyapi.EntitySlice{
							policyapi.EntityWorld,
						},
					},
					ToPorts: ports,
				},
				{
					ToPorts: []policyapi.PortRule{{
						Ports: []policyapi.PortProtocol{
							{Protocol: policyapi.ProtoUDP, Port: "53"},
							{Protocol: policyapi.ProtoUDP, Port: "5353"},
						},
					}},
				},
			},
		},
	}
}

func newConnDisruptCEGP(ns, gwNode string) *ciliumv2.CiliumEgressGatewayPolicy {
	return &ciliumv2.CiliumEgressGatewayPolicy{
		TypeMeta: metav1.TypeMeta{
			Kind:       ciliumv2.CEGPKindDefinition,
			APIVersion: ciliumv2.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{Name: testConnDisruptCEGPName},
		Spec: ciliumv2.CiliumEgressGatewayPolicySpec{
			Selectors: []ciliumv2.EgressRule{
				{
					PodSelector: &slimmetav1.LabelSelector{
						MatchLabels: map[string]slimmetav1.MatchLabelsValue{
							k8sconst.PodNamespaceLabel: ns,
							"kind":                     KindTestConnDisruptEgressGateway,
						},
					},
				},
			},
			DestinationCIDRs: []ciliumv2.CIDR{"0.0.0.0/0"},
			ExcludedCIDRs:    []ciliumv2.CIDR{},
			EgressGateway: &ciliumv2.EgressGateway{
				NodeSelector: &slimmetav1.LabelSelector{
					MatchLabels: map[string]slimmetav1.MatchLabelsValue{
						"kubernetes.io/hostname": gwNode,
					},
				},
			},
			EgressGateways: []ciliumv2.EgressGateway{},
		},
	}
}

func (ct *ConnectivityTest) ingresses() map[string]string {
	ingresses := map[string]string{"same-node": echoSameNodeDeploymentName}
	if !ct.Params().SingleNode || ct.Params().MultiCluster != "" {
		ingresses["other-node"] = echoOtherNodeDeploymentName
	}
	return ingresses
}

// maybeNodeToNodeEncryptionAffinity returns a node affinity term to prefer nodes
// not being part of the control plane when node to node encryption is enabled,
// because they are excluded by default from node to node encryption. This logic
// is currently suboptimal as it only accounts for the default selector, for the
// sake of simplicity, but it should cover all common use cases.
func (ct *ConnectivityTest) maybeNodeToNodeEncryptionAffinity() *corev1.NodeAffinity {
	encryptNode, _ := ct.Feature(features.EncryptionNode)
	if !encryptNode.Enabled || encryptNode.Mode == "" {
		return nil
	}

	return &corev1.NodeAffinity{
		PreferredDuringSchedulingIgnoredDuringExecution: []corev1.PreferredSchedulingTerm{{
			Weight: 100,
			Preference: corev1.NodeSelectorTerm{
				MatchExpressions: []corev1.NodeSelectorRequirement{{
					Key:      "node-role.kubernetes.io/control-plane",
					Operator: corev1.NodeSelectorOpDoesNotExist,
				}},
			},
		}},
	}
}

// deployNamespace sets up the test namespace.
func (ct *ConnectivityTest) deployNamespace(ctx context.Context) error {
	for _, client := range ct.Clients() {
		if ct.params.ForceDeploy {
			if err := ct.deleteDeployments(ctx, client); err != nil {
				return err
			}
			if err := ct.DeleteConnDisruptTestDeployment(ctx, client); err != nil {
				return err
			}
			if err := ct.DeleteCCNPTestEnv(ctx, client); err != nil {
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
					Labels:      labels.Merge(ct.params.NamespaceLabels, appLabels),
				},
			}
			_, err = client.CreateNamespace(ctx, namespace, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create namespace %s: %w", ct.params.TestNamespace, err)
			}
		}
	}

	return nil
}

// DeployZtunnelTestEnv deploys the test infrastructure for ztunnel e2e tests.
// This is exported so it can be called from the test's WithSetupFunc.
func DeployZtunnelTestEnv(ctx context.Context, t *Test, ct *ConnectivityTest) error {
	namespaceConfigs := []struct {
		name string
		obj  *corev1.Namespace
	}{
		{
			name: "cilium-test-ztunnel-enrolled-0",
			obj: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cilium-test-ztunnel-enrolled-0",
				},
			},
		},
		{
			name: "cilium-test-ztunnel-enrolled-1",
			obj: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cilium-test-ztunnel-enrolled-1",
				},
			},
		},
		{
			name: "cilium-test-ztunnel-unenrolled",
			obj: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cilium-test-ztunnel-unenrolled",
				},
			},
		},
	}

	client := ct.K8sClient()

	for _, nsConfig := range namespaceConfigs {
		var err error

		// Create namespace
		_, err = client.GetNamespace(ctx, nsConfig.name, metav1.GetOptions{})
		if err != nil {
			ct.Logf("✨ [%s] Creating namespace %s...", client.ClusterName(), nsConfig.name)
			_, err = client.CreateNamespace(ctx, nsConfig.obj, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create namespace %s: %w", nsConfig.name, err)
			}
		}

		// Create client deployment
		_, err = client.GetDeployment(ctx, nsConfig.name, clientDeploymentName, metav1.GetOptions{})
		if err != nil {
			ct.Logf("✨ [%s] Deploying %s in namespace %s...", client.ClusterName(), clientDeploymentName, nsConfig.name)
			var clientAffinity *corev1.Affinity
			if nsConfig.name == "cilium-test-ztunnel-enrolled-0" {
				// First namespace - just use node affinity
				clientAffinity = &corev1.Affinity{
					NodeAffinity: ct.maybeNodeToNodeEncryptionAffinity(),
				}
			} else {
				// Subsequent namespaces - add pod affinity to first namespace's client
				clientAffinity = &corev1.Affinity{
					PodAffinity: &corev1.PodAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
							{
								LabelSelector: &metav1.LabelSelector{
									MatchExpressions: []metav1.LabelSelectorRequirement{
										{
											Key:      "name",
											Operator: metav1.LabelSelectorOpIn,
											Values:   []string{clientDeploymentName},
										},
									},
								},
								Namespaces:  []string{"cilium-test-ztunnel-enrolled-0"},
								TopologyKey: corev1.LabelHostname,
							},
						},
					},
					NodeAffinity: ct.maybeNodeToNodeEncryptionAffinity(),
				}
			}

			clientDeployment := newDeployment(deploymentParameters{
				Name:         clientDeploymentName,
				Kind:         kindClientName,
				Image:        ct.params.CurlImage,
				Command:      []string{"/usr/bin/pause"},
				Annotations:  ct.params.DeploymentAnnotations.Match(clientDeploymentName),
				Affinity:     clientAffinity,
				NodeSelector: ct.params.NodeSelector,
				Tolerations:  ct.params.GetTolerations(),
			})
			_, err = client.CreateServiceAccount(ctx, nsConfig.name, k8s.NewServiceAccount(clientDeploymentName), metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create service account %s in namespace %s: %w", clientDeploymentName, nsConfig.name, err)
			}
			_, err = client.CreateDeployment(ctx, nsConfig.name, clientDeployment, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create deployment %s in namespace %s: %w", clientDeploymentName, nsConfig.name, err)
			}
		}

		// Create echo-same-node deployment
		_, err = client.GetDeployment(ctx, nsConfig.name, echoSameNodeDeploymentName, metav1.GetOptions{})
		if err != nil {
			ct.Logf("✨ [%s] Deploying %s in namespace %s...", client.ClusterName(), echoSameNodeDeploymentName, nsConfig.name)
			containerPort := 8080
			echoSameNodeDeployment := newDeployment(deploymentParameters{
				Name:        echoSameNodeDeploymentName,
				Kind:        kindEchoName,
				Port:        containerPort,
				NamedPort:   "http-8080",
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
					NodeAffinity: ct.maybeNodeToNodeEncryptionAffinity(),
				},
				Tolerations:    ct.params.GetTolerations(),
				ReadinessProbe: newLocalReadinessProbe(containerPort, "/"),
			})
			_, err = client.CreateServiceAccount(ctx, nsConfig.name, k8s.NewServiceAccount(echoSameNodeDeploymentName), metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create service account %s in namespace %s: %w", echoSameNodeDeploymentName, nsConfig.name, err)
			}
			_, err = client.CreateDeployment(ctx, nsConfig.name, echoSameNodeDeployment, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create deployment %s in namespace %s: %w", echoSameNodeDeploymentName, nsConfig.name, err)
			}
		}

		// Create echo-other-node deployment
		_, err = client.GetDeployment(ctx, nsConfig.name, echoOtherNodeDeploymentName, metav1.GetOptions{})
		if err != nil {
			ct.Logf("✨ [%s] Deploying %s in namespace %s...", client.ClusterName(), echoOtherNodeDeploymentName, nsConfig.name)
			containerPort := 8080
			echoOtherNodeDeployment := newDeployment(deploymentParameters{
				Name:        echoOtherNodeDeploymentName,
				Kind:        kindEchoName,
				NamedPort:   "http-8080",
				Port:        containerPort,
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
					NodeAffinity: ct.maybeNodeToNodeEncryptionAffinity(),
				},
				NodeSelector:   ct.params.NodeSelector,
				ReadinessProbe: newLocalReadinessProbe(containerPort, "/"),
				Tolerations:    ct.params.GetTolerations(),
			})
			_, err = client.CreateServiceAccount(ctx, nsConfig.name, k8s.NewServiceAccount(echoOtherNodeDeploymentName), metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create service account %s in namespace %s: %w", echoOtherNodeDeploymentName, nsConfig.name, err)
			}
			_, err = client.CreateDeployment(ctx, nsConfig.name, echoOtherNodeDeployment, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create deployment %s in namespace %s: %w", echoOtherNodeDeploymentName, nsConfig.name, err)
			}
		}
	}

	// Wait for deployments to be ready
	namespaces := []string{"cilium-test-ztunnel-enrolled-0", "cilium-test-ztunnel-enrolled-1", "cilium-test-ztunnel-unenrolled"}
	for _, ns := range namespaces {
		if err := WaitForDeployment(ctx, ct, client, ns, clientDeploymentName); err != nil {
			return err
		}
		if err := WaitForDeployment(ctx, ct, client, ns, echoSameNodeDeploymentName); err != nil {
			return err
		}
		if err := WaitForDeployment(ctx, ct, client, ns, echoOtherNodeDeploymentName); err != nil {
			return err
		}
	}

	return nil
}

func (ct *ConnectivityTest) deployCCNPTestEnv(ctx context.Context) error {
	namespaceConfigs := []struct {
		name string
		obj  *corev1.Namespace
	}{
		{
			name: "cilium-test-ccnp1",
			obj: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cilium-test-ccnp1",
				},
			},
		},
		{
			name: "cilium-test-ccnp2",
			obj: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cilium-test-ccnp2",
				},
			},
		},
	}

	for _, nsConfig := range namespaceConfigs {

		clientccnp := ct.clients.src
		var err error

		_, err = clientccnp.GetNamespace(ctx, nsConfig.name, metav1.GetOptions{})
		if err != nil {
			_, err = clientccnp.CreateNamespace(ctx, nsConfig.obj, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create namespace %s: %w", nsConfig.name, err)
			}
		}

		_, err = clientccnp.GetDeployment(ctx, nsConfig.name, ccnpDeploymentName, metav1.GetOptions{})
		if err != nil {
			clientDeployment := newDeployment(deploymentParameters{
				Name:         ccnpDeploymentName,
				Kind:         kindCCNPName,
				Image:        ct.params.CurlImage,
				Command:      []string{"/usr/bin/pause"},
				Annotations:  ct.params.DeploymentAnnotations.Match(ccnpDeploymentName),
				Affinity:     &corev1.Affinity{NodeAffinity: ct.maybeNodeToNodeEncryptionAffinity()},
				NodeSelector: ct.params.NodeSelector,
			})
			_, err = clientccnp.CreateServiceAccount(ctx, nsConfig.name, k8s.NewServiceAccount(ccnpDeploymentName), metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create service account %s in namespace %s: %w", ccnpDeploymentName, nsConfig.name, err)
			}
			_, err = clientccnp.CreateDeployment(ctx, nsConfig.name, clientDeployment, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create deployment %s in namespace %s: %w", ccnpDeploymentName, nsConfig.name, err)
			}
		}

	}

	return nil
}

// deploy ensures the test Namespace, Services and Deployments are running on the cluster.
func (ct *ConnectivityTest) deploy(ctx context.Context) error {
	if err := ct.deployNamespace(ctx); err != nil {
		return err
	}

	// Deploy test-conn-disrupt actors (only in the first
	// test namespace in case of tests concurrent run)
	if ct.params.ConnDisruptTestSetup && ct.params.TestNamespaceIndex == 0 {
		if err := ct.createTestConnDisruptServerDeployAndSvc(ctx, testConnDisruptServerDeploymentName, KindTestConnDisrupt, 3,
			testConnDisruptServiceName, "test-conn-disrupt-server", false, newConnDisruptCNP, ""); err != nil {
			return err
		}

		if err := ct.createTestConnDisruptClientDeployment(ctx, testConnDisruptClientDeploymentName, KindTestConnDisrupt,
			"test-conn-disrupt-client", fmt.Sprintf("test-conn-disrupt.%s.svc.cluster.local.:8000", ct.params.TestNamespace),
			5, false, nil, ""); err != nil {
			return err
		}

		if ct.ShouldRunConnDisruptNSTraffic() {
			if err := ct.createTestConnDisruptServerDeployAndSvc(ctx, testConnDisruptServerNSTrafficDeploymentName, KindTestConnDisruptNSTraffic, 1,
				testConnDisruptNSTrafficServiceName, testConnDisruptServerNSTrafficAppLabel, false, newConnDisruptCNPForNSTraffic, ""); err != nil {
				return err
			}

			if err := ct.createTestConnDisruptClientDeploymentForNSTraffic(ctx); err != nil {
				return err
			}
		} else {
			ct.Info("Skipping conn-disrupt-test for NS traffic")
		}

		if ct.ShouldRunConnDisruptL7Traffic() {
			if err := ct.createTestConnDisruptServerDeployAndSvc(ctx, testConnDisruptServerL7TrafficDeploymentName, KindTestConnDisruptL7Traffic, 1,
				testConnDisruptL7TrafficServiceName, testConnDisruptServerL7TrafficAppLabel, false, newConnDisruptCNPForL7Traffic, "http"); err != nil {
				return err
			}

			allTargets := map[string]string{
				"svc": fmt.Sprintf("%s.%s.svc.cluster.local.", testConnDisruptL7TrafficServiceName, ct.params.TestNamespace),
			}
			serverPods, err := ct.clients.src.ListPods(ctx, ct.params.TestNamespace, metav1.ListOptions{LabelSelector: fmt.Sprintf("app=%s", testConnDisruptServerL7TrafficAppLabel)})
			if err != nil {
				return err
			}
			for _, serverPod := range serverPods.Items {
				for _, podIPAddr := range serverPod.Status.PodIPs {
					podIP, err := netip.ParseAddr(podIPAddr.IP)
					if err != nil {
						continue
					}

					if podIP.Unmap().Is4() {
						allTargets["ep-v4"] = podIPAddr.IP
					} else {
						allTargets["ep-v6"] = podIPAddr.IP
					}
				}
			}

			for targetName, target := range allTargets {
				clientDeploymentName := fmt.Sprintf("%s-%s", testConnDisruptClientL7TrafficDeploymentName, targetName)
				targetAddress := fmt.Sprintf("http://%s:8000/echo", target)

				if err := ct.createTestConnDisruptClientDeployment(ctx, clientDeploymentName, KindTestConnDisruptL7Traffic,
					testConnDisruptClientL7TrafficAppLabel, targetAddress, 1, false, nil, "http"); err != nil {
					return err
				}

				ct.testConnDisruptClientL7TrafficDeploymentNames = append(ct.testConnDisruptClientL7TrafficDeploymentNames, clientDeploymentName)
			}
		} else {
			ct.Info("Skipping conn-disrupt-test for L7 traffic")
		}

		if ct.ShouldRunConnDisruptEgressGateway() {
			gatewayNode, nonGatewayNode, err := ct.getGatewayAndNonGatewayNodes()
			if err != nil {
				return err
			}
			cegp := newConnDisruptCEGP(ct.params.TestNamespace, gatewayNode)
			ct.Logf("✨ [%s] Deploying %s CiliumEgressGatewayPolicy...", ct.K8sClient().ClusterName(), cegp.Name)
			_, err = ct.K8sClient().ApplyGeneric(ctx, cegp)
			if err != nil {
				return fmt.Errorf("unable to create CiliumEgressGatewayPolicy %s: %w", cegp.Name, err)
			}

			if err := ct.createTestConnDisruptServerDeployAndSvc(ctx, testConnDisruptServerEgressGatewayDeploymentName, KindTestConnDisruptEgressGateway, 1,
				testConnDisruptEgressGatewayServiceName, testConnDisruptServerEgressGatewayAppLabel, true, newConnDisruptCNPForEgressGateway, ""); err != nil {
				return err
			}

			if err := ct.createTestConnDisruptClientDeployment(ctx, testConnDisruptClientEgressGatewayOnGatewayNodeDeploymentName, KindTestConnDisruptEgressGateway,
				testConnDisruptClientEgressGatewayOnGatewayNodeAppLabel, fmt.Sprintf("test-conn-disrupt-egw.%s.svc.cluster.local.:8000", ct.params.TestNamespace),
				1, false, map[string]string{"kubernetes.io/hostname": gatewayNode}, ""); err != nil {
				return err
			}
			if err := ct.createTestConnDisruptClientDeployment(ctx, testConnDisruptClientEgressGatewayOnNonGatewayNodeDeploymentName, KindTestConnDisruptEgressGateway,
				testConnDisruptClientEgressGatewayOnNonGatewayNodeAppLabel, fmt.Sprintf("test-conn-disrupt-egw.%s.svc.cluster.local.:8000", ct.params.TestNamespace),
				1, false, map[string]string{"kubernetes.io/hostname": nonGatewayNode}, ""); err != nil {
				return err
			}
			for _, clientDeploy := range []string{testConnDisruptClientEgressGatewayOnGatewayNodeDeploymentName, testConnDisruptClientEgressGatewayOnNonGatewayNodeDeploymentName} {
				err := WaitForDeployment(ctx, ct, ct.clients.dst, ct.params.TestNamespace, clientDeploy)
				if err != nil {
					ct.Failf("%s deployment is not ready: %s", clientDeploy, err)
				}
			}

			testPods := append(
				slices.Collect(maps.Values(ct.ClientPods())),
				slices.Collect(maps.Values(ct.EchoPods()))...)

			if err := WaitForEgressGatewayBpfPolicyEntries(ctx, ct.CiliumPods(), testPods,
				func(ciliumPod Pod) ([]BPFEgressGatewayPolicyEntry, error) {
					return ct.GetConnDisruptEgressPolicyEntries(ctx, ciliumPod)
				}, func(ciliumPod Pod) ([]BPFEgressGatewayPolicyEntry, error) {
					return nil, nil
				}); err != nil {
				ct.Fail(err)
			}
		} else {
			ct.Info("Skipping conn-disrupt-test for Egress Gateway")
		}
	}

	_, err := ct.clients.src.GetService(ctx, ct.params.TestNamespace, echoSameNodeDeploymentName, metav1.GetOptions{})
	if err != nil {
		ct.Logf("✨ [%s] Deploying %s service...", ct.clients.src.ClusterName(), echoSameNodeDeploymentName)
		svc := newService(echoSameNodeDeploymentName, map[string]string{"name": echoSameNodeDeploymentName}, serviceLabels, "http", 8080, ct.Params().ServiceType)
		_, err = ct.clients.src.CreateService(ctx, ct.params.TestNamespace, svc, metav1.CreateOptions{})
		if err != nil {
			return err
		}
	}

	if ct.params.MultiCluster != "" {
		_, err = ct.clients.src.GetService(ctx, ct.params.TestNamespace, echoOtherNodeDeploymentName, metav1.GetOptions{})
		svc := newService(echoOtherNodeDeploymentName, map[string]string{"name": echoOtherNodeDeploymentName}, serviceLabels, "http", 8080, ct.Params().ServiceType)
		svc.ObjectMeta.Annotations = map[string]string{}
		svc.ObjectMeta.Annotations["service.cilium.io/global"] = "true"
		svc.ObjectMeta.Annotations["io.cilium/global-service"] = "true"

		if err != nil {
			ct.Logf("✨ [%s] Deploying %s service...", ct.clients.src.ClusterName(), echoOtherNodeDeploymentName)
			_, err = ct.clients.src.CreateService(ctx, ct.params.TestNamespace, svc, metav1.CreateOptions{})
			if err != nil {
				return err
			}
		}

		_, err = ct.clients.src.GetService(ctx, ct.params.TestNamespace, EchoOtherNodeDeploymentHeadlessServiceName, metav1.GetOptions{})
		svcHeadless := svc.DeepCopy()
		svcHeadless.Name = EchoOtherNodeDeploymentHeadlessServiceName
		svcHeadless.Spec.ClusterIP = corev1.ClusterIPNone
		svcHeadless.Spec.Type = corev1.ServiceTypeClusterIP
		svcHeadless.ObjectMeta.Annotations["service.cilium.io/global-sync-endpoint-slices"] = "true"

		if err != nil {
			ct.Logf("✨ [%s] Deploying %s service...", ct.clients.src.ClusterName(), EchoOtherNodeDeploymentHeadlessServiceName)
			_, err = ct.clients.src.CreateService(ctx, ct.params.TestNamespace, svcHeadless, metav1.CreateOptions{})
			if err != nil {
				return err
			}
		}
	}

	hostPort := 0
	if ct.Features[features.HostPort].Enabled {
		hostPort = ct.Params().EchoServerHostPort
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
			return fmt.Errorf("unable to create configmap %s: %w", corednsConfigMapName, err)
		}
	}
	if ct.params.MultiCluster != "" {
		_, err = ct.clients.dst.GetConfigMap(ctx, ct.params.TestNamespace, corednsConfigMapName, metav1.GetOptions{})
		if err != nil {
			ct.Logf("✨ [%s] Deploying DNS test server configmap...", ct.clients.dst.ClusterName())
			_, err = ct.clients.dst.CreateConfigMap(ctx, ct.params.TestNamespace, dnsConfigMap, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create configmap %s: %w", corednsConfigMapName, err)
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
				NodeAffinity: ct.maybeNodeToNodeEncryptionAffinity(),
			},
			Tolerations:    ct.params.GetTolerations(),
			ReadinessProbe: newLocalReadinessProbe(containerPort, "/"),
		}, ct.params.DNSTestServerImage)
		_, err = ct.clients.src.CreateServiceAccount(ctx, ct.params.TestNamespace, k8s.NewServiceAccount(echoSameNodeDeploymentName), metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create service account %s: %w", echoSameNodeDeploymentName, err)
		}
		_, err = ct.clients.src.CreateDeployment(ctx, ct.params.TestNamespace, echoDeployment, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create deployment %s: %w", echoSameNodeDeploymentName, err)
		}
	}

	_, err = ct.clients.src.GetDeployment(ctx, ct.params.TestNamespace, clientDeploymentName, metav1.GetOptions{})
	if err != nil {
		ct.Logf("✨ [%s] Deploying %s deployment...", ct.clients.src.ClusterName(), clientDeploymentName)
		clientDeployment := newDeployment(deploymentParameters{
			Name:         clientDeploymentName,
			Kind:         kindClientName,
			Image:        ct.params.CurlImage,
			Command:      []string{"/usr/bin/pause"},
			Annotations:  ct.params.DeploymentAnnotations.Match(clientDeploymentName),
			Affinity:     &corev1.Affinity{NodeAffinity: ct.maybeNodeToNodeEncryptionAffinity()},
			NodeSelector: ct.params.NodeSelector,
			Tolerations:  ct.params.GetTolerations(),
		})
		_, err = ct.clients.src.CreateServiceAccount(ctx, ct.params.TestNamespace, k8s.NewServiceAccount(clientDeploymentName), metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create service account %s: %w", clientDeploymentName, err)
		}
		_, err = ct.clients.src.CreateDeployment(ctx, ct.params.TestNamespace, clientDeployment, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create deployment %s: %w", clientDeploymentName, err)
		}
	}

	// 2nd client with label other=client
	_, err = ct.clients.src.GetDeployment(ctx, ct.params.TestNamespace, client2DeploymentName, metav1.GetOptions{})
	if err != nil {
		ct.Logf("✨ [%s] Deploying %s deployment...", ct.clients.src.ClusterName(), client2DeploymentName)
		clientDeployment := newDeployment(deploymentParameters{
			Name:        client2DeploymentName,
			Kind:        kindClientName,
			Image:       ct.params.CurlImage,
			Command:     []string{"/usr/bin/pause"},
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
				NodeAffinity: ct.maybeNodeToNodeEncryptionAffinity(),
			},
			NodeSelector: ct.params.NodeSelector,
			Tolerations:  ct.params.GetTolerations(),
		})
		_, err = ct.clients.src.CreateServiceAccount(ctx, ct.params.TestNamespace, k8s.NewServiceAccount(client2DeploymentName), metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create service account %s: %w", client2DeploymentName, err)
		}
		_, err = ct.clients.src.CreateDeployment(ctx, ct.params.TestNamespace, clientDeployment, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create deployment %s: %w", client2DeploymentName, err)
		}
	}

	if ct.params.MultiCluster == "" && !ct.params.SingleNode {
		// 3rd client scheduled on a different node than the first 2 clients
		_, err = ct.clients.src.GetDeployment(ctx, ct.params.TestNamespace, client3DeploymentName, metav1.GetOptions{})
		if err != nil {
			ct.Logf("✨ [%s] Deploying %s deployment...", ct.clients.src.ClusterName(), client3DeploymentName)
			clientDeployment := newDeployment(deploymentParameters{
				Name:        client3DeploymentName,
				Kind:        kindClientName,
				Image:       ct.params.CurlImage,
				Command:     []string{"/usr/bin/pause"},
				Labels:      map[string]string{"other": "client-other-node"},
				Annotations: ct.params.DeploymentAnnotations.Match(client3DeploymentName),
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
					NodeAffinity: ct.maybeNodeToNodeEncryptionAffinity(),
				},
				NodeSelector: ct.params.NodeSelector,
				Tolerations:  ct.params.GetTolerations(),
			})
			_, err = ct.clients.src.CreateServiceAccount(ctx, ct.params.TestNamespace, k8s.NewServiceAccount(client3DeploymentName), metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create service account %s: %w", client3DeploymentName, err)
			}
			_, err = ct.clients.src.CreateDeployment(ctx, ct.params.TestNamespace, clientDeployment, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create deployment %s: %w", client3DeploymentName, err)
			}
		}
	}

	// 4th client scheduled on the control plane
	if ct.params.K8sLocalHostTest {
		ct.Logf("✨ [%s] Deploying %s deployment...", ct.clients.src.ClusterName(), clientCPDeployment)
		clientDeployment := newDeployment(deploymentParameters{
			Name:        clientCPDeployment,
			Kind:        kindClientName,
			Image:       ct.params.CurlImage,
			Command:     []string{"/usr/bin/pause"},
			Labels:      map[string]string{"other": "client"},
			Annotations: ct.params.DeploymentAnnotations.Match(client2DeploymentName),
			NodeSelector: map[string]string{
				"node-role.kubernetes.io/control-plane": "",
			},
			Replicas: len(ct.ControlPlaneNodes()),
			Tolerations: append(
				[]corev1.Toleration{
					{Key: "node-role.kubernetes.io/control-plane"},
				},
				ct.params.GetTolerations()...,
			),
		})
		_, err = ct.clients.src.CreateServiceAccount(ctx, ct.params.TestNamespace, k8s.NewServiceAccount(clientCPDeployment), metav1.CreateOptions{})
		if err != nil && !k8sErrors.IsAlreadyExists(err) {
			return fmt.Errorf("unable to create service account %s: %w", clientCPDeployment, err)
		}
		_, err = ct.clients.src.CreateDeployment(ctx, ct.params.TestNamespace, clientDeployment, metav1.CreateOptions{})
		if err != nil && !k8sErrors.IsAlreadyExists(err) {
			return fmt.Errorf("unable to create deployment %s: %w", clientCPDeployment, err)
		}
	}

	if !ct.params.SingleNode || ct.params.MultiCluster != "" {
		_, err = ct.clients.dst.GetService(ctx, ct.params.TestNamespace, echoOtherNodeDeploymentName, metav1.GetOptions{})
		svc := newService(echoOtherNodeDeploymentName, map[string]string{"name": echoOtherNodeDeploymentName}, serviceLabels, "http", 8080, ct.Params().ServiceType)
		if ct.params.MultiCluster != "" {
			svc.ObjectMeta.Annotations = map[string]string{}
			svc.ObjectMeta.Annotations["service.cilium.io/global"] = "true"
			svc.ObjectMeta.Annotations["io.cilium/global-service"] = "true"
		}

		if err != nil {
			ct.Logf("✨ [%s] Deploying %s service...", ct.clients.dst.ClusterName(), echoOtherNodeDeploymentName)
			_, err = ct.clients.dst.CreateService(ctx, ct.params.TestNamespace, svc, metav1.CreateOptions{})
			if err != nil {
				return err
			}
		}

		if ct.params.MultiCluster != "" {
			svcHeadless := svc.DeepCopy()
			svcHeadless.Name = EchoOtherNodeDeploymentHeadlessServiceName
			svcHeadless.Spec.ClusterIP = corev1.ClusterIPNone
			svcHeadless.Spec.Type = corev1.ServiceTypeClusterIP
			svcHeadless.ObjectMeta.Annotations["service.cilium.io/global-sync-endpoint-slices"] = "true"
			_, err = ct.clients.dst.GetService(ctx, ct.params.TestNamespace, EchoOtherNodeDeploymentHeadlessServiceName, metav1.GetOptions{})
			if err != nil {
				ct.Logf("✨ [%s] Deploying %s service...", ct.clients.dst.ClusterName(), EchoOtherNodeDeploymentHeadlessServiceName)
				_, err = ct.clients.dst.CreateService(ctx, ct.params.TestNamespace, svcHeadless, metav1.CreateOptions{})
				if err != nil {
					return err
				}
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
					NodeAffinity: ct.maybeNodeToNodeEncryptionAffinity(),
				},
				NodeSelector:   ct.params.NodeSelector,
				ReadinessProbe: newLocalReadinessProbe(containerPort, "/"),
				Tolerations:    ct.params.GetTolerations(),
			}, ct.params.DNSTestServerImage)
			_, err = ct.clients.dst.CreateServiceAccount(ctx, ct.params.TestNamespace, k8s.NewServiceAccount(echoOtherNodeDeploymentName), metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create service account %s: %w", echoOtherNodeDeploymentName, err)
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
					Labels:      map[string]string{"other": "host-netns"},
					Command:     []string{"/usr/bin/pause"},
					HostNetwork: true,
				})
				_, err = client.CreateDaemonSet(ctx, ct.params.TestNamespace, ds, metav1.CreateOptions{})
				if err != nil {
					return fmt.Errorf("unable to create daemonset %s: %w", hostNetNSDeploymentName, err)
				}
			}
		}
	}

	if ct.Features[features.NodeWithoutCilium].Enabled {
		_, err = ct.clients.src.GetDaemonSet(ctx, ct.params.TestNamespace, hostNetNSDeploymentNameNonCilium, metav1.GetOptions{})
		if err != nil {
			ct.Logf("✨ [%s] Deploying %s daemonset...", hostNetNSDeploymentNameNonCilium, ct.clients.src.ClusterName())
			ds := newDaemonSet(daemonSetParameters{
				Name:        hostNetNSDeploymentNameNonCilium,
				Kind:        kindHostNetNS,
				Image:       ct.params.CurlImage,
				Labels:      map[string]string{"other": "host-netns"},
				Command:     []string{"/usr/bin/pause"},
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

		_, err = ct.clients.src.GetDeployment(ctx, ct.params.TestNamespace, echoExternalNodeDeploymentName, metav1.GetOptions{})
		if err != nil {
			ct.Logf("✨ [%s] Deploying echo-external-node deployment...", ct.clients.src.ClusterName())
			// in case if test concurrency is > 1 port must be unique for each test namespace
			port := ct.Params().ExternalDeploymentPort
			echoExternalDeployment := newDeployment(deploymentParameters{
				Name:           echoExternalNodeDeploymentName,
				Kind:           kindEchoExternalNodeName,
				Port:           port,
				NamedPort:      fmt.Sprintf("http-%d", port),
				HostPort:       port,
				Image:          ct.params.JSONMockImage,
				Labels:         map[string]string{"external": "echo"},
				Annotations:    ct.params.DeploymentAnnotations.Match(echoExternalNodeDeploymentName),
				NodeSelector:   map[string]string{"cilium.io/no-schedule": "true"},
				ReadinessProbe: newLocalReadinessProbe(port, "/"),
				HostNetwork:    true,
				Tolerations: append(
					[]corev1.Toleration{
						{Operator: corev1.TolerationOpExists},
					},
					ct.params.GetTolerations()...,
				),
			})
			_, err = ct.clients.src.CreateServiceAccount(ctx, ct.params.TestNamespace, k8s.NewServiceAccount(echoExternalNodeDeploymentName), metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create service account %s: %w", echoExternalNodeDeploymentName, err)
			}
			_, err = ct.clients.src.CreateDeployment(ctx, ct.params.TestNamespace, echoExternalDeployment, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create deployment %s: %w", echoExternalNodeDeploymentName, err)
			}

			svc := newService(echoExternalNodeDeploymentName,
				map[string]string{"name": echoExternalNodeDeploymentName, "kind": kindEchoExternalNodeName},
				map[string]string{"kind": kindEchoExternalNodeName}, "http", port, "ClusterIP")
			svc.Spec.ClusterIP = corev1.ClusterIPNone
			_, err := ct.clients.src.CreateService(ctx, ct.params.TestNamespace, svc, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create service %s: %w", echoExternalNodeDeploymentName, err)
			}
		}
	} else {
		ct.Infof("Skipping tests that require a node Without Cilium")
	}

	// Create one Ingress service for echo deployment
	if ct.Features[features.IngressController].Enabled {
		for name, backend := range ct.ingresses() {
			_, err = ct.clients.src.GetIngress(ctx, ct.params.TestNamespace, name, metav1.GetOptions{})
			if err != nil {
				ct.Logf("✨ [%s] Deploying Ingress resource...", ct.clients.src.ClusterName())
				_, err = ct.clients.src.CreateIngress(ctx, ct.params.TestNamespace, newIngress(name, backend), metav1.CreateOptions{})
				if err != nil {
					return err
				}
			}
		}
	}

	if ct.Features[features.CCNP].Enabled {
		ct.Logf("✨ [%s] Deploying ccnp deployment...", ct.clients.src.ClusterName())
		ct.deployCCNPTestEnv(ctx)
	}

	if ct.Features[features.LocalRedirectPolicy].Enabled {
		ct.Logf("✨ [%s] Deploying lrp-client deployment...", ct.clients.src.ClusterName())
		lrpClientDeployment := newDeployment(deploymentParameters{
			Name:         lrpClientDeploymentName,
			Kind:         kindLrpName,
			Image:        ct.params.CurlImage,
			Command:      []string{"/usr/bin/pause"},
			Labels:       map[string]string{"lrp": "client"},
			Annotations:  ct.params.DeploymentAnnotations.Match(lrpClientDeploymentName),
			NodeSelector: ct.params.NodeSelector,
			Tolerations:  ct.params.GetTolerations(),
		})

		_, err = ct.clients.src.GetServiceAccount(ctx, ct.params.TestNamespace, lrpClientDeploymentName, metav1.GetOptions{})
		if err != nil {
			_, err = ct.clients.src.CreateServiceAccount(ctx, ct.params.TestNamespace, k8s.NewServiceAccount(lrpClientDeploymentName), metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create service account %s: %w", lrpClientDeployment, err)
			}
		}

		_, err = ct.clients.src.GetDeployment(ctx, ct.params.TestNamespace, lrpClientDeploymentName, metav1.GetOptions{})
		if err != nil {
			_, err = ct.clients.src.CreateDeployment(ctx, ct.params.TestNamespace, lrpClientDeployment, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create deployment %s: %w", lrpClientDeployment, err)
			}
		}

		ct.Logf("✨ [%s] Deploying lrp-backend deployment...", ct.clients.src.ClusterName())
		containerPort := 8080
		lrpBackendDeployment := newDeployment(deploymentParameters{
			Name:           lrpBackendDeploymentName,
			Kind:           kindLrpName,
			Image:          ct.params.JSONMockImage,
			NamedPort:      "tcp-8080",
			Port:           containerPort,
			ReadinessProbe: newLocalReadinessProbe(containerPort, "/"),
			Labels:         map[string]string{"lrp": "backend"},
			Annotations:    ct.params.DeploymentAnnotations.Match(lrpBackendDeploymentName),
			Affinity: &corev1.Affinity{
				PodAffinity: &corev1.PodAffinity{
					RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
						{
							LabelSelector: &metav1.LabelSelector{
								MatchExpressions: []metav1.LabelSelectorRequirement{
									{Key: "name", Operator: metav1.LabelSelectorOpIn, Values: []string{lrpClientDeploymentName}},
								},
							},
							TopologyKey: corev1.LabelHostname,
						},
					},
				},
			},
			NodeSelector: ct.params.NodeSelector,
			Tolerations:  ct.params.GetTolerations(),
		})

		_, err = ct.clients.src.GetServiceAccount(ctx, ct.params.TestNamespace, lrpBackendDeploymentName, metav1.GetOptions{})
		if err != nil {
			_, err = ct.clients.src.CreateServiceAccount(ctx, ct.params.TestNamespace, k8s.NewServiceAccount(lrpBackendDeploymentName), metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create service account %s: %w", lrpBackendDeployment, err)
			}
		}

		_, err = ct.clients.src.GetDeployment(ctx, ct.params.TestNamespace, lrpBackendDeploymentName, metav1.GetOptions{})
		if err != nil {
			_, err = ct.clients.src.CreateDeployment(ctx, ct.params.TestNamespace, lrpBackendDeployment, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create deployment %s: %w", lrpBackendDeployment, err)
			}
		}
	}

	if ct.Features[features.BGPControlPlane].Enabled && ct.Features[features.NodeWithoutCilium].Enabled && ct.params.TestConcurrency == 1 {
		// BGP tests need to run sequentially, deploy only if BGP CP is enabled and test concurrency is disabled
		_, err = ct.clients.src.GetDaemonSet(ctx, ct.params.TestNamespace, frrDaemonSetNameName, metav1.GetOptions{})
		if err != nil {
			ct.Logf("✨ [%s] Deploying %s daemonset...", ct.clients.src.ClusterName(), frrDaemonSetNameName)
			ds := NewFRRDaemonSet(ct.params)
			_, err = ct.clients.src.CreateDaemonSet(ctx, ct.params.TestNamespace, ds, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create daemonset %s: %w", frrDaemonSetNameName, err)
			}
			_, err = ct.clients.src.GetConfigMap(ctx, ct.params.TestNamespace, frrConfigMapName, metav1.GetOptions{})
			if err != nil {
				cm := NewFRRConfigMap()
				ct.Logf("✨ [%s] Deploying %s configmap...", ct.clients.dst.ClusterName(), cm.Name)
				_, err = ct.clients.dst.CreateConfigMap(ctx, ct.params.TestNamespace, cm, metav1.CreateOptions{})
				if err != nil {
					return fmt.Errorf("unable to create configmap %s: %w", cm.Name, err)
				}
			}
		}
	}

	if ct.Features[features.Multicast].Enabled {
		_, err = ct.clients.src.GetDeployment(ctx, ct.params.TestNamespace, socatClientDeploymentName, metav1.GetOptions{})
		if err != nil {
			ct.Logf("✨ [%s] Deploying %s deployment...", ct.clients.src.ClusterName(), socatClientDeploymentName)
			ds := NewSocatClientDeployment(ct.params)
			_, err = ct.clients.src.CreateServiceAccount(ctx, ct.params.TestNamespace, k8s.NewServiceAccount(socatClientDeploymentName), metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create service account %s: %w", socatClientDeploymentName, err)
			}
			_, err = ct.clients.src.CreateDeployment(ctx, ct.params.TestNamespace, ds, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create deployment %s: %w", socatClientDeploymentName, err)
			}
		}
	}

	if ct.Features[features.Multicast].Enabled {
		_, err = ct.clients.src.GetDaemonSet(ctx, ct.params.TestNamespace, socatServerDaemonsetName, metav1.GetOptions{})
		if err != nil {
			ct.Logf("✨ [%s] Deploying %s daemonset...", ct.clients.src.ClusterName(), socatServerDaemonsetName)
			ds := NewSocatServerDaemonSet(ct.params)
			_, err = ct.clients.src.CreateDaemonSet(ctx, ct.params.TestNamespace, ds, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create daemonset %s: %w", socatServerDaemonsetName, err)
			}
		}
	}

	if ct.Features[features.L7LoadBalancer].Enabled {
		_, err = ct.clients.src.GetDeployment(ctx, ct.params.TestNamespace, loadbalancerL7DeploymentName, metav1.GetOptions{})
		if err != nil {
			ct.Logf("✨ [%s] Deploying same-node deployment...", ct.clients.src.ClusterName())
			containerPort := 8080
			l7lbDeployment := newDeploymentWithDNSTestServer(deploymentParameters{
				Name:  loadbalancerL7DeploymentName,
				Kind:  kindL7LBName,
				Image: ct.params.EchoImage,
				Args: []string{
					"--tcp=9090", "--port=8080", "--grpc=7070", "--port=8443", "--tls=8443", "--crt=/cert.crt", "--key=/cert.key",
				},
				Labels: map[string]string{"kind": "l7-lb"},
				Affinity: &corev1.Affinity{
					PodAffinity: &corev1.PodAffinity{
						RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
							{
								LabelSelector: &metav1.LabelSelector{
									MatchExpressions: []metav1.LabelSelectorRequirement{
										{Key: "name", Operator: metav1.LabelSelectorOpIn, Values: []string{loadbalancerL7DeploymentName}},
									},
								},
								TopologyKey: corev1.LabelHostname,
							},
						},
					},
					NodeAffinity: ct.maybeNodeToNodeEncryptionAffinity(),
				},
				ReadinessProbe: newLocalReadinessProbe(containerPort, "/"),
				Tolerations:    ct.params.GetTolerations(),
			}, ct.params.DNSTestServerImage)
			_, err = ct.clients.src.CreateServiceAccount(ctx, ct.params.TestNamespace, k8s.NewServiceAccount(loadbalancerL7DeploymentName), metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create service account %s: %w", loadbalancerL7DeploymentName, err)
			}
			_, err = ct.clients.src.CreateDeployment(ctx, ct.params.TestNamespace, l7lbDeployment, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create deployment %s: %w", loadbalancerL7DeploymentName, err)
			}
		}

		_, err = ct.clients.dst.GetService(ctx, ct.params.TestNamespace, loadbalancerL7DeploymentName, metav1.GetOptions{})
		if err != nil {
			ct.Logf("✨ [%s] Deploying %s service...", ct.clients.dst.ClusterName(), loadbalancerL7DeploymentName)
			svc := newService(
				loadbalancerL7DeploymentName,
				map[string]string{"name": loadbalancerL7DeploymentName},
				map[string]string{"name": loadbalancerL7DeploymentName, "kind": kindL7LBName},
				"http",
				8080,
				ct.Params().ServiceType)

			svc.ObjectMeta.Annotations = map[string]string{
				"service.cilium.io/lb-l7": "enabled",
			}
			_, err = ct.clients.dst.CreateService(ctx, ct.params.TestNamespace, svc, metav1.CreateOptions{})
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (ct *ConnectivityTest) DeleteCCNPTestEnv(ctx context.Context, client *k8s.Client) error {
	namespaces := []string{"cilium-test-ccnp1", "cilium-test-ccnp2"}

	for _, ns := range namespaces {
		_, err := client.GetDeployment(ctx, ns, ccnpDeploymentName, metav1.GetOptions{})
		if err == nil {
			ct.Logf("🔥 [%s] Deleting ccnp deployment in %s ns...", client.ClusterName(), ns)
			_ = client.DeleteDeployment(ctx, ns, ccnpDeploymentName, metav1.DeleteOptions{})
		}

		_, err = client.GetNamespace(ctx, ns, metav1.GetOptions{})
		if err == nil {
			ct.Logf("⌛ [%s] Waiting for namespace %s to disappear", client.ClusterName(), ns)
			for err == nil {
				time.Sleep(time.Second)
				// Retry the namespace deletion in-case the previous delete was
				// rejected, i.e. by yahoo/k8s-namespace-guard
				_ = client.DeleteNamespace(ctx, ns, metav1.DeleteOptions{})
				_, err = client.GetNamespace(ctx, ns, metav1.GetOptions{})
			}
		}
	}

	return nil
}

func (ct *ConnectivityTest) patchDeployment(ctx context.Context) error {
	if ct.Params().ExternalTargetCAName != "cabundle" && ct.Params().ExternalTargetCANamespace != ct.Params().TestNamespace {
		caSecret, err := ct.client.GetSecret(ctx, ct.Params().ExternalTargetCANamespace, ct.Params().ExternalTargetCAName, metav1.GetOptions{})
		if err != nil {
			return fmt.Errorf("unable to get CA secret %s/%s: %w", ct.Params().ExternalTargetCANamespace, ct.Params().ExternalTargetCAName, err)
		}
		ct.Logf("✨ [%s] Adding %s external target CA to client root CAs...", ct.clients.src.ClusterName(), caSecret.Name)

		cert, found := caSecret.Data["ca.crt"]
		if !found {
			return fmt.Errorf("unable to find ca.crt in secret %s", ct.Params().ExternalTargetCAName)
		}
		encodedCert := base64.StdEncoding.EncodeToString(cert)

		clientPods, err := ct.client.ListPods(ctx, ct.params.TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + kindClientName})
		if err != nil {
			return fmt.Errorf("unable to list client pods: %w", err)
		}

		for _, pod := range clientPods.Items {
			_, err := ct.client.ExecInPod(ctx, ct.params.TestNamespace, pod.Name, pod.Spec.Containers[0].Name,
				[]string{"sh", "-c", fmt.Sprintf("echo %s | base64 -d >> /etc/ssl/certs/ca-certificates.crt", encodedCert)})
			if err != nil {
				return fmt.Errorf("unable to add CA to pod %s: %w", pod.Name, err)
			}
		}
	}

	return nil
}

func (ct *ConnectivityTest) createTestConnDisruptServerDeployAndSvc(ctx context.Context, deployName, kind string, replicas int, svcName, appLabel string,
	isExternal bool, cnpFunc func(ns string) *ciliumv2.CiliumNetworkPolicy, protocol string,
) error {
	command := []string{"tcd-server", "8000"}
	if len(protocol) != 0 {
		command = []string{"tcd-server", "--protocol", protocol, "8000"}
	}

	_, err := ct.clients.src.GetDeployment(ctx, ct.params.TestNamespace, deployName, metav1.GetOptions{})
	if err != nil {
		ct.Logf("✨ [%s] Deploying %s deployment...", ct.clients.src.ClusterName(), deployName)
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
		param := deploymentParameters{
			Name:           deployName,
			Kind:           kind,
			Image:          ct.params.TestConnDisruptImage,
			Replicas:       replicas,
			Labels:         map[string]string{"app": appLabel},
			Command:        command,
			Port:           8000,
			ReadinessProbe: readinessProbe,
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceCPU: *resource.NewMilliQuantity(100, resource.DecimalSI)},
			},
			Tolerations: ct.params.GetTolerations(),
		}
		if isExternal {
			param.NodeSelector = map[string]string{defaults.CiliumNoScheduleLabel: "true"}
			param.HostNetwork = true
			param.Tolerations = append(param.Tolerations, corev1.Toleration{
				Operator: corev1.TolerationOpExists,
			})
		}
		testConnDisruptServerDeployment := newDeployment(param)
		_, err = ct.clients.src.CreateServiceAccount(ctx, ct.params.TestNamespace, k8s.NewServiceAccount(deployName), metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create service account %s: %w", deployName, err)
		}
		_, err = ct.clients.src.CreateDeployment(ctx, ct.params.TestNamespace, testConnDisruptServerDeployment, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create deployment %s: %w", testConnDisruptServerDeployment, err)
		}
	}

	// Make sure that the server deployment is ready to spread client connections
	err = WaitForDeployment(ctx, ct, ct.clients.src, ct.params.TestNamespace, deployName)
	if err != nil {
		ct.Failf("%s deployment is not ready: %s", deployName, err)
	}

	for _, client := range ct.Clients() {
		_, err = client.GetService(ctx, ct.params.TestNamespace, svcName, metav1.GetOptions{})
		if err != nil {
			ct.Logf("✨ [%s] Deploying %s service...", client.ClusterName(), svcName)
			svc := newService(svcName, map[string]string{"app": appLabel}, nil, "http", 8000, ct.Params().ServiceType)
			svc.ObjectMeta.Annotations = map[string]string{"service.cilium.io/global": "true"}
			_, err = client.CreateService(ctx, ct.params.TestNamespace, svc, metav1.CreateOptions{})
			if err != nil {
				return fmt.Errorf("unable to create service %s: %w", svcName, err)
			}
		}

		if enabled, _ := ct.Features.MatchRequirements(features.RequireEnabled(features.CNP)); enabled {
			ipsec, _ := ct.Features.MatchRequirements(features.RequireMode(features.EncryptionPod, "ipsec"))
			if ipsec && versioncheck.MustCompile("<1.16.0")(ct.CiliumVersion) {
				// https://github.com/cilium/cilium/issues/36681
				continue
			}
			for _, client := range ct.Clients() {
				cnp := cnpFunc(ct.params.TestNamespace)
				ct.Logf("✨ [%s] Deploying %s CiliumNetworkPolicy...", client.ClusterName(), cnp.Name)
				_, err = client.ApplyGeneric(ctx, cnp)
				if err != nil {
					return fmt.Errorf("unable to create CiliumNetworkPolicy %s: %w", cnp.Name, err)
				}
			}
		}
	}

	return err
}

func (ct *ConnectivityTest) createTestConnDisruptClientDeployment(ctx context.Context, deployName, kind, appLabel, address string, replicas int, isExternal bool, nodeSelector map[string]string, protocol string) error {
	command := []string{
		"tcd-client",
		"--dispatch-interval", ct.params.ConnDisruptDispatchInterval.String(),
	}
	if len(protocol) != 0 {
		command = append(command, "--protocol", protocol)
	}

	_, err := ct.clients.dst.GetDeployment(ctx, ct.params.TestNamespace, deployName, metav1.GetOptions{})
	if err != nil {
		ct.Logf("✨ [%s] Deploying %s deployment...", ct.clients.dst.ClusterName(), deployName)
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

		param := deploymentParameters{
			Name:     deployName,
			Kind:     kind,
			Image:    ct.params.TestConnDisruptImage,
			Replicas: replicas,
			Labels:   map[string]string{"app": appLabel},
			Command:  append(command, address),

			ReadinessProbe: readinessProbe,
			Resources: corev1.ResourceRequirements{
				Requests: corev1.ResourceList{corev1.ResourceCPU: *resource.NewMilliQuantity(100, resource.DecimalSI)},
			},
			Tolerations: ct.params.GetTolerations(),
		}
		if isExternal {
			param.NodeSelector = map[string]string{defaults.CiliumNoScheduleLabel: "true"}
			param.HostNetwork = true
			param.Tolerations = append(param.Tolerations, corev1.Toleration{
				Operator: corev1.TolerationOpExists,
			})
		}
		if nodeSelector != nil {
			param.NodeSelector = nodeSelector
		}
		testConnDisruptClientDeployment := newDeployment(param)

		_, err = ct.clients.dst.CreateServiceAccount(ctx, ct.params.TestNamespace, k8s.NewServiceAccount(deployName), metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create service account %s: %w", deployName, err)
		}
		_, err = ct.clients.dst.CreateDeployment(ctx, ct.params.TestNamespace, testConnDisruptClientDeployment, metav1.CreateOptions{})
		if err != nil {
			return fmt.Errorf("unable to create deployment %s: %w", testConnDisruptClientDeployment, err)
		}
	}

	return err
}

func (ct *ConnectivityTest) createTestConnDisruptClientDeploymentForNSTraffic(ctx context.Context) error {
	nodes, err := ct.getBackendNodeAndNonBackendNode(ctx)
	if err != nil {
		return err
	}

	for _, n := range nodes {
		for _, client := range ct.Clients() {
			svc, err := client.GetService(ctx, ct.params.TestNamespace, testConnDisruptNSTrafficServiceName, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("unable to get service %s: %w", testConnDisruptNSTrafficServiceName, err)
			}

			var errs error
			np := uint16(svc.Spec.Ports[0].NodePort)
			addrs := slices.Clone(n.node.Status.Addresses)
			ct.ForEachIPFamily(func(family features.IPFamily) {
				for _, addr := range addrs {
					if features.GetIPFamily(addr.Address) != family {
						continue
					}

					// On GKE ExternalIP is not reachable from inside a cluster
					if addr.Type == slimcorev1.NodeExternalIP {
						if f, ok := ct.Feature(features.Flavor); ok && f.Enabled && f.Mode == "gke" {
							continue
						}
					}

					deployName := fmt.Sprintf("%s-%s-%s-%s", testConnDisruptClientNSTrafficDeploymentName, n.nodeType, family, strings.ToLower(string(addr.Type)))
					if err := ct.createTestConnDisruptClientDeployment(ctx,
						deployName,
						KindTestConnDisruptNSTraffic,
						fmt.Sprintf("test-conn-disrupt-client-%s-%s-%s", n.nodeType, family, strings.ToLower(string(addr.Type))),
						netip.AddrPortFrom(netip.MustParseAddr(addr.Address), np).String(),
						1, true, nil, ""); err != nil {
						errs = errors.Join(errs, err)
					}
					ct.testConnDisruptClientNSTrafficDeploymentNames = append(ct.testConnDisruptClientNSTrafficDeploymentNames, deployName)
				}
			})
			if errs != nil {
				return errs
			}
		}
	}

	return err
}

type nodeWithType struct {
	nodeType string
	node     *slimcorev1.Node
}

func (ct *ConnectivityTest) getBackendNodeAndNonBackendNode(ctx context.Context) ([]nodeWithType, error) {
	appLabel := fmt.Sprintf("app=%s", testConnDisruptServerNSTrafficAppLabel)
	podList, err := ct.clients.src.ListPods(ctx, ct.params.TestNamespace, metav1.ListOptions{LabelSelector: appLabel})
	if err != nil {
		return nil, fmt.Errorf("unable to list pods with lable %s: %w", appLabel, err)
	}

	pod := podList.Items[0]

	var nodes []nodeWithType
	nodes = append(nodes, nodeWithType{
		nodeType: "backend-node",
		node:     ct.nodes[pod.Spec.NodeName],
	})
	for name, node := range ct.Nodes() {
		if name != pod.Spec.NodeName {
			nodes = append(nodes, nodeWithType{
				nodeType: "non-backend-node",
				node:     node,
			})
			break
		}
	}

	return nodes, err
}

func (ct *ConnectivityTest) getGatewayAndNonGatewayNodes() (string, string, error) {
	var workerNodes []string
	for _, node := range ct.nodes {
		if _, found := ct.controlPlaneNodes[node.Name]; !found {
			workerNodes = append(workerNodes, node.Name)
		}
	}
	if len(workerNodes) < 2 {
		return "", "", fmt.Errorf("unable to pick gateway and non gateway nodes")
	}
	slices.Sort(workerNodes)

	return workerNodes[0], workerNodes[1], nil
}

func (ct *ConnectivityTest) GetGatewayNodeInternalIP(egressGatewayNode string, ipv6 bool) netip.Addr {
	gatewayNode, ok := ct.Nodes()[egressGatewayNode]
	if !ok {
		return netip.Addr{}
	}

	for _, addr := range gatewayNode.Status.Addresses {
		if addr.Type != slimcorev1.NodeInternalIP {
			continue
		}

		ip, err := netip.ParseAddr(addr.Address)
		if err != nil {
			continue
		}

		unMappedIp := ip.Unmap()
		if unMappedIp.Is6() == ipv6 {
			return unMappedIp
		}
	}

	return netip.Addr{}
}

func (ct *ConnectivityTest) getConnDisruptClientEgressGatewayPodIPs(ctx context.Context) ([]string, error) {
	var appLabels []string
	appLabels = append(appLabels, fmt.Sprintf("app=%s", testConnDisruptClientEgressGatewayOnGatewayNodeAppLabel))
	appLabels = append(appLabels, fmt.Sprintf("app=%s", testConnDisruptClientEgressGatewayOnNonGatewayNodeAppLabel))

	var podIPs []string
	for _, appLabel := range appLabels {
		connDisruptPods, err := ct.K8sClient().ListPods(ctx, ct.Params().TestNamespace, metav1.ListOptions{LabelSelector: appLabel})
		if err != nil {
			return nil, fmt.Errorf("unable to list pods with lable %s: %w", appLabel, err)
		}

		for _, connDisruptPod := range connDisruptPods.Items {
			podIPs = append(podIPs, connDisruptPod.Status.PodIP)
		}
	}

	return podIPs, nil
}

func (ct *ConnectivityTest) GetConnDisruptEgressPolicyEntries(ctx context.Context, ciliumPod Pod) ([]BPFEgressGatewayPolicyEntry, error) {
	var targetEntries []BPFEgressGatewayPolicyEntry

	podIPs, err := ct.getConnDisruptClientEgressGatewayPodIPs(ctx)
	if err != nil {
		return nil, err
	}

	gatewayNode, _, err := ct.getGatewayAndNonGatewayNodes()
	if err != nil {
		return nil, err
	}

	gatewayIP := ct.GetGatewayNodeInternalIP(gatewayNode, false)
	if !gatewayIP.IsValid() {
		return nil, nil
	}

	egressIP := "0.0.0.0"
	if ciliumPod.Pod.Spec.NodeName == gatewayNode {
		egressIP = gatewayIP.String()
	}

	for _, podIP := range podIPs {
		targetEntries = append(targetEntries,
			BPFEgressGatewayPolicyEntry{
				SourceIP:  podIP,
				DestCIDR:  "0.0.0.0/0",
				EgressIP:  egressIP,
				GatewayIP: gatewayIP.String(),
			})
	}

	return targetEntries, nil
}

func (ct *ConnectivityTest) createClientPerfDeployment(ctx context.Context, name string, nodeName string, hostNetwork bool) error {
	ct.Logf("✨ [%s] Deploying %s deployment...", ct.clients.src.ClusterName(), name)
	gracePeriod := int64(1)
	perfClientDeployment := newDeployment(deploymentParameters{
		Name:  name,
		Kind:  kindPerfName,
		Image: ct.params.PerfParameters.Image,
		Labels: map[string]string{
			perfPodRoleKey: string(perfPodRoleClient),
		},
		Annotations:                   ct.params.DeploymentAnnotations.Match(name),
		Command:                       []string{"/bin/bash", "-c", "sleep 10000000"},
		NodeSelector:                  map[string]string{"kubernetes.io/hostname": nodeName},
		HostNetwork:                   hostNetwork,
		TerminationGracePeriodSeconds: &gracePeriod,
		Tolerations:                   ct.params.GetTolerations(),
	})
	_, err := ct.clients.src.CreateServiceAccount(ctx, ct.params.TestNamespace, k8s.NewServiceAccount(name), metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("unable to create service account %s: %w", name, err)
	}
	_, err = ct.clients.src.CreateDeployment(ctx, ct.params.TestNamespace, perfClientDeployment, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("unable to create deployment %s: %w", perfClientDeployment, err)
	}
	return nil
}

func (ct *ConnectivityTest) createServerPerfDeployment(ctx context.Context, name, nodeName string, hostNetwork bool) error {
	ct.Logf("✨ [%s] Deploying %s deployment...", ct.clients.src.ClusterName(), name)
	gracePeriod := int64(1)
	perfServerDeployment := newDeployment(deploymentParameters{
		Name: name,
		Kind: kindPerfName,
		Labels: map[string]string{
			perfPodRoleKey: string(perfPodRoleServer),
		},
		Annotations:                   ct.params.DeploymentAnnotations.Match(name),
		Port:                          12865,
		NamedPort:                     "netserver-ctrl",
		Image:                         ct.params.PerfParameters.Image,
		Command:                       []string{"netserver", "-D"},
		NodeSelector:                  map[string]string{"kubernetes.io/hostname": nodeName},
		HostNetwork:                   hostNetwork,
		TerminationGracePeriodSeconds: &gracePeriod,
		Tolerations:                   ct.params.GetTolerations(),
	})
	_, err := ct.clients.src.CreateServiceAccount(ctx, ct.params.TestNamespace, k8s.NewServiceAccount(name), metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("unable to create service account %s: %w", name, err)
	}

	_, err = ct.clients.src.CreateDeployment(ctx, ct.params.TestNamespace, perfServerDeployment, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("unable to create deployment %s: %w", perfServerDeployment, err)
	}
	return nil
}

func (ct *ConnectivityTest) createProfilingPerfDeployment(ctx context.Context, name, nodeName string) error {
	ct.Logf("✨ [%s] Deploying %s deployment...", ct.clients.src.ClusterName(), name)

	labels := map[string]string{
		"name":         name,
		"kind":         kindPerfName,
		perfPodRoleKey: string(perfPodRoleProfiling),
	}

	_, err := ct.clients.src.CreateDeployment(ctx, ct.params.TestNamespace, &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: labels},
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{{
						Name:            "init",
						Image:           ct.params.PerfParameters.Image,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Command:         []string{"nsenter", "--target=1", "--mount", "--", "bash", "-e", "-c", "$(SCRIPT)"},
						Env: []corev1.EnvVar{{
							Name: "SCRIPT",
							Value: `
							if command -v perf 2>&1 >/dev/null; then
								echo "Nice, perf appears to be already installed"
							elif command -v apt 2>&1 >/dev/null; then
								echo "Attempting to install perf with apt"
								apt update && apt install -y linux-perf
							elif command -v yum 2>&1 >/dev/null; then
								echo "Attempting to install perf with dnf"
								dnf install -y perf
							else
								echo "Could not install perf using attempted package managers."
								exit 1
							fi
							`,
						}},
						SecurityContext: &corev1.SecurityContext{Privileged: ptr.To(true)},
					}},
					Containers: []corev1.Container{{
						Name:            "profiler",
						Image:           ct.params.PerfParameters.Image,
						ImagePullPolicy: corev1.PullIfNotPresent,
						Command:         []string{"/bin/sleep", "infinity"},
						SecurityContext: &corev1.SecurityContext{Privileged: ptr.To(true)},
					}},
					HostNetwork: true,
					HostPID:     true,
					NodeName:    nodeName,
					Tolerations: ct.params.GetTolerations(),
				},
			},
			Replicas: ptr.To[int32](1),
			Selector: &metav1.LabelSelector{MatchLabels: labels},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("unable to create deployment %s: %w", name, err)
	}
	return nil
}

func (ct *ConnectivityTest) deployPerf(ctx context.Context) error {
	if err := ct.deployNamespace(ctx); err != nil {
		return err
	}

	nodeSelectorServer := labels.SelectorFromSet(ct.params.PerfParameters.NodeSelectorServer).String()
	nodeSelectorClient := labels.SelectorFromSet(ct.params.PerfParameters.NodeSelectorClient).String()

	serverNodes, err := ct.client.ListNodes(ctx, metav1.ListOptions{LabelSelector: nodeSelectorServer, Limit: 2})
	if err != nil {
		return fmt.Errorf("unable to query nodes with selector %s", nodeSelectorServer)
	}

	clientNodes, err := ct.client.ListNodes(ctx, metav1.ListOptions{LabelSelector: nodeSelectorClient, Limit: 2})
	if err != nil {
		return fmt.Errorf("unable to query nodes with selector %s", nodeSelectorClient)
	}

	var serverNode, clientNode corev1.Node
	switch {
	case len(serverNodes.Items) >= 1 && len(clientNodes.Items) >= 1 && serverNodes.Items[0].Name != clientNodes.Items[0].Name:
		serverNode, clientNode = serverNodes.Items[0], clientNodes.Items[0]
	case len(serverNodes.Items) >= 1 && len(clientNodes.Items) >= 2:
		serverNode, clientNode = serverNodes.Items[0], clientNodes.Items[1]
	case len(serverNodes.Items) >= 2 && len(clientNodes.Items) >= 1:
		serverNode, clientNode = serverNodes.Items[1], clientNodes.Items[0]
	default:
		return fmt.Errorf("Insufficient number of nodes selected with selectors: %s, %s", nodeSelectorServer, nodeSelectorClient)
	}

	ct.Info("Nodes used for performance testing:")
	ct.Infof("* Node name: %s, zone: %s", serverNode.Name, serverNode.Labels[corev1.LabelTopologyZone])
	ct.Infof("* Node name: %s, zone: %s", clientNode.Name, clientNode.Labels[corev1.LabelTopologyZone])
	if serverNode.Labels[corev1.LabelTopologyZone] != clientNode.Labels[corev1.LabelTopologyZone] {
		ct.Warn("Selected nodes have different zones, tweak nodeSelector if that's not what you intended")
	}

	if ct.params.PerfParameters.NetQos {
		// Disable host net deploys
		ct.params.PerfParameters.HostNet = false

		// TODO: Merge with existing annotations
		lowPrioDeployAnnotations := annotations{bwPrioAnnotationString: "5"}
		highPrioDeployAnnotations := annotations{bwPrioAnnotationString: "6"}

		ct.params.DeploymentAnnotations.Set(`{
				"` + perClientLowPriorityDeploymentName + `": ` + lowPrioDeployAnnotations.String() + `,
			    "` + perClientHighPriorityDeploymentName + `": ` + highPrioDeployAnnotations.String() + `
			}`)
		if err = ct.createServerPerfDeployment(ctx, perfServerDeploymentName, serverNode.Name, false); err != nil {
			ct.Warnf("unable to create deployment: %s", err)
		}
		// Create low priority client on other node
		if err = ct.createClientPerfDeployment(ctx, perClientLowPriorityDeploymentName, clientNode.Name, false); err != nil {
			ct.Warnf("unable to create deployment: %s", err)
		}
		// Create high priority client on other node
		if err = ct.createClientPerfDeployment(ctx, perClientHighPriorityDeploymentName, clientNode.Name, false); err != nil {
			ct.Warnf("unable to create deployment: %s", err)
		}

		return nil
	}

	if ct.params.PerfParameters.Bandwidth {
		ct.params.PerfParameters.PodNet = false
		ct.params.PerfParameters.HostNet = false
		ct.params.PerfParameters.SameNode = false
		ct.params.PerfParameters.OtherNode = false

		egressBandwidthAnnotations := annotations{egressBandwidth: "10M"}
		ingressBandwidthAnnotations := annotations{ingressBandwidth: "10M"}
		ct.params.DeploymentAnnotations.Set(`{
				"` + perClientEgressDeploymentName + `": ` + egressBandwidthAnnotations.String() + `,
			    "` + perServerIngressDeploymentName + `": ` + ingressBandwidthAnnotations.String() + `
			}`)
		if err = ct.createServerPerfDeployment(ctx, perServerEgressDeploymentName, serverNode.Name, false); err != nil {
			ct.Warnf("unable to create server deployment %s (egress): %s", perServerEgressDeploymentName, err)
		}
		if err = ct.createServerPerfDeployment(ctx, perServerIngressDeploymentName, serverNode.Name, false); err != nil {
			ct.Warnf("unable to create server deployment %s (ingress): %s", perServerIngressDeploymentName, err)
		}
		if err = ct.createClientPerfDeployment(ctx, perClientEgressDeploymentName, clientNode.Name, false); err != nil {
			ct.Warnf("unable to create client deployment %s (egress): %s", perClientEgressDeploymentName, err)
		}
		if err = ct.createClientPerfDeployment(ctx, perClientIngressDeploymentName, clientNode.Name, false); err != nil {
			ct.Warnf("unable to create client deployment %s (ingress): %s", perClientIngressDeploymentName, err)
		}
	}

	if ct.params.PerfParameters.PodNet || ct.params.PerfParameters.PodToHost {
		if ct.params.PerfParameters.SameNode {
			if err = ct.createClientPerfDeployment(ctx, perfClientDeploymentName, serverNode.Name, false); err != nil {
				ct.Warnf("unable to create deployment: %s", err)
			}
		}

		if ct.params.PerfParameters.OtherNode {
			// Create second client on other node
			if err = ct.createClientPerfDeployment(ctx, perfClientAcrossDeploymentName, clientNode.Name, false); err != nil {
				ct.Warnf("unable to create deployment: %s", err)
			}
		}
	}

	if ct.params.PerfParameters.PodNet || ct.params.PerfParameters.HostToPod {
		if err = ct.createServerPerfDeployment(ctx, perfServerDeploymentName, serverNode.Name, false); err != nil {
			ct.Warnf("unable to create deployment: %s", err)
		}
	}

	if ct.params.PerfParameters.HostNet || ct.params.PerfParameters.HostToPod {
		if ct.params.PerfParameters.SameNode {
			if err = ct.createClientPerfDeployment(ctx, perfClientHostNetDeploymentName, serverNode.Name, true); err != nil {
				ct.Warnf("unable to create deployment: %s", err)
			}
		}

		if ct.params.PerfParameters.OtherNode {
			// Create second client on other node
			if err = ct.createClientPerfDeployment(ctx, perfClientHostNetAcrossDeploymentName, clientNode.Name, true); err != nil {
				ct.Warnf("unable to create deployment: %s", err)
			}
		}
	}

	if ct.params.PerfParameters.HostNet || ct.params.PerfParameters.PodToHost {
		if err = ct.createServerPerfDeployment(ctx, perfServerHostNetDeploymentName, serverNode.Name, true); err != nil {
			ct.Warnf("unable to create deployment: %s", err)
		}
	}

	if ct.params.PerfParameters.KernelProfiles {
		if err = ct.createProfilingPerfDeployment(ctx, PerfServerProfilingDeploymentName, serverNode.Name); err != nil {
			ct.Warnf("unable to create deployment: %s", err)
		}

		if ct.params.PerfParameters.OtherNode {
			if err = ct.createProfilingPerfDeployment(ctx, PerfClientProfilingAcrossDeploymentName, clientNode.Name); err != nil {
				ct.Warnf("unable to create deployment: %s", err)
			}
		}
	}

	return nil
}

// deploymentListPerf returns the list of deployments required by the performance tests.
func (ct *ConnectivityTest) deploymentListPerf() (srcList []string, dstList []string) {
	if ct.params.PerfParameters.NetQos {
		srcList = append(srcList, perClientLowPriorityDeploymentName)
		srcList = append(srcList, perClientHighPriorityDeploymentName)
		srcList = append(srcList, perfServerDeploymentName)
		return srcList, dstList
	}

	if ct.params.PerfParameters.Bandwidth {
		srcList = append(srcList, perClientEgressDeploymentName)
		srcList = append(srcList, perClientIngressDeploymentName)
		srcList = append(srcList, perServerEgressDeploymentName)
		srcList = append(srcList, perServerIngressDeploymentName)
		return srcList, dstList
	}

	if ct.params.PerfParameters.PodNet || ct.params.PerfParameters.PodToHost {
		if ct.params.PerfParameters.SameNode {
			srcList = append(srcList, perfClientDeploymentName)
		}
		if ct.params.PerfParameters.OtherNode {
			srcList = append(srcList, perfClientAcrossDeploymentName)
		}
	}
	if ct.params.PerfParameters.PodNet || ct.params.PerfParameters.HostToPod {
		srcList = append(srcList, perfServerDeploymentName)
	}

	if ct.params.PerfParameters.HostNet || ct.params.PerfParameters.HostToPod {
		if ct.params.PerfParameters.SameNode {
			srcList = append(srcList, perfClientHostNetDeploymentName)
		}
		if ct.params.PerfParameters.OtherNode {
			srcList = append(srcList, perfClientHostNetAcrossDeploymentName)
		}
	}
	if ct.params.PerfParameters.HostNet || ct.params.PerfParameters.PodToHost {
		srcList = append(srcList, perfServerHostNetDeploymentName)
	}

	if ct.params.PerfParameters.KernelProfiles {
		srcList = append(srcList, PerfServerProfilingDeploymentName)
		if ct.params.PerfParameters.OtherNode {
			srcList = append(srcList, PerfClientProfilingAcrossDeploymentName)
		}
	}

	return srcList, dstList
}

// deploymentList returns 2 lists of Deployments to be used for running tests with.
func (ct *ConnectivityTest) deploymentList() (srcList []string, dstList []string) {
	srcList = []string{clientDeploymentName, client2DeploymentName, echoSameNodeDeploymentName}
	if ct.params.MultiCluster == "" && !ct.params.SingleNode {
		srcList = append(srcList, client3DeploymentName)
	}

	if ct.params.IncludeConnDisruptTest && ct.params.TestNamespaceIndex == 0 {
		// We append the server and client deployment names to two different
		// lists. This matters when running in multi-cluster mode, because
		// the server is deployed in the local cluster (targeted by the "src"
		// client), while the client in the remote one (targeted by the "dst"
		// client). When running against a single cluster, instead, this does
		// not matter much, because the two clients are identical.
		srcList = append(srcList, testConnDisruptServerDeploymentName)
		dstList = append(dstList, testConnDisruptClientDeploymentName)
		if ct.ShouldRunConnDisruptNSTraffic() {
			srcList = append(srcList, testConnDisruptServerNSTrafficDeploymentName)
			dstList = append(dstList, ct.testConnDisruptClientNSTrafficDeploymentNames...)
		}
		if ct.ShouldRunConnDisruptL7Traffic() {
			srcList = append(srcList, testConnDisruptServerL7TrafficDeploymentName)
			dstList = append(dstList, ct.testConnDisruptClientL7TrafficDeploymentNames...)
		}
		if ct.ShouldRunConnDisruptEgressGateway() {
			srcList = append(srcList, testConnDisruptServerEgressGatewayDeploymentName)
			dstList = append(dstList, testConnDisruptClientEgressGatewayOnGatewayNodeDeploymentName,
				testConnDisruptClientEgressGatewayOnNonGatewayNodeDeploymentName)
		}
	}

	if ct.params.MultiCluster != "" || !ct.params.SingleNode {
		dstList = append(dstList, echoOtherNodeDeploymentName)
	}

	if ct.Features[features.NodeWithoutCilium].Enabled {
		srcList = append(srcList, echoExternalNodeDeploymentName)
	}

	if ct.Features[features.LocalRedirectPolicy].Enabled {
		srcList = append(srcList, lrpClientDeploymentName)
		srcList = append(srcList, lrpBackendDeploymentName)
	}

	if ct.Features[features.Multicast].Enabled {
		srcList = append(srcList, socatClientDeploymentName)
	}

	return srcList, dstList
}

func (ct *ConnectivityTest) deleteDeployments(ctx context.Context, client *k8s.Client) error {
	ct.Logf("🔥 [%s] Deleting connectivity check deployments...", client.ClusterName())
	_ = client.DeleteDeployment(ctx, ct.params.TestNamespace, echoSameNodeDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteDeployment(ctx, ct.params.TestNamespace, echoOtherNodeDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteDeployment(ctx, ct.params.TestNamespace, clientDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteDeployment(ctx, ct.params.TestNamespace, client2DeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteDeployment(ctx, ct.params.TestNamespace, client3DeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteDeployment(ctx, ct.params.TestNamespace, socatClientDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteDeployment(ctx, ct.params.TestNamespace, socatServerDaemonsetName, metav1.DeleteOptions{}) // Q:Daemonset in here is OK?
	_ = client.DeleteServiceAccount(ctx, ct.params.TestNamespace, echoSameNodeDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteServiceAccount(ctx, ct.params.TestNamespace, echoOtherNodeDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteServiceAccount(ctx, ct.params.TestNamespace, clientDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteServiceAccount(ctx, ct.params.TestNamespace, client2DeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteServiceAccount(ctx, ct.params.TestNamespace, client3DeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteService(ctx, ct.params.TestNamespace, echoSameNodeDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteService(ctx, ct.params.TestNamespace, echoOtherNodeDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteService(ctx, ct.params.TestNamespace, EchoOtherNodeDeploymentHeadlessServiceName, metav1.DeleteOptions{})
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
	ct.Debugf("🔥 [%s] Deleting test-conn-disrupt deployments...", client.ClusterName())
	_ = client.DeleteDeployment(ctx, ct.params.TestNamespace, testConnDisruptClientDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteDeployment(ctx, ct.params.TestNamespace, testConnDisruptServerDeploymentName, metav1.DeleteOptions{})

	deployList, err := client.ListDeployment(ctx, ct.params.TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + KindTestConnDisruptNSTraffic})
	if err != nil {
		ct.Warnf("failed to list deployments: %s %v", KindTestConnDisruptNSTraffic, err)
	}
	for _, deploy := range deployList.Items {
		_ = client.DeleteDeployment(ctx, ct.params.TestNamespace, deploy.Name, metav1.DeleteOptions{})
		_ = client.DeleteServiceAccount(ctx, ct.params.TestNamespace, deploy.Name, metav1.DeleteOptions{})
	}

	deployList, err = client.ListDeployment(ctx, ct.params.TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + KindTestConnDisruptL7Traffic})
	if err != nil {
		ct.Warnf("failed to list deployments: %s %v", KindTestConnDisruptNSTraffic, err)
	}
	for _, deploy := range deployList.Items {
		_ = client.DeleteDeployment(ctx, ct.params.TestNamespace, deploy.Name, metav1.DeleteOptions{})
		_ = client.DeleteServiceAccount(ctx, ct.params.TestNamespace, deploy.Name, metav1.DeleteOptions{})
	}

	_ = client.DeleteDeployment(ctx, ct.params.TestNamespace, testConnDisruptServerNSTrafficDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteDeployment(ctx, ct.params.TestNamespace, testConnDisruptServerL7TrafficDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteDeployment(ctx, ct.params.TestNamespace, testConnDisruptClientEgressGatewayOnGatewayNodeDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteDeployment(ctx, ct.params.TestNamespace, testConnDisruptClientEgressGatewayOnNonGatewayNodeDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteDeployment(ctx, ct.params.TestNamespace, testConnDisruptServerEgressGatewayDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteServiceAccount(ctx, ct.params.TestNamespace, testConnDisruptClientDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteServiceAccount(ctx, ct.params.TestNamespace, testConnDisruptServerDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteServiceAccount(ctx, ct.params.TestNamespace, testConnDisruptServerNSTrafficDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteServiceAccount(ctx, ct.params.TestNamespace, testConnDisruptServerL7TrafficDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteServiceAccount(ctx, ct.params.TestNamespace, testConnDisruptServerEgressGatewayDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteServiceAccount(ctx, ct.params.TestNamespace, testConnDisruptClientEgressGatewayOnGatewayNodeDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteServiceAccount(ctx, ct.params.TestNamespace, testConnDisruptClientEgressGatewayOnNonGatewayNodeDeploymentName, metav1.DeleteOptions{})
	_ = client.DeleteService(ctx, ct.params.TestNamespace, testConnDisruptServiceName, metav1.DeleteOptions{})
	_ = client.DeleteService(ctx, ct.params.TestNamespace, testConnDisruptNSTrafficServiceName, metav1.DeleteOptions{})
	_ = client.DeleteService(ctx, ct.params.TestNamespace, testConnDisruptL7TrafficServiceName, metav1.DeleteOptions{})
	_ = client.DeleteService(ctx, ct.params.TestNamespace, testConnDisruptEgressGatewayServiceName, metav1.DeleteOptions{})
	_ = client.DeleteCiliumNetworkPolicy(ctx, ct.params.TestNamespace, testConnDisruptCNPName, metav1.DeleteOptions{})
	_ = client.DeleteCiliumNetworkPolicy(ctx, ct.params.TestNamespace, testConnDisruptNSTrafficCNPName, metav1.DeleteOptions{})
	_ = client.DeleteCiliumNetworkPolicy(ctx, ct.params.TestNamespace, testConnDisruptL7TrafficCNPName, metav1.DeleteOptions{})
	_ = client.DeleteCiliumNetworkPolicy(ctx, ct.params.TestNamespace, testConnDisruptEgressGatewayCNPName, metav1.DeleteOptions{})
	_ = client.DeleteCiliumEgressGatewayPolicy(ctx, testConnDisruptCEGPName, metav1.DeleteOptions{})

	return nil
}

func (ct *ConnectivityTest) validateDeploymentCommon(ctx context.Context, srcDeployments, dstDeployments []string) error {
	ct.Debug("Validating Deployments...")

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

	return nil
}

func (ct *ConnectivityTest) validateDeploymentPerf(ctx context.Context) error {
	srcDeployments, dstDeployments := ct.deploymentListPerf()
	if err := ct.validateDeploymentCommon(ctx, srcDeployments, dstDeployments); err != nil {
		return err
	}

	perfPods, err := ct.client.ListPods(ctx, ct.params.TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + kindPerfName})
	if err != nil {
		return fmt.Errorf("unable to list perf pods: %w", err)
	}

	for _, perfPod := range perfPods.Items {
		role := perfPodRole(perfPod.GetLabels()[perfPodRoleKey])
		switch role {
		case perfPodRoleServer:
			ct.perfServerPod = append(ct.perfServerPod, Pod{
				K8sClient: ct.client,
				Pod:       perfPod.DeepCopy(),
			})
		case perfPodRoleClient:
			ct.perfClientPods = append(ct.perfClientPods, Pod{
				K8sClient: ct.client,
				Pod:       perfPod.DeepCopy(),
			})
		case perfPodRoleProfiling:
			name := perfPod.GetLabels()["name"]
			ct.perfProfilingPods[name] = Pod{
				K8sClient: ct.client,
				Pod:       perfPod.DeepCopy(),
			}
		default:
			ct.Warnf("Found perf pod %q with unknown a role %q", perfPod.GetName(), role)
		}
	}

	// Sort pods so results are always displayed in the same order in console
	sort.SliceStable(ct.perfServerPod, func(i, j int) bool {
		return ct.perfServerPod[i].Pod.Name < ct.perfServerPod[j].Pod.Name
	})
	sort.SliceStable(ct.perfClientPods, func(i, j int) bool {
		return ct.perfClientPods[i].Pod.Name < ct.perfClientPods[j].Pod.Name
	})

	return nil
}

func (ct *ConnectivityTest) validateDeployment(ctx context.Context) error {
	srcDeployments, dstDeployments := ct.deploymentList()
	if err := ct.validateDeploymentCommon(ctx, srcDeployments, dstDeployments); err != nil {
		return err
	}

	if ct.Features[features.LocalRedirectPolicy].Enabled {
		lrpPods, err := ct.client.ListPods(ctx, ct.params.TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + kindLrpName})
		if err != nil {
			return fmt.Errorf("unable to list lrp pods: %w", err)
		}
		for _, lrpPod := range lrpPods.Items {
			if v, hasLabel := lrpPod.GetLabels()["lrp"]; hasLabel {
				if v == "backend" {
					ct.lrpBackendPods[lrpPod.Name] = Pod{
						K8sClient: ct.client,
						Pod:       lrpPod.DeepCopy(),
					}
				} else if v == "client" {
					ct.lrpClientPods[lrpPod.Name] = Pod{
						K8sClient: ct.client,
						Pod:       lrpPod.DeepCopy(),
					}
				}
			}
		}
	}

	if ct.Features[features.CCNP].Enabled {

		namespaces := []string{"cilium-test-ccnp1", "cilium-test-ccnp2"}
		for _, ns := range namespaces {
			if err := WaitForDeployment(ctx, ct, ct.clients.src, ns, ccnpDeploymentName); err != nil {
				return err
			}
			ccnpPods, err := ct.client.ListPods(ctx, ns, metav1.ListOptions{LabelSelector: "kind=" + kindCCNPName})
			if err != nil {
				return fmt.Errorf("unable to list ccnp pods in namespace %s: %w", ns, err)
			}
			for _, ccnpPod := range ccnpPods.Items {
				ct.ccnpTestPods[ns] = Pod{
					K8sClient: ct.client,
					Pod:       ccnpPod.DeepCopy(),
				}
			}
		}
	}

	clientPods, err := ct.client.ListPods(ctx, ct.params.TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + kindClientName})
	if err != nil {
		return fmt.Errorf("unable to list client pods: %w", err)
	}

	for _, pod := range clientPods.Items {
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
				port:      uint32(ct.Params().ExternalDeploymentPort), // listen port of the echo server inside the container
			}
		}

		echoExternalServices, err := ct.clients.dst.ListServices(ctx, ct.params.TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + kindEchoExternalNodeName})
		if err != nil {
			return fmt.Errorf("unable to list echo external services: %w", err)
		}

		for _, echoExternalService := range echoExternalServices.Items {
			ct.echoExternalServices[echoExternalService.Name] = Service{
				Service: echoExternalService.DeepCopy(),
			}
		}
	}

	if ct.Features[features.BGPControlPlane].Enabled && ct.Features[features.NodeWithoutCilium].Enabled && ct.params.TestConcurrency == 1 {
		if err := WaitForDaemonSet(ctx, ct, ct.clients.src, ct.Params().TestNamespace, frrDaemonSetNameName); err != nil {
			return err
		}
		frrPods, err := ct.clients.dst.ListPods(ctx, ct.params.TestNamespace, metav1.ListOptions{LabelSelector: "name=" + frrDaemonSetNameName})
		if err != nil {
			return fmt.Errorf("unable to list FRR pods: %w", err)
		}
		for _, pod := range frrPods.Items {
			ct.frrPods = append(ct.frrPods, Pod{
				K8sClient: ct.client,
				Pod:       pod.DeepCopy(),
			})
		}
	}

	if ct.Features[features.Multicast].Enabled {
		// socat client pods
		socatCilentPods, err := ct.clients.src.ListPods(ctx, ct.params.TestNamespace, metav1.ListOptions{LabelSelector: "name=" + socatClientDeploymentName})
		if err != nil {
			return fmt.Errorf("unable to list socat client pods: %w", err)
		}
		for _, pod := range socatCilentPods.Items {
			ct.socatClientPods = append(ct.socatClientPods, Pod{
				K8sClient: ct.client,
				Pod:       pod.DeepCopy(),
			})
		}

		// socat server pods
		if err := WaitForDaemonSet(ctx, ct, ct.clients.src, ct.Params().TestNamespace, socatServerDaemonsetName); err != nil {
			return err
		}
		socatServerPods, err := ct.clients.src.ListPods(ctx, ct.params.TestNamespace, metav1.ListOptions{LabelSelector: "name=" + socatServerDaemonsetName})
		if err != nil {
			return fmt.Errorf("unable to list socat server pods: %w", err)
		}
		for _, pod := range socatServerPods.Items {
			ct.socatServerPods = append(ct.socatServerPods, Pod{
				K8sClient: ct.client,
				Pod:       pod.DeepCopy(),
			})
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
		for name := range ct.ingresses() {
			svcName := fmt.Sprintf("cilium-ingress-%s", name)
			svc, err := WaitForServiceRetrieval(ctx, ct, ct.client, ct.params.TestNamespace, svcName)
			if err != nil {
				return err
			}

			ct.ingressService[svcName] = svc
		}
	}

	if ct.params.MultiCluster == "" {
		client := ct.RandomClientPod()
		if client == nil {
			return fmt.Errorf("no client pod available")
		}

		// Wait for NodePorts to be ready on all node IP addresses.
		// Tests iterate through all addresses in node.Status.Addresses[], which can include
		// both IPv4 and IPv6 in dual-stack clusters. Validating only HostIP (typically IPv4)
		// would leave IPv6 addresses unchecked, causing timeouts when tests try them.
		for _, node := range ct.Nodes() {
			for _, addr := range node.Status.Addresses {
				// Only check IP addresses (skip DNS names, hostnames)
				if addr.Type != slimcorev1.NodeInternalIP && addr.Type != slimcorev1.NodeExternalIP {
					continue
				}

				// Skip IP addresses of families which are not enabled in Cilium
				addrFamily := features.GetIPFamily(addr.Address)
				if (addrFamily == features.IPFamilyV4 && !ct.Features[features.IPv4].Enabled) ||
					(addrFamily == features.IPFamilyV6 && !ct.Features[features.IPv6].Enabled) {
					continue
				}

				// On GKE, ExternalIP is not reachable from inside a cluster.
				// Skip validation for external IPs in GKE to match the actual test behavior.
				if addr.Type == slimcorev1.NodeExternalIP {
					if f, ok := ct.Feature(features.Flavor); ok && f.Enabled && f.Mode == "gke" {
						ct.Debugf("Skipping NodePort validation for external IP %s on GKE", addr.Address)
						continue
					}
				}

				for _, s := range ct.echoServices {
					if err := WaitForNodePorts(ctx, ct, *client, addr.Address, s); err != nil {
						return err
					}
				}
			}
		}
	}

	// The host-netns-non-cilium DaemonSet is created in the source cluster only, also in case of multi-cluster tests.
	if ct.Features[features.NodeWithoutCilium].Enabled {
		if err := WaitForDaemonSet(ctx, ct, ct.clients.src, ct.Params().TestNamespace, hostNetNSDeploymentNameNonCilium); err != nil {
			return err
		}
	}

	for _, client := range ct.clients.clients() {
		if !ct.params.SingleNode || ct.params.MultiCluster != "" {
			if err := WaitForDaemonSet(ctx, ct, client, ct.Params().TestNamespace, hostNetNSDeploymentName); err != nil {
				return err
			}
		}
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
					addr, err := client.ExecInPod(ctx, pod.Namespace, pod.Name, pod.Spec.Containers[0].Name, cmd)
					if err != nil {
						return fmt.Errorf("failed to fetch secondary network ip addr: %w", err)
					}
					ct.secondaryNetworkNodeIPv4[pod.Spec.NodeName] = strings.TrimSuffix(addr.String(), "\n")
				}
				if ct.Features[features.IPv6].Enabled {
					cmd := []string{"/bin/sh", "-c", fmt.Sprintf("ip -family inet6 -oneline address show dev %s scope global | awk '{print $4}' | cut -d/ -f1", iface)}
					addr, err := client.ExecInPod(ctx, pod.Namespace, pod.Name, pod.Spec.Containers[0].Name, cmd)
					if err != nil {
						return fmt.Errorf("failed to fetch secondary network ip addr: %w", err)
					}
					ct.secondaryNetworkNodeIPv6[pod.Spec.NodeName] = strings.TrimSuffix(addr.String(), "\n")
				}
			}
		}
	}

	if ct.Features[features.L7LoadBalancer].Enabled {
		l7LBPods, err := ct.client.ListPods(ctx, ct.params.TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + kindL7LBName})
		if err != nil {
			return fmt.Errorf("unable to list client pods: %w", err)
		}

		for _, pod := range l7LBPods.Items {
			ct.l7LBClientPods[pod.Name] = Pod{
				K8sClient: ct.client,
				Pod:       pod.DeepCopy(),
			}
		}

		service, err := ct.client.ListServices(ctx, ct.params.TestNamespace, metav1.ListOptions{LabelSelector: "kind=" + kindL7LBName})
		if err != nil {
			return fmt.Errorf("unable to list L7 service: %w", err)
		}

		testClient := ct.RandomClientPod()
		for _, svc := range service.Items {
			s := Service{Service: svc.DeepCopy()}
			if err := WaitForService(ctx, ct, *testClient, s); err != nil {
				return err
			}
			ct.l7LBService[svc.Name] = s
		}
	}

	return nil
}
