// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"bytes"
	"cmp"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"helm.sh/helm/v3/pkg/release"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/internal/helm"
	"github.com/cilium/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium/cilium-cli/status"
	"github.com/cilium/cilium/cilium-cli/utils/wait"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
)

const (
	configNameClusterID   = "cluster-id"
	configNameClusterName = "cluster-name"

	configNameTunnelLegacy         = "tunnel"
	configNameTunnelProtocol       = "tunnel-protocol"
	configNameRoutingMode          = "routing-mode"
	configNameMaxConnectedClusters = "max-connected-clusters"

	configNameIdentityAllocationMode = "identity-allocation-mode"
)

var (
	// This can be replaced with cilium/pkg/defaults.MaxConnectedClusters once
	// changes are merged there.
	maxConnectedClusters = defaults.ClustermeshMaxConnectedClusters

	errConfigRequiredNotRetrieved = errors.New("remote cluster configuration required but not found")
)

type k8sClusterMeshImplementation interface {
	GetSecret(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Secret, error)
	GetConfigMap(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.ConfigMap, error)
	GetDeployment(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*appsv1.Deployment, error)
	CheckDeploymentStatus(ctx context.Context, namespace, deployment string) error
	GetService(ctx context.Context, namespace, name string, opts metav1.GetOptions) (*corev1.Service, error)
	GetDaemonSet(ctx context.Context, namespace, name string, options metav1.GetOptions) (*appsv1.DaemonSet, error)
	ListNodes(ctx context.Context, options metav1.ListOptions) (*corev1.NodeList, error)
	ListPods(ctx context.Context, namespace string, options metav1.ListOptions) (*corev1.PodList, error)
	AutodetectFlavor(ctx context.Context) k8s.Flavor
	CiliumStatus(ctx context.Context, namespace, pod string) (*models.StatusResponse, error)
	KVStoreMeshStatus(ctx context.Context, namespace, pod string) ([]*models.RemoteCluster, error)
	CiliumDbgEndpoints(ctx context.Context, namespace, pod string) ([]*models.Endpoint, error)
	ClusterName() string
	ListCiliumEndpoints(ctx context.Context, namespace string, options metav1.ListOptions) (*ciliumv2.CiliumEndpointList, error)
	ContainerLogs(ctx context.Context, namespace, pod, containerName string, since time.Time, previous bool) (string, error)
}

type K8sClusterMesh struct {
	client          k8sClusterMeshImplementation
	statusCollector *status.K8sStatusCollector
	flavor          k8s.Flavor
	params          Parameters
	clusterName     string
	clusterID       string
	externalKVStore bool
}

type Parameters struct {
	Namespace            string
	ServiceType          string
	DestinationContext   []string
	ConnectionMode       string
	Wait                 bool
	WaitDuration         time.Duration
	DestinationEndpoints []string
	SourceEndpoints      []string
	Parallel             int
	Writer               io.Writer
	Labels               map[string]string
	IPv4AllocCIDR        string
	IPv6AllocCIDR        string
	All                  bool
	ConfigOverwrites     []string
	Retries              int
	Output               string
	ImpersonateAs        string
	ImpersonateGroups    []string

	// EnableKVStoreMesh indicates whether kvstoremesh should be enabled.
	// For Helm mode only.
	EnableKVStoreMesh bool
	// Indicates if we should actually set the kvstoremesh.enabled Helm value
	// or rely on the default value. Default value of kvstoremesh changed in 1.16
	EnableKVStoreMeshChanged bool

	// HelmReleaseName specifies the Helm release name for the Cilium CLI.
	// Useful for referencing Cilium installations installed directly through Helm
	// or overriding the Cilium CLI for install/upgrade/enable.
	HelmReleaseName string
}

type notConnectedError struct{ error }

func (p Parameters) waitTimeout() time.Duration {
	if p.WaitDuration != time.Duration(0) {
		return p.WaitDuration
	}

	return time.Minute * 15
}

func NewK8sClusterMesh(client k8sClusterMeshImplementation, p Parameters) *K8sClusterMesh {
	return &K8sClusterMesh{
		client: client,
		params: p,
	}
}

func (k *K8sClusterMesh) Log(format string, a ...interface{}) {
	fmt.Fprintf(k.params.Writer, format+"\n", a...)
}

func (k *K8sClusterMesh) GetClusterConfig(ctx context.Context) error {
	k.flavor = k.client.AutodetectFlavor(ctx)

	cm, err := k.client.GetConfigMap(ctx, k.params.Namespace, defaults.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("unable to retrieve ConfigMap %q: %w", defaults.ConfigMapName, err)
	}

	k.externalKVStore = cm.Data[configNameIdentityAllocationMode] != "crd"

	clusterID := cm.Data[configNameClusterID]
	if clusterID == "" {
		clusterID = "0"
	}
	k.clusterID = clusterID

	clusterName := cm.Data[configNameClusterName]
	if clusterName == "" {
		clusterName = "default"
	}
	k.clusterName = clusterName

	if clusterID == "0" || clusterName == "default" {
		k.Log("⚠️  Cluster not configured for clustermesh, use '--set cluster.id' and '--set cluster.name' with 'cilium install'.")
	}

	return nil
}

type accessInformation struct {
	ServiceType          corev1.ServiceType `json:"service_type,omitempty"`
	ServiceIPs           []string           `json:"service_ips,omitempty"`
	ServicePort          int                `json:"service_port,omitempty"`
	ClusterID            string             `json:"cluster_id,omitempty"`
	ClusterName          string             `json:"cluster_name,omitempty"`
	CA                   []byte             `json:"ca,omitempty"`
	ClientCert           []byte             `json:"client_cert,omitempty"`
	ClientKey            []byte             `json:"client_key,omitempty"`
	Tunnel               string             `json:"tunnel,omitempty"`
	MaxConnectedClusters int                `json:"max_connected_clusters,omitempty"`
}

func (ai *accessInformation) validate() bool {
	return ai.ClusterName != "" &&
		ai.ClusterName != "default" &&
		ai.ClusterID != "" &&
		ai.ClusterID != "0"
}

func getDeprecatedName(secretName string) string {
	switch secretName {
	case defaults.ClusterMeshRemoteSecretName:
		return defaults.ClusterMeshClientSecretName
	case defaults.ClusterMeshServerSecretName,
		defaults.ClusterMeshAdminSecretName,
		defaults.ClusterMeshClientSecretName:
		return secretName + "s"
	default:
		return ""
	}
}

// getDeprecatedSecret attempts to retrieve a secret using one or more deprecated names
// There are now multiple "layers" of deprecated secret names, so we call this function recursively if needed
func (k *K8sClusterMesh) getDeprecatedSecret(ctx context.Context, client k8sClusterMeshImplementation, secretName string, defaultName string) (*corev1.Secret, error) {

	deprecatedSecretName := getDeprecatedName(secretName)
	if deprecatedSecretName == "" {
		return nil, fmt.Errorf("unable to get secret %q and no deprecated names to try", secretName)
	}

	k.Log("Trying to get secret %s by deprecated name %s", secretName, deprecatedSecretName)

	secret, err := client.GetSecret(ctx, k.params.Namespace, deprecatedSecretName, metav1.GetOptions{})
	if err != nil {
		return k.getDeprecatedSecret(ctx, client, deprecatedSecretName, defaultName)
	}

	k.Log("⚠️ Deprecated secret name %q, should be changed to %q", secret.Name, defaultName)

	return secret, err
}

// We had inconsistency in naming clustermesh secrets between Helm installation and Cilium CLI installation
// Cilium CLI was naming clustermesh secrets with trailing 's'. eg. 'clustermesh-apiserver-client-certs' instead of `clustermesh-apiserver-client-cert`
// This caused Cilium CLI 'clustermesh status' command to fail when Cilium is installed using Helm
// getSecret handles both secret names and logs warning if deprecated secret name is found
func (k *K8sClusterMesh) getSecret(ctx context.Context, client k8sClusterMeshImplementation, secretName string) (*corev1.Secret, error) {

	secret, err := client.GetSecret(ctx, k.params.Namespace, secretName, metav1.GetOptions{})
	if err != nil {
		return k.getDeprecatedSecret(ctx, client, secretName, secretName)
	}
	return secret, err
}

func (k *K8sClusterMesh) getCACert(ctx context.Context, client k8sClusterMeshImplementation) ([]byte, error) {
	secret, err := client.GetSecret(ctx, k.params.Namespace, defaults.CASecretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("get secret %q to retrieve CA: %w", defaults.CASecretName, err)
	}

	// The helm and cronjob certificate generation methods currently store
	// the certificate under the ca.crt key, while cert-manager requires it
	// to be under the tls.crt key. Hence, let's attempt to retrieve it
	// using both keys.
	cert, ok := secret.Data[defaults.CASecretCertName]
	if ok {
		return cert, nil
	}

	cert, ok = secret.Data[corev1.TLSCertKey]
	if ok {
		return cert, nil
	}

	return nil, fmt.Errorf("secret %q does not contain the CA certificate", defaults.CASecretName)
}

func (k *K8sClusterMesh) extractAccessInformation(ctx context.Context, client k8sClusterMeshImplementation, endpoints []string, verbose bool) (*accessInformation, error) {
	cm, err := client.GetConfigMap(ctx, k.params.Namespace, defaults.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve ConfigMap %q: %w", defaults.ConfigMapName, err)
	}

	if _, ok := cm.Data[configNameClusterName]; !ok {
		return nil, fmt.Errorf("%s is not set in ConfigMap %q", configNameClusterName, defaults.ConfigMapName)
	}

	clusterID := cm.Data[configNameClusterID]
	clusterName := cm.Data[configNameClusterName]

	if mcc, ok := cm.Data[configNameMaxConnectedClusters]; ok {
		maxConnectedClusters, err = strconv.Atoi(mcc)
		if err != nil {
			return nil, fmt.Errorf("unable to parse %s: %w", configNameMaxConnectedClusters, err)
		}
	}

	if verbose {
		k.Log("✨ Extracting access information of cluster %s...", clusterName)
	}
	svc, err := client.GetService(ctx, k.params.Namespace, defaults.ClusterMeshServiceName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to get clustermesh service %q: %w", defaults.ClusterMeshServiceName, err)
	}

	if verbose {
		k.Log("🔑 Extracting secrets from cluster %s...", clusterName)
	}

	meshSecret, err := k.getSecret(ctx, client, defaults.ClusterMeshRemoteSecretName)
	if err != nil {
		return nil, fmt.Errorf("unable to get client secret to access clustermesh service: %w", err)
	}

	clientKey, ok := meshSecret.Data[corev1.TLSPrivateKeyKey]
	if !ok {
		return nil, fmt.Errorf("secret %q does not contain key %q", meshSecret.Name, corev1.TLSPrivateKeyKey)
	}

	clientCert, ok := meshSecret.Data[corev1.TLSCertKey]
	if !ok {
		return nil, fmt.Errorf("secret %q does not contain key %q", meshSecret.Name, corev1.TLSCertKey)
	}

	caCert, err := k.getCACert(ctx, client)
	// We failed to retrieve the CA from its own secret, let's fallback to the ca.crt certificate inside the mesh secret.
	if err != nil {
		caCert, ok = meshSecret.Data[defaults.CASecretCertName]
		if !ok {
			return nil, fmt.Errorf("unable to retrieve the CA certificate: %w", err)
		}
	}

	tunnelProtocol := ""
	if cm.Data[configNameRoutingMode] == "tunnel" {
		// Cilium v1.14 and newer
		tunnelProtocol = "vxlan" // default for tunnel mode
		if proto, ok := cm.Data[configNameTunnelProtocol]; ok {
			tunnelProtocol = proto
		}
	} else if proto, ok := cm.Data[configNameTunnelLegacy]; ok {
		// Cilium v1.13 and older (some v1.14 configurations might use it too)
		// Can be removed once we drop support for v1.14
		tunnelProtocol = proto
	}

	ai := &accessInformation{
		ClusterID:            clusterID,
		ClusterName:          clusterName,
		CA:                   caCert,
		ClientKey:            clientKey,
		ClientCert:           clientCert,
		ServiceType:          svc.Spec.Type,
		ServiceIPs:           []string{},
		Tunnel:               tunnelProtocol,
		MaxConnectedClusters: maxConnectedClusters,
	}

	switch {
	case len(endpoints) > 0:
		for _, endpoint := range endpoints {
			ip, port, err := net.SplitHostPort(endpoint)
			if err != nil {
				return nil, fmt.Errorf("invalid endpoint %q, must be IP:PORT: %w", endpoint, err)
			}

			intPort, err := strconv.Atoi(port)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q: %w", port, err)
			}

			if ai.ServicePort == 0 {
				ai.ServicePort = intPort
			} else if ai.ServicePort != intPort {
				return nil, fmt.Errorf("port mismatch (%d != %d), all endpoints must use the same port number", ai.ServicePort, intPort)
			}

			ai.ServiceIPs = append(ai.ServiceIPs, ip)
		}

	case svc.Spec.Type == corev1.ServiceTypeClusterIP:
		if len(svc.Spec.Ports) == 0 {
			return nil, fmt.Errorf("port of service could not be derived, service has no ports")
		}
		if svc.Spec.Ports[0].Port == 0 {
			return nil, fmt.Errorf("port is not set in service")
		}
		ai.ServicePort = int(svc.Spec.Ports[0].Port)

		if svc.Spec.ClusterIP == "" {
			return nil, fmt.Errorf("IP of service could not be derived, service has no ClusterIP")
		}
		ai.ServiceIPs = append(ai.ServiceIPs, svc.Spec.ClusterIP)

	case svc.Spec.Type == corev1.ServiceTypeNodePort:
		if len(svc.Spec.Ports) == 0 {
			return nil, fmt.Errorf("port of service could not be derived, service has no ports")
		}

		if svc.Spec.Ports[0].NodePort == 0 {
			return nil, fmt.Errorf("nodeport is not set in service")
		}
		ai.ServicePort = int(svc.Spec.Ports[0].NodePort)

		nodes, err := client.ListNodes(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("unable to list nodes in cluster: %w", err)
		}

		for _, node := range nodes.Items {
			nodeIP := ""
			for _, address := range node.Status.Addresses {
				switch address.Type {
				case corev1.NodeExternalIP:
					nodeIP = address.Address
				case corev1.NodeInternalIP:
					if nodeIP == "" {
						nodeIP = address.Address
					}
				}
			}

			if nodeIP != "" {
				ai.ServiceIPs = append(ai.ServiceIPs, nodeIP)

				// We can't really support multiple nodes as
				// the NodePort will be different and the
				// current use of hostAliases will lead to
				// DNS-style RR requiring all endpoints to use
				// the same port
				break
			}
		}
		k.Log("⚠️  Service type NodePort detected! Service may fail when nodes are removed from the cluster!")

	case svc.Spec.Type == corev1.ServiceTypeLoadBalancer:
		if len(svc.Spec.Ports) == 0 {
			return nil, fmt.Errorf("port of service could not be derived, service has no ports")
		}

		ai.ServicePort = int(svc.Spec.Ports[0].Port)

		for _, ingressStatus := range svc.Status.LoadBalancer.Ingress {
			if ingressStatus.Hostname == "" {
				ai.ServiceIPs = append(ai.ServiceIPs, ingressStatus.IP)
			} else {
				k.Log("Hostname based ingress detected, trying to resolve it")

				ips, err := net.LookupHost(ingressStatus.Hostname)
				if err != nil {
					k.Log(fmt.Sprintf("Could not resolve the hostname of the ingress, falling back to the static IP. Error: %v", err))
					ai.ServiceIPs = append(ai.ServiceIPs, ingressStatus.IP)
				} else {
					k.Log("Hostname resolved, using the found ip(s)")
					ai.ServiceIPs = append(ai.ServiceIPs, ips...)
				}
			}
		}
	}

	switch {
	case len(ai.ServiceIPs) > 0:
		if verbose {
			k.Log("ℹ️  Found ClusterMesh service IPs: %s", ai.ServiceIPs)
		}
	default:
		return nil, fmt.Errorf("unable to derive service IPs automatically")
	}

	return ai, nil
}

func (k *K8sClusterMesh) getRemoteClients() ([]*k8s.Client, error) {
	var remoteClients []*k8s.Client
	for _, d := range k.params.DestinationContext {
		remoteClient, err := k8s.NewClient(d, "", k.params.Namespace, k.params.ImpersonateAs, k.params.ImpersonateGroups)
		if err != nil {
			return nil, fmt.Errorf(
				"unable to create Kubernetes client to access remote cluster %q: %w",
				d, err)
		}
		remoteClients = append(remoteClients, remoteClient)
	}
	return remoteClients, nil
}

func (k *K8sClusterMesh) shallowExtractAccessInfo(ctx context.Context, c *k8s.Client) (*accessInformation, error) {
	cm, err := c.GetConfigMap(ctx, k.params.Namespace, defaults.ConfigMapName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve ConfigMap %q: %w", defaults.ConfigMapName, err)
	}
	id, ok := cm.Data[configNameClusterID]
	if !ok {
		return nil, fmt.Errorf("unable to locate key: %q in ConfigMap %q", configNameClusterID, defaults.ConfigMapName)
	}
	name, ok := cm.Data[configNameClusterName]
	if !ok {
		return nil, fmt.Errorf("unable to locate key: %q in ConfigMap %q", configNameClusterName, defaults.ConfigMapName)
	}

	return &accessInformation{
		ClusterID:   id,
		ClusterName: name,
	}, nil
}

func (k *K8sClusterMesh) getAccessInfoForConnect(
	ctx context.Context, client *k8s.Client, endpoints []string,
) (*accessInformation, error) {
	ai, err := k.extractAccessInformation(ctx, client, endpoints, true)
	if err != nil {
		k.Log("❌ Unable to retrieve access information of cluster %q: %s", client.ClusterName(), err)
		return nil, err
	}

	return ai, nil
}

// connectAccessInit initializes a Kubernetes client for the local and remote cluster
// and performs some validation that the two clusters can be connected via clustermesh
func (k *K8sClusterMesh) validateInfoForConnect(aiLocal, aiRemote *accessInformation) error {
	if !aiRemote.validate() {
		return fmt.Errorf("remote cluster has non-unique name (%s) and/or ID (%s)",
			aiRemote.ClusterName, aiRemote.ClusterID)
	}

	if !aiLocal.validate() {
		return fmt.Errorf(
			"local cluster has the default name (cluster name: %s) and/or ID 0 (cluster ID: %s)",
			aiLocal.ClusterName, aiLocal.ClusterID)
	}

	cid, err := strconv.Atoi(aiRemote.ClusterID)
	if err != nil {
		return fmt.Errorf(
			"remote cluster has non-numeric cluster ID %s. Only numeric values 1-255 are allowed",
			aiRemote.ClusterID)
	}
	if cid < 1 || cid > aiLocal.MaxConnectedClusters {
		return fmt.Errorf("remote cluster has cluster ID %d out of acceptable range (1-%d)", cid, aiLocal.MaxConnectedClusters)
	}

	if aiRemote.MaxConnectedClusters != aiLocal.MaxConnectedClusters {
		return fmt.Errorf("remote and local clusters have different max connected clusters: %d != %d", aiRemote.MaxConnectedClusters, aiLocal.MaxConnectedClusters)
	}

	if aiRemote.ClusterName == aiLocal.ClusterName {
		return fmt.Errorf("remote and local cluster have the same, non-unique name: %s", aiLocal.ClusterName)
	}

	if aiRemote.ClusterID == aiLocal.ClusterID {
		return fmt.Errorf("remote and local cluster have the same, non-unique ID: %s", aiLocal.ClusterID)
	}

	return nil
}

type Status struct {
	AccessInformation *accessInformation  `json:"access_information,omitempty"`
	Connectivity      *ConnectivityStatus `json:"connectivity,omitempty"`
	KVStoreMesh       struct {
		Enabled bool                `json:"enabled"`
		Status  *ConnectivityStatus `json:"status,omitempty"`
	} `json:"kvstoremesh,omitempty"`
}

func (k *K8sClusterMesh) statusAccessInformation(ctx context.Context, log bool) (*accessInformation, error) {
	w := wait.NewObserver(ctx, wait.Parameters{Log: func(err error, wait string) {
		if log {
			k.Log("⌛ Waiting (%s) for access information: %s", wait, err)
		}
	}})
	defer w.Cancel()

	for {
		ai, err := k.extractAccessInformation(ctx, k.client, []string{}, false)
		if err != nil && k.params.Wait {
			if err := w.Retry(err); err != nil {
				return nil, err
			}
			continue
		}

		return ai, err
	}
}

func (k *K8sClusterMesh) statusDeployment(ctx context.Context) (err error) {
	w := wait.NewObserver(ctx, wait.Parameters{Log: func(err error, wait string) {
		k.Log("⌛ Waiting (%s) for deployment %s to become ready: %s", wait, defaults.ClusterMeshDeploymentName, err)
	}})
	defer func() {
		w.Cancel()
		if err != nil {
			err = fmt.Errorf("deployment %s is not ready: %w", defaults.ClusterMeshDeploymentName, err)
		}
	}()

	for {
		err := k.client.CheckDeploymentStatus(ctx, k.params.Namespace, defaults.ClusterMeshDeploymentName)
		if err != nil && k.params.Wait {
			if err := w.Retry(err); err != nil {
				return err
			}
			continue
		}

		return err
	}
}

func (k *K8sClusterMesh) kvstoremeshEnabled(ctx context.Context) (bool, error) {
	deploy, err := k.client.GetDeployment(ctx, k.params.Namespace, defaults.ClusterMeshDeploymentName, metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("failed checking whether KVStoreMesh is enabled: %w", err)
	}

	for _, container := range deploy.Spec.Template.Spec.Containers {
		if container.Name == defaults.ClusterMeshKVStoreMeshContainerName {
			return true, nil
		}
	}

	return false, nil
}

type StatisticalStatus struct {
	Min int64   `json:"min,omitempty"`
	Avg float64 `json:"avg,omitempty"`
	Max int64   `json:"max,omitempty"`
}

type ClusterStats struct {
	Configured int `json:"configured,omitempty"`
	Connected  int `json:"connected,omitempty"`
}

type ConnectivityStatus struct {
	GlobalServices StatisticalStatus        `json:"global_services,omitempty"`
	Connected      StatisticalStatus        `json:"connected,omitempty"`
	Clusters       map[string]*ClusterStats `json:"clusters,omitempty"`
	Total          int64                    `json:"total,omitempty"`
	NotReady       int64                    `json:"not_ready,omitempty"`
	Errors         status.ErrorCountMapMap  `json:"errors,omitempty"`
}

func (c *ConnectivityStatus) addError(pod, cluster string, err error) {
	m := c.Errors[pod]
	if m == nil {
		m = status.ErrorCountMap{}
		c.Errors[pod] = m
	}

	if m[cluster] == nil {
		m[cluster] = &status.ErrorCount{}
	}

	m[cluster].Errors = append(m[cluster].Errors, err)
}

func remoteClusterStatusToError(status *models.RemoteCluster) error {
	switch {
	case status == nil:
		return errors.New("unknown status")
	case !status.Connected:
		return notConnectedError{errors.New(status.Status)}
	case status.Config == nil:
		return errors.New("remote cluster configuration retrieval status unknown")
	case status.Config.Required && !status.Config.Retrieved:
		return errConfigRequiredNotRetrieved
	case status.Synced == nil:
		return errors.New("synchronization status unknown")
	case !(status.Synced.Nodes && status.Synced.Endpoints && status.Synced.Identities && status.Synced.Services):
		var toSync []string
		appendNotSynced := func(name string, synced bool) {
			if !synced {
				toSync = append(toSync, name)
			}
		}
		appendNotSynced("endpoints", status.Synced.Endpoints)
		appendNotSynced("identities", status.Synced.Identities)
		appendNotSynced("nodes", status.Synced.Nodes)
		appendNotSynced("services", status.Synced.Services)

		return fmt.Errorf("synchronization in progress for %s", strings.Join(toSync, ", "))
	default:
		return errors.New("not ready")
	}
}

func (c *ConnectivityStatus) parseAgentStatus(name string, expected []string, s *status.ClusterMeshAgentConnectivityStatus) {
	if c.GlobalServices.Min < 0 || c.GlobalServices.Min > s.GlobalServices {
		c.GlobalServices.Min = s.GlobalServices
	}

	if c.GlobalServices.Max < s.GlobalServices {
		c.GlobalServices.Max = s.GlobalServices
	}

	c.GlobalServices.Avg += float64(s.GlobalServices)
	c.Total++

	ready := int64(0)
	for _, cluster := range s.Clusters {
		stats, ok := c.Clusters[cluster.Name]
		if !ok {
			stats = &ClusterStats{}
			c.Clusters[cluster.Name] = stats
		}

		stats.Configured++

		if cluster.Ready {
			ready++
			stats.Connected++
		} else {
			c.addError(name, cluster.Name, remoteClusterStatusToError(cluster))
		}
	}

	// Add an error for any cluster that was expected but not found
	var missing bool
	for _, exp := range expected {
		if _, ok := s.Clusters[exp]; !ok {
			missing = true
			c.addError(name, exp, errors.New("unknown status"))
		}
	}

	if missing || ready != int64(len(s.Clusters)) {
		c.NotReady++
	}

	if c.Connected.Min < 0 || c.Connected.Min > ready {
		c.Connected.Min = ready
	}

	if c.Connected.Max < ready {
		c.Connected.Max = ready
	}

	c.Connected.Avg += float64(ready)
}

func (k *K8sClusterMesh) statusConnectivity(ctx context.Context, checkKVStoreMesh bool) (agents, kvstoremesh *ConnectivityStatus, err error) {
	var err1, err2 error
	var checkAgents = true

	w := wait.NewObserver(ctx, wait.Parameters{Log: func(err error, wait string) {
		k.Log("⌛ Waiting (%s) for clusters to be connected: %s", wait, err)
	}})
	defer w.Cancel()

	for {
		if checkAgents {
			agents, err1 = k.determineStatusConnectivity(
				ctx, defaults.ClusterMeshSecretName, defaults.AgentPodSelector, k.statusCollector.ClusterMeshConnectivity,
			)
		}

		if checkKVStoreMesh {
			kvstoremesh, err2 = k.determineStatusConnectivity(
				ctx, defaults.ClusterMeshKVStoreMeshSecretName, defaults.ClusterMeshPodSelector, k.statusCollector.KVStoreMeshConnectivity,
			)

			if errors.Is(err2, k8s.ErrKVStoreMeshStatusNotImplemented) {
				k.Log("⚠️  KVStoreMesh status retrieval is not supported by this Cilium version")
				err2 = nil
			}
		}

		if k.params.Wait {
			notReadyCheck := func(status *ConnectivityStatus, err error, component string) error {
				if err == nil && status != nil {
					if status.NotReady > 0 {
						err = fmt.Errorf("%d %s are not ready", status.NotReady, component)
					}
				}
				return err
			}

			err1 = notReadyCheck(agents, err1, "nodes")
			err2 = notReadyCheck(kvstoremesh, err2, "KVStoreMesh replicas")

			checkAgents = checkAgents && err1 != nil
			checkKVStoreMesh = checkKVStoreMesh && err2 != nil

			if err := cmp.Or(err2, err1); err != nil {
				if err := w.Retry(err); err != nil {
					return agents, kvstoremesh, err
				}
				continue
			}
		}

		// Return only one error rather than both, as joined errors are displayed poorly.
		// And Prefer the KVStoreMesh one, given that it implies the agents one as well
		// in most cases.
		return agents, kvstoremesh, cmp.Or(err2, err1)
	}
}

func (k *K8sClusterMesh) determineStatusConnectivity(ctx context.Context, secretName, selector string,
	collector func(ctx context.Context, ciliumPod string) (*status.ClusterMeshAgentConnectivityStatus, error),
) (*ConnectivityStatus, error) {
	stats := &ConnectivityStatus{
		GlobalServices: StatisticalStatus{Min: -1},
		Connected:      StatisticalStatus{Min: -1},
		Errors:         status.ErrorCountMapMap{},
		Clusters:       map[string]*ClusterStats{},
	}

	// Retrieve the remote clusters to connect to from the clustermesh configuration,
	// as there's no guarantee that the secret has already propagated into the agents.
	// Don't fail in case the secret is not found, as it is legitimate if no cluster
	// has been connected yet.
	config, err := k.client.GetSecret(ctx, k.params.Namespace, secretName, metav1.GetOptions{})
	if err != nil && !k8serrors.IsNotFound(err) {
		return nil, fmt.Errorf("unable to retrieve configuration: %w", err)
	}

	var expected []string
	for name, cfg := range config.Data {
		// Same check as https://github.com/cilium/cilium/blob/538a18800206da0d33916f5f48853a3d4454dd81/pkg/clustermesh/internal/config.go#L68
		// Additionally skip the configuration of the local cluster, if present
		if name != k.clusterName && strings.Contains(string(cfg), "endpoints:") {
			stats.Clusters[name] = &ClusterStats{}
			expected = append(expected, name)
		}
	}

	pods, err := k.client.ListPods(ctx, k.params.Namespace, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, fmt.Errorf("unable to list pods: %w", err)
	}

	for _, pod := range pods.Items {
		s, err := collector(ctx, pod.Name)
		if err != nil {
			if len(expected) == 0 && errors.Is(err, status.ErrClusterMeshStatusNotAvailable) {
				continue
			}
			return nil, fmt.Errorf("unable to determine status of pod %q: %w", pod.Name, err)
		}

		stats.parseAgentStatus(pod.Name, expected, s)
	}

	if len(pods.Items) > 0 {
		stats.GlobalServices.Avg /= float64(len(pods.Items))
		stats.Connected.Avg /= float64(len(pods.Items))
	}

	return stats, nil
}

func (k *K8sClusterMesh) Status(ctx context.Context) (*Status, error) {
	err := k.GetClusterConfig(ctx)
	if err != nil {
		return nil, err
	}

	collector, err := status.NewK8sStatusCollector(k.client, status.K8sStatusParameters{
		Namespace: k.params.Namespace,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to create client to collect status: %w", err)
	}

	k.statusCollector = collector

	ctx, cancel := context.WithTimeout(ctx, k.params.waitTimeout())
	defer cancel()

	s := &Status{}

	if k.externalKVStore {
		k.Log("✅ Cilium is configured with an external kvstore")
	} else {
		s.AccessInformation, err = k.statusAccessInformation(ctx, true)
		if err != nil {
			return nil, err
		}

		k.Log("✅ Service %q of type %q found", defaults.ClusterMeshServiceName, s.AccessInformation.ServiceType)
		k.Log("✅ Cluster access information is available:")
		for _, ip := range s.AccessInformation.ServiceIPs {
			k.Log("  - %s:%d", ip, s.AccessInformation.ServicePort)
		}

		err = k.statusDeployment(ctx)
		if err != nil {
			return nil, err
		}
		k.Log("✅ Deployment %s is ready", defaults.ClusterMeshDeploymentName)

		s.KVStoreMesh.Enabled, err = k.kvstoremeshEnabled(ctx)
		if err != nil {
			return nil, err
		}

		status := "disabled"
		if s.KVStoreMesh.Enabled {
			status = "enabled"
		}
		k.Log("ℹ️  KVStoreMesh is %s", status)
	}

	s.Connectivity, s.KVStoreMesh.Status, err = k.statusConnectivity(ctx, s.KVStoreMesh.Enabled)

	if k.params.Output == status.OutputJSON {
		jsonStatus, err := json.MarshalIndent(s, "", " ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal status to JSON")
		}
		fmt.Println(string(jsonStatus))
		return s, nil
	}

	if s.Connectivity != nil {
		k.outputConnectivityStatus(s.Connectivity, s.KVStoreMesh.Status, s.KVStoreMesh.Enabled)
	}

	return s, err
}

func (k *K8sClusterMesh) outputConnectivityStatus(agents, kvstoremesh *ConnectivityStatus, kvstoremeshEnabled bool) {
	outputStatusReady := func(status *ConnectivityStatus, component string) {
		if status.NotReady > 0 {
			k.Log("⚠️  %d/%d %s are not connected to all clusters [min:%d / avg:%.1f / max:%d]",
				status.NotReady,
				status.Total,
				component,
				status.Connected.Min,
				status.Connected.Avg,
				status.Connected.Max)
		} else if len(status.Clusters) > 0 {
			k.Log("✅ All %d %s are connected to all clusters [min:%d / avg:%.1f / max:%d]",
				status.Total,
				component,
				status.Connected.Min,
				status.Connected.Avg,
				status.Connected.Max)
		}
	}

	k.Log("")
	outputStatusReady(agents, "nodes")
	if kvstoremesh != nil {
		outputStatusReady(kvstoremesh, "KVStoreMesh replicas")
	}

	k.Log("")
	if len(agents.Clusters) > 0 {
		k.Log("🔌 Cluster Connections:")
		for _, cluster := range slices.Sorted(maps.Keys(agents.Clusters)) {
			stats := agents.Clusters[cluster]

			line := fmt.Sprintf("  - %s: %d/%d configured, %d/%d connected",
				cluster, stats.Configured, agents.Total,
				stats.Connected, agents.Total)

			if kvstoremesh != nil {
				stats, ok := kvstoremesh.Clusters[cluster]
				if !ok {
					line += " - KVStoreMesh: status not available"
				} else {
					line += fmt.Sprintf(" - KVStoreMesh: %d/%d configured, %d/%d connected",
						stats.Configured, kvstoremesh.Total,
						stats.Connected, kvstoremesh.Total)
				}
			}

			k.Log(line)
		}
	} else {
		k.Log("🔌 No cluster connected")
	}

	k.Log("")
	k.Log("🔀 Global services: [ min:%d / avg:%.1f / max:%d ]",
		agents.GlobalServices.Min,
		agents.GlobalServices.Avg,
		agents.GlobalServices.Max)

	k.Log("")
	errCount := len(agents.Errors)
	if kvstoremesh != nil {
		errCount += len(kvstoremesh.Errors)
	}

	if errCount > 0 {
		k.Log("❌ %d Errors:", errCount)

		outputErrors := func(errs status.ErrorCountMapMap, container, cmd string, likelyKVStoreMesh bool) {
			for _, podName := range slices.Sorted(maps.Keys(errs)) {
				clusters := errs[podName]
				for clusterName, a := range clusters {
					for _, err := range a.Errors {
						k.Log("  ❌ %s is not connected to cluster %s: %s", podName, clusterName, err)
						if errors.As(err, &notConnectedError{}) {
							k.Log("     💡 Run 'kubectl exec -it -n %s %s -c %s -- %s %s' to investigate the cause",
								k.params.Namespace, podName, container, cmd, clusterName)
						} else if errors.Is(err, errConfigRequiredNotRetrieved) {
							if likelyKVStoreMesh {
								k.Log("     💡 This is likely caused by KVStoreMesh not being connected to the given cluster")
							} else {
								k.Log("     💡 Double check if the cluster name matches the one configured in the remote cluster")
							}
						}
					}
				}
			}
		}

		outputErrors(agents.Errors, defaults.AgentContainerName, "cilium-dbg troubleshoot clustermesh", kvstoremeshEnabled)
		if kvstoremesh != nil {
			outputErrors(kvstoremesh.Errors, defaults.ClusterMeshKVStoreMeshContainerName, defaults.ClusterMeshBinaryName+" kvstoremesh-dbg troubleshoot", false)
		}
	}
}

func log(format string, a ...interface{}) {
	// TODO (ajs): make logger configurable
	fmt.Fprintf(os.Stdout, format+"\n", a...)
}

func generateEnableHelmValues(params Parameters, flavor k8s.Flavor) (map[string]interface{}, error) {
	helmVals := map[string]interface{}{
		"clustermesh": map[string]interface{}{
			"useAPIServer": true,
		},
	}

	if params.ServiceType == "" {
		switch flavor.Kind {
		case k8s.KindGKE:
			log("🔮 Auto-exposing service within GCP VPC (networking.gke.io/load-balancer-type=Internal)")
			helmVals["clustermesh"].(map[string]interface{})["apiserver"] = map[string]interface{}{
				"service": map[string]interface{}{
					"type": corev1.ServiceTypeLoadBalancer,
					"annotations": map[string]interface{}{
						"networking.gke.io/load-balancer-type": "Internal",
						// Allows cross-region access
						"networking.gke.io/internal-load-balancer-allow-global-access": "true",
					},
				},
			}
		case k8s.KindAKS:
			log("🔮 Auto-exposing service within Azure VPC (service.beta.kubernetes.io/azure-load-balancer-internal)")
			helmVals["clustermesh"].(map[string]interface{})["apiserver"] = map[string]interface{}{
				"service": map[string]interface{}{
					"type": corev1.ServiceTypeLoadBalancer,
					"annotations": map[string]interface{}{
						"service.beta.kubernetes.io/azure-load-balancer-internal": "true",
					},
				},
			}
		case k8s.KindEKS:
			log("🔮 Auto-exposing service within AWS VPC (service.beta.kubernetes.io/aws-load-balancer-scheme: internal")
			helmVals["clustermesh"].(map[string]interface{})["apiserver"] = map[string]interface{}{
				"service": map[string]interface{}{
					"type": corev1.ServiceTypeLoadBalancer,
					"annotations": map[string]interface{}{
						"service.beta.kubernetes.io/aws-load-balancer-scheme": "internal",
					},
				},
			}
		default:
			return nil, fmt.Errorf("cannot auto-detect service type, please specify using '--service-type' option")
		}
	} else {
		if corev1.ServiceType(params.ServiceType) == corev1.ServiceTypeNodePort {
			log("⚠️  Using service type NodePort may fail when nodes are removed from the cluster!")
		} else if corev1.ServiceType(params.ServiceType) != corev1.ServiceTypeLoadBalancer {
			return nil, fmt.Errorf("service type %q is not valid", params.ServiceType)
		}

		helmVals["clustermesh"].(map[string]interface{})["apiserver"] = map[string]interface{}{
			"service": map[string]interface{}{
				"type": params.ServiceType,
			},
		}
	}

	helmVals["clustermesh"].(map[string]interface{})["apiserver"].(map[string]interface{})["tls"] =
		// default to using certgen, so that certificates are renewed automatically
		map[string]interface{}{
			"auto": map[string]interface{}{
				"enabled": true,
				"method":  "cronJob",
				// run the renewal every 4 months on the 1st of the month
				"schedule": "0 0 1 */4 *",
			},
		}

	if params.EnableKVStoreMeshChanged {
		helmVals["clustermesh"].(map[string]interface{})["apiserver"].(map[string]interface{})["kvstoremesh"] =
			map[string]interface{}{
				"enabled": params.EnableKVStoreMesh,
			}
	}

	return helmVals, nil
}

func EnableWithHelm(ctx context.Context, k8sClient *k8s.Client, params Parameters) error {
	helmVals, err := generateEnableHelmValues(params, k8sClient.AutodetectFlavor(ctx))
	if err != nil {
		return err
	}
	upgradeParams := helm.UpgradeParameters{
		Namespace:   params.Namespace,
		Name:        params.HelmReleaseName,
		Values:      helmVals,
		ResetValues: false,
		ReuseValues: true,
	}
	_, err = helm.Upgrade(ctx, k8sClient.HelmActionConfig, upgradeParams)
	return err
}

func DisableWithHelm(ctx context.Context, k8sClient *k8s.Client, params Parameters) error {
	helmStrValues := []string{
		"clustermesh.useAPIServer=false",
		"clustermesh.config.enabled=false",
	}
	vals, err := helm.ParseVals(helmStrValues)
	if err != nil {
		return err
	}

	err = unstructured.SetNestedSlice(vals, []interface{}{}, "clustermesh", "config", "clusters")
	if err != nil {
		return err
	}

	upgradeParams := helm.UpgradeParameters{
		Namespace:   params.Namespace,
		Name:        params.HelmReleaseName,
		Values:      vals,
		ResetValues: false,
		ReuseValues: true,
	}
	_, err = helm.Upgrade(ctx, k8sClient.HelmActionConfig, upgradeParams)
	return err
}

func getRelease(kc *k8s.Client, params Parameters) (*release.Release, error) {
	return kc.HelmActionConfig.Releases.Last(params.HelmReleaseName)
}

// validateCAMatch determines if the certificate authority certificate being
// used by aiLocal and aiRemote uses a matching keypair. The bool return value
// is true (keypairs match), false (keys do not match OR there was an error)
func (k *K8sClusterMesh) validateCAMatch(aiLocal, aiRemote *accessInformation) (bool, error) {
	caLocal := aiLocal.CA
	block, _ := pem.Decode(caLocal)
	if block == nil {
		return false, fmt.Errorf("failed to parse certificate PEM for local CA cert")
	}
	localCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, err
	}

	caRemote := aiRemote.CA
	block, _ = pem.Decode(caRemote)
	if block == nil {
		return false, fmt.Errorf("failed to parse certificate PEM for remote CA cert")
	}
	remoteCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, err
	}

	// Compare the x509 key identifier of each certificate
	if !bytes.Equal(localCert.SubjectKeyId, remoteCert.SubjectKeyId) {
		// Note: For now, do NOT return an error. Warn about this condition at the call site.
		return false, nil
	}
	return true, nil
}

// ClusterState holds the state during the processing of remote clusters.
type ClusterState struct {
	localOldClusters       []map[string]interface{}               // current clustermesh section of helm values
	localNewClusters       []map[string]interface{}               // new clustermesh section of helm values
	localHelmValues        map[string]interface{}                 // localOldClusters + localNewClusters => local helm values generated
	remoteHelmValuesMesh   map[string]map[string]interface{}      // helm values for all remote cluster in mesh mode
	remoteHelmValuesBD     map[string]map[string]interface{}      // helm values for all remote cluster bidirectional mode
	remoteClients          map[string]*k8s.Client                 // Map of remoteClients to apply remoteHelmValuesMesh or remoteHelmValuesBD
	remoteOldClustersAll   map[string][]map[string]interface{}    // current clustermesh sections of helm values for remote clusters
	remoteHelmValuesDelete map[*k8s.Client]map[string]interface{} // helm values for all remote clusters to disconnect
	remoteNewCluster       map[string]interface{}                 // local cluster to add to remote clusters
	remoteClusterNames     []string                               // names of remote clusters for displaying logs
	remoteClusterNamesAi   []string                               // names of remote clusters for remove sections
}

func processLocalClient(localRelease *release.Release) (*ClusterState, error) {
	state := &ClusterState{}
	var err error

	state.localOldClusters, err = getOldClusters(localRelease.Config)
	if err != nil {
		return state, err
	}

	return state, nil
}

func (k *K8sClusterMesh) processSingleRemoteClient(ctx context.Context, remoteClient *k8s.Client, aiLocal *accessInformation, state *ClusterState) error {
	state.remoteClusterNames = append(state.remoteClusterNames, remoteClient.ClusterName())
	aiRemote, err := k.getAccessInfoForConnect(ctx, remoteClient, k.params.DestinationEndpoints)
	if err != nil {
		return err
	}

	err = k.validateInfoForConnect(aiLocal, aiRemote)
	if err != nil {
		return err
	}

	// Validate that CA certificates match between the two clusters
	match, err := k.validateCAMatch(aiLocal, aiRemote)
	if err != nil {
		return err
	} else if !match {
		k.Log("⚠️ Cilium CA certificates do not match between clusters. Multicluster features will be limited!")
	}

	// Expand those values to include the clustermesh configuration
	newCluster := getCluster(aiRemote, !match)
	state.localNewClusters = append(state.localNewClusters, newCluster)

	// Get existing helm values for the remote cluster
	remoteRelease, err := getRelease(remoteClient, k.params)
	if err != nil {
		k.Log("❌ Unable to find Helm release for the remote cluster")
		return err
	}

	remoteOldClusters, err := getOldClusters(remoteRelease.Config)
	if err != nil {
		return err
	}
	if state.remoteOldClustersAll == nil {
		state.remoteOldClustersAll = make(map[string][]map[string]interface{})
	}
	state.remoteOldClustersAll[aiRemote.ClusterName] = remoteOldClusters

	state.remoteNewCluster = getCluster(aiLocal, !match)
	remoteHelmValues, err := mergeClusters(remoteOldClusters, []map[string]interface{}{state.remoteNewCluster}, "")
	if err != nil {
		return err
	}
	if state.remoteHelmValuesBD == nil {
		state.remoteHelmValuesBD = make(map[string]map[string]interface{})
	}
	state.remoteHelmValuesBD[aiRemote.ClusterName] = remoteHelmValues

	if state.remoteClients == nil {
		state.remoteClients = make(map[string]*k8s.Client)
	}
	state.remoteClients[aiRemote.ClusterName] = remoteClient
	return nil
}

func (k *K8sClusterMesh) processRemoteClients(ctx context.Context, remoteClients []*k8s.Client, localClient *k8s.Client, state *ClusterState) error {
	aiLocal, err := k.getAccessInfoForConnect(ctx, localClient, k.params.SourceEndpoints)
	if err != nil {
		return err
	}

	for _, remoteClient := range remoteClients {
		err := k.processSingleRemoteClient(ctx, remoteClient, aiLocal, state)
		if err != nil {
			return err
		}
	}

	return nil
}

func processRemoteHelmValuesMesh(state *ClusterState) error {
	if state.remoteHelmValuesMesh == nil {
		state.remoteHelmValuesMesh = make(map[string]map[string]interface{})
	}
	remoteNewClusters := append(state.localNewClusters, state.remoteNewCluster)
	for aiClusterName, remoteOldClusters := range state.remoteOldClustersAll {
		remoteHelmValues, err := mergeClusters(remoteOldClusters, remoteNewClusters, aiClusterName)
		if err != nil {
			return err
		}
		state.remoteHelmValuesMesh[aiClusterName] = remoteHelmValues
	}
	return nil
}

func (k *K8sClusterMesh) connectLocalWithHelm(ctx context.Context, localClient *k8s.Client, state *ClusterState) error {
	var err error
	state.localHelmValues, err = mergeClusters(state.localOldClusters, state.localNewClusters, "")
	if err != nil {
		return err
	}

	k.Log("ℹ️ Configuring Cilium in cluster %s to connect to cluster %s",
		localClient.ClusterName(), strings.Join(state.remoteClusterNames, ","))
	return k.helmUpgrade(ctx, localClient, state.localHelmValues)
}

func (k *K8sClusterMesh) helmUpgrade(ctx context.Context, client *k8s.Client, values map[string]interface{}) error {
	upgradeParams := helm.UpgradeParameters{
		Namespace:   k.params.Namespace,
		Name:        k.params.HelmReleaseName,
		Values:      values,
		ResetValues: false,
		ReuseValues: true,
	}

	_, err := helm.Upgrade(ctx, client.HelmActionConfig, upgradeParams)
	if err != nil {
		return err
	}
	return nil
}

func (k *K8sClusterMesh) checkConnectionMode() error {
	validModes := []string{
		defaults.ClusterMeshConnectionModeBidirectional,
		defaults.ClusterMeshConnectionModeMesh,
		defaults.ClusterMeshConnectionModeUnicast,
	}

	for _, mode := range validModes {
		if k.params.ConnectionMode == mode {
			return nil
		}
	}

	k.Log("❌ %s is not a correct connection mode.", k.params.ConnectionMode)
	k.Log("Available connection modes: %s", strings.Join(validModes, ", "))
	return errors.New("Bad connection mode")
}

// ConnectWithHelm enables clustermesh using a Helm Upgrade
// action. Certificates are generated via the Helm chart's cronJob
// (certgen) mode. As with classic mode, only autodetected IP-based
// clustermesh-apiserver Service endpoints are currently supported.
func (k *K8sClusterMesh) ConnectWithHelm(ctx context.Context) error {
	localClient := k.client.(*k8s.Client)
	err := k.checkConnectionMode()
	if err != nil {
		return err
	}

	localRelease, err := getRelease(localClient, k.params)
	if err != nil {
		k.Log("❌ Unable to find Helm release for the target cluster")
		return err
	}

	remoteClients, err := k.getRemoteClients()
	if err != nil {
		return err
	}

	clusterState, err := processLocalClient(localRelease)
	if err != nil {
		return err
	}

	err = k.processRemoteClients(ctx, remoteClients, localClient, clusterState)
	if err != nil {
		return err
	}

	err = processRemoteHelmValuesMesh(clusterState)
	if err != nil {
		return err
	}

	err = k.connectLocalWithHelm(ctx, localClient, clusterState)
	if err != nil {
		return err
	}

	err = k.connectRemoteWithHelm(ctx, localClient.ClusterName(), clusterState)
	if err != nil {
		return err
	}
	k.displayCompleteMessage(localClient, remoteClients, clusterState)
	return nil
}

func (k *K8sClusterMesh) displayCompleteMessage(localClient *k8s.Client, remoteClients []*k8s.Client, state *ClusterState) {
	switch k.params.ConnectionMode {
	case defaults.ClusterMeshConnectionModeBidirectional:
		for _, remoteClient := range remoteClients {
			k.Log("✅ Connected cluster %s <=> %s!", localClient.ClusterName(), remoteClient.ClusterName())
		}
	case defaults.ClusterMeshConnectionModeMesh:
		k.Log("✅ Connected clusters %s, and %s!", strings.Join(state.remoteClusterNames, ", "), localClient.ClusterName())
	case defaults.ClusterMeshConnectionModeUnicast:
		for _, remoteClient := range remoteClients {
			k.Log("✅ Connected cluster %s => %s!", localClient.ClusterName(), remoteClient.ClusterName())
		}
	}
}

func (k *K8sClusterMesh) connectRemoteWithHelm(ctx context.Context, localClusterName string, state *ClusterState) error {
	var rc map[string]*k8s.Client
	var cn []string
	var helmValues map[string]map[string]interface{}

	switch k.params.ConnectionMode {
	case defaults.ClusterMeshConnectionModeBidirectional:
		rc = state.remoteClients
		helmValues = state.remoteHelmValuesBD
		cn = []string{localClusterName}
	case defaults.ClusterMeshConnectionModeMesh:
		rc = state.remoteClients
		helmValues = state.remoteHelmValuesMesh
		cn = append(state.remoteClusterNames, localClusterName)
	}

	maxGoroutines := k.params.Parallel

	sem := make(chan struct{}, maxGoroutines)
	var wg sync.WaitGroup
	var mu lock.Mutex
	var firstErr error

	for aiClusterName, remoteClient := range rc {
		wg.Add(1)

		sem <- struct{}{}

		go func(cn []string, rc *k8s.Client, helmVals map[string]interface{}) {
			defer wg.Done()
			defer func() { <-sem }()

			if err := k.connectSingleRemoteWithHelm(ctx, rc, cn, helmVals); err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				mu.Unlock()
			}
		}(cn, remoteClient, helmValues[aiClusterName])
	}

	wg.Wait()

	return firstErr
}

func (k *K8sClusterMesh) connectSingleRemoteWithHelm(ctx context.Context, remoteClient *k8s.Client, clusterNames []string, helmValues map[string]interface{}) error {
	clusterNamesExceptRemote := removeStringFromSlice(remoteClient.ClusterName(), clusterNames)
	k.Log("ℹ️ Configuring Cilium in cluster %s to connect to cluster %s",
		remoteClient.ClusterName(), strings.Join(clusterNamesExceptRemote, ","))
	err := k.helmUpgrade(ctx, remoteClient, helmValues)
	if err != nil {
		return err
	}
	return nil
}

func (k *K8sClusterMesh) getRemoteClusterNamesAi(ctx context.Context, remoteClients []*k8s.Client) (*ClusterState, error) {
	state := &ClusterState{}

	for _, remoteClient := range remoteClients {
		aiRemote, err := k.shallowExtractAccessInfo(ctx, remoteClient)
		if err != nil {
			return state, err
		}
		state.remoteClusterNamesAi = append(state.remoteClusterNamesAi, aiRemote.ClusterName)
	}

	return state, nil
}

func (k *K8sClusterMesh) retrieveRemoteHelmValues(ctx context.Context, remoteClients []*k8s.Client, state *ClusterState) error {
	aiLocal, err := k.shallowExtractAccessInfo(ctx, k.client.(*k8s.Client))
	if err != nil {
		return err
	}
	remoteClusterNames := []string{aiLocal.ClusterName}
	if k.params.ConnectionMode == defaults.ClusterMeshConnectionModeMesh {
		remoteClusterNames = append(remoteClusterNames, state.remoteClusterNamesAi...)
	}
	for _, remoteClient := range remoteClients {
		remoteRelease, err := getRelease(remoteClient, k.params)
		if err != nil {
			k.Log("❌ Unable to find Helm release for the remote cluster")
			return err
		}
		// Modify the clustermesh config to remove the intended cluster if any
		remoteHelmValues, err := removeFromClustermeshConfig(remoteRelease.Config, remoteClusterNames)
		if err != nil {
			return err
		}
		if state.remoteHelmValuesDelete == nil {
			state.remoteHelmValuesDelete = make(map[*k8s.Client]map[string]interface{})
		}
		state.remoteHelmValuesDelete[remoteClient] = remoteHelmValues
		state.remoteClusterNames = append(state.remoteClusterNames, remoteClient.ClusterName())
	}
	return nil
}

func removeStringFromSlice(name string, names []string) []string {
	namesCopy := append([]string{}, names...)
	namesCopy = slices.DeleteFunc(namesCopy, func(n string) bool {
		return n == name
	})
	return namesCopy
}

func (k *K8sClusterMesh) valueOfFromClusterName(clusterName string, remoteClusterName string, remoteClusterNames []string) string {
	cn := clusterName
	if k.params.ConnectionMode == defaults.ClusterMeshConnectionModeMesh {
		clusterNamesExceptRemote := removeStringFromSlice(remoteClusterName, remoteClusterNames)
		clusterNamesExceptRemote = append(clusterNamesExceptRemote, clusterName)
		cn = strings.Join(clusterNamesExceptRemote, ",")
	}
	return cn
}

func (k *K8sClusterMesh) disconnectRemoteWithHelm(ctx context.Context, clusterName string, state *ClusterState) error {
	if k.params.ConnectionMode == defaults.ClusterMeshConnectionModeUnicast {
		return nil
	}
	for remoteClient, helmValues := range state.remoteHelmValuesDelete {
		cn := k.valueOfFromClusterName(clusterName, remoteClient.ClusterName(), state.remoteClusterNames)
		k.Log("ℹ️ Configuring Cilium in cluster %s to disconnect from cluster %s",
			remoteClient.ClusterName(), cn)
		err := k.helmUpgrade(ctx, remoteClient, helmValues)
		if err != nil {
			return err
		}
	}
	return nil
}

func (k *K8sClusterMesh) DisconnectWithHelm(ctx context.Context) error {
	localClient := k.client.(*k8s.Client)
	err := k.checkConnectionMode()
	if err != nil {
		return err
	}

	localRelease, err := getRelease(localClient, k.params)
	if err != nil {
		k.Log("❌ Unable to find Helm release for the target cluster")
		return err
	}

	remoteClients, err := k.getRemoteClients()
	if err != nil {
		return err
	}
	clusterState, err := k.getRemoteClusterNamesAi(ctx, remoteClients)
	if err != nil {
		return err
	}

	// Modify the clustermesh config to remove the intended cluster if any
	localHelmValues, err := removeFromClustermeshConfig(localRelease.Config, clusterState.remoteClusterNamesAi)
	if err != nil {
		return err
	}

	err = k.retrieveRemoteHelmValues(ctx, remoteClients, clusterState)
	if err != nil {
		return err
	}

	k.Log("ℹ️ Configuring Cilium in cluster %s to disconnect from cluster %s",
		localClient.ClusterName(), strings.Join(clusterState.remoteClusterNames, ","))
	err = k.helmUpgrade(ctx, localClient, localHelmValues)
	if err != nil {
		return err
	}
	err = k.disconnectRemoteWithHelm(ctx, localClient.ClusterName(), clusterState)
	if err != nil {
		return err
	}

	k.displayDisconnectedCompleteMessage(localClient, remoteClients, clusterState)

	return nil
}

func (k *K8sClusterMesh) displayDisconnectedCompleteMessage(localClient *k8s.Client, remoteClients []*k8s.Client, state *ClusterState) {
	switch k.params.ConnectionMode {
	case defaults.ClusterMeshConnectionModeBidirectional:
		for _, remoteClient := range remoteClients {
			k.Log("✅ Disconnected clusters %s <x> %s!", localClient.ClusterName(), remoteClient.ClusterName())
		}
	case defaults.ClusterMeshConnectionModeMesh:
		k.Log("✅ Disconnected clusters %s, and %s!", strings.Join(state.remoteClusterNames, ", "), localClient.ClusterName())
	case defaults.ClusterMeshConnectionModeUnicast:
		for _, remoteClient := range remoteClients {
			k.Log("✅ Disconnected clusters %s x> %s!", localClient.ClusterName(), remoteClient.ClusterName())
		}
	}
}

func getOldClusters(values map[string]interface{}) ([]map[string]interface{}, error) {
	// get current clusters config slice, if it exists
	c, found, err := unstructured.NestedFieldCopy(values, "clustermesh", "config", "clusters")
	if err != nil {
		return nil, fmt.Errorf("existing clustermesh.config is invalid")
	}
	if !found || c == nil {
		c = []interface{}{}
	}

	// parse the existing config slice
	oldClusters := make([]map[string]interface{}, 0)
	cs, ok := c.([]interface{})
	if !ok {
		return nil, fmt.Errorf("existing clustermesh.config.clusters array is invalid")
	}
	for _, m := range cs {
		cluster, ok := m.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("existing clustermesh.config.clusters array is invalid")
		}
		oldClusters = append(oldClusters, cluster)
	}

	return oldClusters, nil
}

func getCluster(ai *accessInformation, configTLS bool) map[string]interface{} {
	remoteCluster := map[string]interface{}{
		"name": ai.ClusterName,
		"ips":  []string{ai.ServiceIPs[0]},
		"port": ai.ServicePort,
	}

	// Only add TLS configuration if requested (probably because CA
	// certs do not match among clusters). Note that this is a DEGRADED
	// mode of operation in which client certificates will not be
	// renewed automatically and cross-cluster Hubble does not operate.
	if configTLS {
		remoteCluster["tls"] = map[string]interface{}{
			"cert":   base64.StdEncoding.EncodeToString(ai.ClientCert),
			"key":    base64.StdEncoding.EncodeToString(ai.ClientKey),
			"caCert": base64.StdEncoding.EncodeToString(ai.CA),
		}
	}

	return remoteCluster
}

func mergeClusters(
	oldClusters []map[string]interface{}, newClusters []map[string]interface{}, exceptCluster string) (map[string]interface{}, error) {
	clusters := map[string]map[string]interface{}{}
	for _, c := range oldClusters {
		name, ok := c["name"].(string)
		if !ok {
			return nil, fmt.Errorf("existing clustermesh.config.clusters array is invalid")
		}
		clusters[name] = c
	}
	for _, c := range newClusters {
		if c["name"].(string) != exceptCluster {
			clusters[c["name"].(string)] = c
		}
	}

	outputClusters := make([]map[string]interface{}, 0)
	for _, v := range clusters {
		outputClusters = append(outputClusters, v)
	}

	newValues := map[string]interface{}{
		"clustermesh": map[string]interface{}{
			"config": map[string]interface{}{
				"enabled":  true,
				"clusters": outputClusters,
			},
		},
	}
	return newValues, nil
}

func removeFromClustermeshConfig(values map[string]any, clusterNames []string) (map[string]any, error) {
	// get current clusters config slice, if it exists
	c, found, err := unstructured.NestedFieldCopy(values, "clustermesh", "config", "clusters")
	if err != nil {
		return nil, fmt.Errorf("existing clustermesh.config is invalid")
	}
	if !found || c == nil {
		c = []any{}
	}

	cs, ok := c.([]any)
	if !ok {
		return nil, fmt.Errorf("existing clustermesh.config.clusters array is invalid")
	}
	outputClusters := make([]map[string]any, 0, len(cs))
	for _, m := range cs {
		cluster, ok := m.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("existing clustermesh.config.clusters map is invalid")
		}
		name, ok := cluster["name"].(string)
		if ok && slices.Contains(clusterNames, name) {
			continue
		}
		outputClusters = append(outputClusters, cluster)
	}

	newValues := map[string]any{
		"clustermesh": map[string]any{
			"config": map[string]any{
				"enabled":  true,
				"clusters": outputClusters,
			},
		},
	}

	return newValues, nil
}
