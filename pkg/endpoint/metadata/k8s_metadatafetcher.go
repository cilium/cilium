// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metadata

import (
	"errors"
	"log/slog"

	"github.com/cilium/statedb"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/option"
)

var ErrPodStoreOutdated = errors.New("pod store outdated")

type EndpointMetadataFetcher interface {
	FetchK8sMetadataForEndpoint(nsName, podName, uid string) (*slim_corev1.Pod, *endpoint.K8sMetadata, error)

	FetchK8sMetadataForEndpointFromPod(p *slim_corev1.Pod) (*endpoint.K8sMetadata, error)
}

type cachedEndpointMetadataFetcher struct {
	logger     *slog.Logger
	config     *option.DaemonConfig
	db         *statedb.DB
	pods       statedb.Table[daemonk8s.LocalPod]
	namespaces statedb.Table[daemonk8s.Namespace]
}

func NewEndpointMetadataFetcher(logger *slog.Logger, config *option.DaemonConfig, db *statedb.DB, pods statedb.Table[daemonk8s.LocalPod], namespaces statedb.Table[daemonk8s.Namespace]) EndpointMetadataFetcher {
	return &cachedEndpointMetadataFetcher{
		logger:     logger,
		config:     config,
		db:         db,
		pods:       pods,
		namespaces: namespaces,
	}
}

func (cemf *cachedEndpointMetadataFetcher) FetchK8sMetadataForEndpoint(nsName, podName, uid string) (*slim_corev1.Pod, *endpoint.K8sMetadata, error) {
	p, err := cemf.getPod(nsName, podName)
	if err != nil {
		return nil, nil, err
	}

	if uid != "" && uid != string(p.GetUID()) {
		return nil, nil, ErrPodStoreOutdated
	}

	metadata, err := cemf.FetchK8sMetadataForEndpointFromPod(p)
	return p, metadata, err
}

func (cemf *cachedEndpointMetadataFetcher) FetchK8sMetadataForEndpointFromPod(p *slim_corev1.Pod) (*endpoint.K8sMetadata, error) {
	ns, err := cemf.fetchNamespace(p.Namespace)
	if err != nil {
		return nil, err
	}

	containerPorts, lbls := k8s.GetPodMetadata(cemf.logger, ns, p)
	k8sLbls := labels.Map2Labels(lbls, labels.LabelSourceK8s)
	identityLabels, infoLabels := labelsfilter.Filter(k8sLbls)
	return &endpoint.K8sMetadata{
		ContainerPorts: containerPorts,
		IdentityLabels: identityLabels,
		InfoLabels:     infoLabels,
	}, nil
}

func (cemf *cachedEndpointMetadataFetcher) fetchNamespace(nsName string) (daemonk8s.Namespace, error) {
	// If network policies are disabled, labels are not needed, the namespace
	// watcher is not running, and a namespace containing only the name is returned.
	if !option.NetworkPolicyEnabled(cemf.config) {
		return daemonk8s.Namespace{
			Name: nsName,
		}, nil
	}
	return cemf.getNamespace(nsName)
}

func (cemf *cachedEndpointMetadataFetcher) getPod(namespace, name string) (*slim_corev1.Pod, error) {
	_, initWatch := cemf.pods.Initialized(cemf.db.ReadTxn())
	<-initWatch

	pod, _, found := cemf.pods.Get(cemf.db.ReadTxn(), daemonk8s.PodByName(namespace, name))
	if !found {
		return nil, k8sErrors.NewNotFound(schema.GroupResource{
			Group:    "core",
			Resource: "pod",
		}, name)
	}
	return pod.Pod, nil
}

func (cemf *cachedEndpointMetadataFetcher) getNamespace(namespace string) (daemonk8s.Namespace, error) {
	_, initWatch := cemf.namespaces.Initialized(cemf.db.ReadTxn())
	<-initWatch

	ns, _, found := cemf.namespaces.Get(cemf.db.ReadTxn(), daemonk8s.NamespaceIndex.Query(namespace))
	if !found {
		return daemonk8s.Namespace{}, k8sErrors.NewNotFound(schema.GroupResource{
			Group:    "core",
			Resource: "namespace",
		}, namespace)
	}
	return ns, nil
}
