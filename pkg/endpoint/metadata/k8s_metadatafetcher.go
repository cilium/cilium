// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metadata

import (
	"errors"
	"log/slog"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/option"
)

var PodStoreOutdatedErr = errors.New("pod store outdated")

type EndpointMetadataFetcher interface {
	// FetchK8sMetadataForEndpoint wraps the k8s package to fetch and provide
	// endpoint metadata.
	// The returned pod is deepcopied which means the its fields can be written
	// into. Returns an error If a uid is given, and the uid of the retrieved
	// pod does not match it.
	FetchK8sMetadataForEndpoint(nsName, podName, uid string) (*slim_corev1.Pod, *endpoint.K8sMetadata, error)

	FetchK8sMetadataForEndpointFromPod(p *slim_corev1.Pod) (*endpoint.K8sMetadata, error)
}

type cachedEndpointMetadataFetcher struct {
	logger                *slog.Logger
	config                *option.DaemonConfig
	k8sPodMetadataFetcher k8sPodMetadataFetcher
}

func NewEndpointMetadataFetcher(logger *slog.Logger, config *option.DaemonConfig, k8sPodMetadataFetcher k8sPodMetadataFetcher) EndpointMetadataFetcher {
	return &cachedEndpointMetadataFetcher{
		logger:                logger,
		config:                config,
		k8sPodMetadataFetcher: k8sPodMetadataFetcher,
	}
}

type k8sPodMetadataFetcher interface {
	GetCachedNamespace(nsName string) (*slim_corev1.Namespace, error)
	GetCachedPod(nsName, podName string) (*slim_corev1.Pod, error)
}

func (cemf *cachedEndpointMetadataFetcher) FetchK8sMetadataForEndpoint(nsName, podName, uid string) (*slim_corev1.Pod, *endpoint.K8sMetadata, error) {
	p, err := cemf.k8sPodMetadataFetcher.GetCachedPod(nsName, podName)
	if err != nil {
		return nil, nil, err
	}

	if uid != "" && uid != string(p.GetUID()) {
		return nil, nil, PodStoreOutdatedErr
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

func (cemf *cachedEndpointMetadataFetcher) fetchNamespace(nsName string) (*slim_corev1.Namespace, error) {
	// If network policies are disabled, labels are not needed, the namespace
	// watcher is not running, and a namespace containing only the name is returned.
	if !option.NetworkPolicyEnabled(cemf.config) {
		return &slim_corev1.Namespace{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name: nsName,
			},
		}, nil
	}
	return cemf.k8sPodMetadataFetcher.GetCachedNamespace(nsName)
}
