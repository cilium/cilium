package endpoint

import (
	"errors"
	"fmt"

	agentk8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/statedb"
)

type MetadataResolver interface {
	GetPodMetadata(ns, podName, uid string) (pod *slim_corev1.Pod, k8sMetadata K8sMetadata, err error)
}

var ErrPodOutdated = errors.New("pod outdated")

func NewMetadataResolver(
	db *statedb.DB,
	pods statedb.Table[agentk8s.LocalPod],
	namespaces statedb.Table[agentk8s.Namespace],
) MetadataResolver {
	return metadataResolver{db, pods, namespaces}
}

type metadataResolver struct {
	db         *statedb.DB
	pods       statedb.Table[agentk8s.LocalPod]
	namespaces statedb.Table[agentk8s.Namespace]
}

// GetPodMetadata implements MetadataResolver.
func (m metadataResolver) GetPodMetadata(nsName string, podName string, uid string) (pod *slim_corev1.Pod, k8sMetadata K8sMetadata, err error) {
	txn := m.db.ReadTxn()

	// Wait for the pod table to be fully populated before querying.
	_, initWatch := m.pods.Initialized(txn)
	<-initWatch

	localPod, _, found := m.pods.Get(txn, agentk8s.PodByName(nsName, podName))
	if !found {
		return nil, K8sMetadata{}, fmt.Errorf("pod %s/%s not found", nsName, podName)
	}
	pod = localPod.Pod

	if uid != "" && uid != string(pod.GetUID()) {
		return nil, K8sMetadata{}, ErrPodOutdated
	}

	// Wait for the namespace table to be fully populated before querying.
	_, initWatch = m.namespaces.Initialized(txn)
	<-initWatch

	ns, _, found := m.namespaces.Get(txn, agentk8s.NamespaceByName(nsName))
	if !found {
		return nil, K8sMetadata{}, fmt.Errorf("namespace %q not found", nsName)
	}

	containerPorts, lbls := k8s.GetPodMetadata(ns, pod)
	k8sLbls := labels.Map2Labels(lbls, labels.LabelSourceK8s)
	identityLabels, infoLabels := labelsfilter.Filter(k8sLbls)
	return pod, K8sMetadata{
		ContainerPorts: containerPorts,
		IdentityLabels: identityLabels,
		InfoLabels:     infoLabels,
	}, nil
}

var _ MetadataResolver = metadataResolver{}
