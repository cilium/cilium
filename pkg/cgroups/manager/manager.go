// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"os"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"

	"github.com/cilium/cilium/pkg/cgroups"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "cgroup-manager")
	// Channel buffer size for pod events in order to not block callers
	podEventsChannelSize = 20
)

// Pod events processed by CgroupManager
const (
	podAddEvent = iota
	podUpdateEvent
	podDeleteEvent
	podGetMetadataEvent
	podDumpMetadataEvent
)

// CgroupManager maintains Kubernetes and low-level metadata (cgroup path and
// cgroup id) for local pods and their containers. In order to do that, it defines
// and implements callback functions that are called on Kubernetes pod watcher events.
// It also exposes APIs to read the saved metadata.
//
// The manager's internals are synchronized via a channel, and must not be
// accessed/updated outside this channel.
//
// During initialization, the manager checks for a valid cgroup path pathProvider.
// If it fails to find a pathProvider, it will ignore all the subsequent pod events.
type CgroupManager struct {
	// Map of pod metadata indexed by their UIDs
	podMetadataById map[podUID]*podMetadata
	// Map of container metadata indexed by their cgroup ids
	containerMetadataByCgrpId map[uint64]*containerMetadata
	// Buffered channel to receive pod events
	podEvents chan podEvent
	// Cgroup path provider
	pathProvider cgroupPathProvider
	// Object to get cgroup path provider
	checkPathProvider *sync.Once
	// Flag to check if manager is enabled, and processing events
	enabled bool
	// Channel to shut down manager
	shutdown chan struct{}
	// Interface to do cgroups related operations
	cgroupsChecker cgroup
}

// PodMetadata stores selected metadata of a pod populated via Kubernetes watcher events.
type PodMetadata struct {
	Name      string
	Namespace string
	IPs       []string
}

// FullPodMetadata stores selected metadata of a pod and associated containers.
type FullPodMetadata struct {
	Name       string
	Namespace  string
	Containers []*cgroupMetadata
	IPs        []string
}

type cgroupMetadata struct {
	CgroupId   uint64
	CgroupPath string
}

// NewCgroupManager returns an initialized version of CgroupManager.
func NewCgroupManager() *CgroupManager {
	return initManager(nil, cgroupImpl{}, podEventsChannelSize)
}

func (m *CgroupManager) OnAddPod(pod *v1.Pod) {
	if pod.Spec.NodeName != nodetypes.GetName() {
		return
	}
	m.podEvents <- podEvent{
		pod:       pod,
		eventType: podAddEvent,
	}
}

func (m *CgroupManager) OnUpdatePod(oldPod, newPod *v1.Pod) {
	if newPod.Spec.NodeName != nodetypes.GetName() {
		return
	}
	m.podEvents <- podEvent{
		pod:       newPod,
		oldPod:    oldPod,
		eventType: podUpdateEvent,
	}
}

func (m *CgroupManager) OnDeletePod(pod *v1.Pod) {
	if pod.Spec.NodeName != nodetypes.GetName() {
		return
	}
	m.podEvents <- podEvent{
		pod:       pod,
		eventType: podDeleteEvent,
	}
}

// GetPodMetadataForContainer returns pod metadata for the given container
// cgroup id in case of success, or nil otherwise.
func (m *CgroupManager) GetPodMetadataForContainer(cgroupId uint64) *PodMetadata {
	if !m.enabled {
		return nil
	}
	podMetaOut := make(chan *PodMetadata)

	m.podEvents <- podEvent{
		cgroupId:       cgroupId,
		eventType:      podGetMetadataEvent,
		podMetadataOut: podMetaOut,
	}
	select {
	// We either receive pod metadata, or zero value when the channel is closed.
	case pm := <-podMetaOut:
		return pm
	}
}

func (m *CgroupManager) DumpPodMetadata() []*FullPodMetadata {
	if !m.enabled {
		return nil
	}
	allMetaOut := make(chan []*FullPodMetadata)

	m.podEvents <- podEvent{
		eventType:      podDumpMetadataEvent,
		allMetadataOut: allMetaOut,
	}
	select {
	case cm := <-allMetaOut:
		return cm
	}
}

// Close should only be called once from daemon close.
func (m *CgroupManager) Close() {
	close(m.shutdown)
}

type podUID = string

type podMetadata struct {
	name       string
	namespace  string
	ips        []string
	containers map[string]struct{}
}

type containerMetadata struct {
	cgroupId   uint64
	cgroupPath string
	podId      string
}

type podEvent struct {
	pod            *v1.Pod
	oldPod         *v1.Pod
	cgroupId       uint64
	eventType      int
	podMetadataOut chan *PodMetadata
	allMetadataOut chan []*FullPodMetadata
}

type fs interface {
	Stat(name string) (os.FileInfo, error)
}

type cgroup interface {
	GetCgroupID(cgroupPath string) (uint64, error)
}

type cgroupImpl struct{}

func (c cgroupImpl) GetCgroupID(cgroupPath string) (uint64, error) {
	return cgroups.GetCgroupID(cgroupPath)
}

func initManager(provider cgroupPathProvider, cg cgroup, channelSize int) *CgroupManager {
	m := &CgroupManager{
		podMetadataById:           make(map[string]*podMetadata),
		containerMetadataByCgrpId: make(map[uint64]*containerMetadata),
		podEvents:                 make(chan podEvent, channelSize),
		shutdown:                  make(chan struct{}),
	}
	m.cgroupsChecker = cg
	m.checkPathProvider = new(sync.Once)
	m.pathProvider = provider

	m.enable()
	go m.processPodEvents()

	return m
}

func (m *CgroupManager) enable() {
	if !option.Config.EnableSocketLBTracing {
		m.enabled = false
		return
	}
	m.enabled = true
	m.checkPathProvider.Do(func() {
		if m.pathProvider != nil {
			return
		}
		var err error
		if m.pathProvider, err = getCgroupPathProvider(); err != nil {
			log.Warn("No valid cgroup base path found: socket load-balancing tracing with Hubble will not work." +
				"See the kubeproxy-free guide for more details.")
			m.enabled = false
		}
	})

	if m.enabled {
		log.Info("Cgroup metadata manager is enabled")
	}
}

func (m *CgroupManager) processPodEvents() {
	for {
		select {
		case ev := <-m.podEvents:
			if !m.enabled {
				continue
			}
			switch ev.eventType {
			case podAddEvent, podUpdateEvent:
				m.updatePodMetadata(ev.pod, ev.oldPod)
			case podDeleteEvent:
				m.deletePodMetadata(ev.pod)
			case podGetMetadataEvent:
				m.getPodMetadata(ev.cgroupId, ev.podMetadataOut)
			case podDumpMetadataEvent:
				m.dumpPodMetadata(ev.allMetadataOut)
			}
		case <-m.shutdown:
			return
		}
	}
}

func (m *CgroupManager) updatePodMetadata(pod, oldPod *v1.Pod) {
	id := string(pod.ObjectMeta.UID)
	pm, ok := m.podMetadataById[id]
	if !ok {
		// Fill in pod static metadata.
		pm = &podMetadata{
			name:      pod.Name,
			namespace: pod.Namespace,
		}
		m.podMetadataById[id] = pm
	}
	if oldPod != nil && oldPod.Status.DeepEqual(&pod.Status) || len(pod.Status.PodIPs) == 0 {
		return
	}
	// Only update the metadata that can change. This excludes pod's name,
	// namespace, id, and qos class.
	podIPs := pod.Status.PodIPs
	pm.ips = make([]string, len(podIPs))
	for i := range podIPs {
		pm.ips[i] = podIPs[i].IP
	}
	// Get metadata for pod's containers that are in the running state. Containers
	// can get re-created, and their ids can change. Update the new containers.
	// Pod's metadata including its containers map will be deleted when the pod
	// is deleted.
	numContainers := len(pod.Status.ContainerStatuses)
	if pm.containers == nil && numContainers > 0 {
		pm.containers = make(map[string]struct{})
	}
	currContainers := make(map[string]struct{}, numContainers)
	for _, c := range pod.Status.ContainerStatuses {
		var cId string
		if cId = c.ContainerID; cId == "" || c.State.Running == nil {
			continue
		}
		// The container ID field is of the form: <container-runtime>://<containerID>
		// Example:containerd://e275d1a37782ab30008aa3ae6666cccefe53b3a14a2ab5a8dc459939107c8c0e
		_, after, found := strings.Cut(cId, "//")
		if !found || after == "" {
			log.WithFields(logrus.Fields{
				logfields.K8sPodName:   pod.Name,
				logfields.K8sNamespace: pod.Namespace,
				"container-id":         cId,
			}).Error("unexpected container ID")
			continue
		}
		cId = after
		if _, ok := pm.containers[cId]; ok {
			currContainers[cId] = struct{}{}
			// Container cgroup path doesn't change as long as the container id
			// is the same.
			continue
		}
		pm.containers[cId] = struct{}{}
		currContainers[cId] = struct{}{}

		// Container could've been gone, so don't log any errors.
		cgrpPath, err := m.pathProvider.getContainerPath(id, cId, pod.Status.QOSClass)
		if err != nil {
			log.WithFields(logrus.Fields{
				logfields.K8sPodName:   pod.Name,
				logfields.K8sNamespace: pod.Namespace,
				"container-id":         cId,
			}).WithError(err).Debugf("failed to get container metadata")
			continue
		}
		cgrpId, err := m.cgroupsChecker.GetCgroupID(cgrpPath)
		if err != nil {
			log.WithFields(logrus.Fields{
				logfields.K8sPodName:   pod.Name,
				logfields.K8sNamespace: pod.Namespace,
				"cgroup-path":          cgrpPath,
			}).WithError(err).Debugf("failed to get cgroup id")
			continue
		}
		m.containerMetadataByCgrpId[cgrpId] = &containerMetadata{
			cgroupId:   cgrpId,
			cgroupPath: cgrpPath,
			podId:      id,
		}
	}
	// Clean up any pod's old containers.
	if oldPod != nil {
		for _, c := range oldPod.Status.ContainerStatuses {
			// Pod status fields other than containers can be updated so check for
			// containers that were deleted.
			if _, ok := currContainers[c.ContainerID]; !ok {
				delete(pm.containers, c.ContainerID)
			}
		}
	}
}

func (m *CgroupManager) deletePodMetadata(pod *v1.Pod) {
	podId := string(pod.ObjectMeta.UID)

	if _, ok := m.podMetadataById[podId]; !ok {
		return
	}
	for k, cm := range m.containerMetadataByCgrpId {
		if cm.podId == podId {
			delete(m.containerMetadataByCgrpId, k)
		}
	}
	delete(m.podMetadataById, podId)
}

func (m *CgroupManager) getPodMetadata(cgroupId uint64, podMetadataOut chan *PodMetadata) {
	cm, ok := m.containerMetadataByCgrpId[cgroupId]
	if !ok {
		close(podMetadataOut)
		return
	}

	pm, ok := m.podMetadataById[cm.podId]
	if !ok {
		close(podMetadataOut)
		return
	}
	podMetadata := PodMetadata{
		Name:      pm.name,
		Namespace: pm.namespace,
	}
	podMetadata.IPs = append(podMetadata.IPs, pm.ips...)
	log.WithFields(logrus.Fields{
		"container-cgroup-id": cgroupId,
	}).Debugf("Pod metadata: %+v", podMetadata)

	podMetadataOut <- &podMetadata
	close(podMetadataOut)
}

func (m *CgroupManager) dumpPodMetadata(allMetadataOut chan []*FullPodMetadata) {
	allMetas := make(map[string]*FullPodMetadata)
	for _, cm := range m.containerMetadataByCgrpId {
		pm, ok := m.podMetadataById[cm.podId]
		if !ok {
			log.WithFields(logrus.Fields{
				"container-cgroup-id": cm.cgroupId,
			}).Debugf("Pod metadata not found")
			continue
		}
		fullPm, ok := allMetas[cm.podId]
		if !ok {
			fullPm = &FullPodMetadata{
				Name:      pm.name,
				Namespace: pm.namespace,
			}
			fullPm.IPs = append(fullPm.IPs, pm.ips...)
			allMetas[cm.podId] = fullPm
		}
		cgroupMetadata := &cgroupMetadata{
			CgroupId:   cm.cgroupId,
			CgroupPath: cm.cgroupPath,
		}
		fullPm.Containers = append(fullPm.Containers, cgroupMetadata)
	}

	allMetadataOut <- maps.Values(allMetas)
	close(allMetadataOut)
}
