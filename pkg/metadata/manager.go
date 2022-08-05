package metadata

import (
	"strings"

	"github.com/cilium/cilium/pkg/cgroups"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

// Manager keeps a mapping of pod and pod's container related Kubernetes as well
// low-level metadata. In order to do that, it defines and implements callback
// functions that are called on Kubernetes pod watcher events. Additionally, it
// instantiates a gRPC container runtime interface (CRI) client that communicates
// with the underlying container runtime to get low-level metadata.
// It also exposes APIs to read the saved metadata.
type Manager struct {
	// Map of pod metadata indexed by their ids
	podMetadataById map[string]*podMetadata
	// Map of container metadata indexed by their cgroup ids
	containerMetadata map[uint64]*containerMetadata
	// Channel to receive pod events
	podEvents chan podEvent
	// TODO
	// shutdown channel?
}

type PodMetadata struct {
	name      string
	namespace string
	ips       []v1.PodIP
}

const (
	PodAddEvent = iota
	PodUpdateEvent
	PodDeleteEvent
	PodMetadataEvent
)

func NewManager() *Manager {
	log.Info("aditi-debug init cri")
	initCRIClient()
	m := &Manager{
		podMetadataById:   make(map[string]*podMetadata),
		containerMetadata: make(map[uint64]*containerMetadata),
		podEvents:         make(chan podEvent),
	}
	go m.processPodEvents()
	return m
}

func (m *Manager) OnAddPod(pod *v1.Pod) {
	m.podEvents <- podEvent{
		pod:       pod,
		eventType: PodAddEvent,
	}
}

func (m *Manager) OnUpdatePod(pod *v1.Pod) {
	m.podEvents <- podEvent{
		pod:       pod,
		eventType: PodUpdateEvent,
	}
}

func (m *Manager) OnDeletePod(pod *v1.Pod) {
	m.podEvents <- podEvent{
		pod:       pod,
		eventType: PodDeleteEvent,
	}
}

// GetParentPodMetadata returns parent pod metadata for the given container
// cgroup id in case of success, or nil otherwise.
func (m *Manager) GetParentPodMetadata(cgroupId uint64) *PodMetadata {
	podMetaOut := make(chan PodMetadata)

	m.podEvents <- podEvent{
		cgroupId:       cgroupId,
		eventType:      PodMetadataEvent,
		podMetadataOut: podMetaOut,
	}
	select {
	// We either receive pod metadata, or zero value when the channel is closed.
	case pm := <-podMetaOut:
		return &pm
	}
}

type podMetadata struct {
	name       string
	namespace  string
	id         string
	ips        []v1.PodIP
	containers map[string]struct{}
}

type containerMetadata struct {
	cgroupId    uint64
	cgroupPath  string
	parentPodId string
}

type podEvent struct {
	pod            *v1.Pod
	cgroupId       uint64
	eventType      int
	podMetadataOut chan PodMetadata
}

func (m *Manager) processPodEvents() {
	for {
		select {
		case ev := <-m.podEvents:
			switch ev.eventType {
			case PodAddEvent, PodUpdateEvent:
				m.updatePodMetadata(ev.pod)
			case PodDeleteEvent:
				m.deletePodMetadata(ev.pod)
			case PodMetadataEvent:
				m.getParentPodMetadata(ev.cgroupId, ev.podMetadataOut)
			}
		}
	}
}

func (m *Manager) updatePodMetadata(pod *v1.Pod) {
	id := string(pod.ObjectMeta.UID)
	p, ok := m.podMetadataById[id]
	if !ok {
		// Fill in pod static metadata.
		p = &podMetadata{
			id:        id,
			name:      pod.Name,
			namespace: pod.Namespace,
		}
		m.podMetadataById[id] = p
	}
	// Only update the metadata that can change. This excludes pod's name, namespace,
	// and id.
	podIPs := pod.Status.PodIPs
	p.ips = make([]v1.PodIP, len(podIPs))
	for i := range podIPs {
		p.ips[i] = podIPs[i]
	}
	if p.containers == nil && len(pod.Status.ContainerStatuses) > 0 {
		p.containers = make(map[string]struct{})
	}
	// Get metadata for pod's containers.
	for _, c := range pod.Status.ContainerStatuses {
		if cId := c.ContainerID; cId != "" {
			if _, ok := p.containers[cId]; ok {
				// Container cgroup path doesn't change.
				// TODO: container IDs can change.
				continue
			}
			p.containers[cId] = struct{}{}
			// The container ID field is of the form: <container-runtime>://<containerID>
			// Example:containerd://e275d1a37782ab30008aa3ae6666cccefe53b3a14a2ab5a8dc459939107c8c0e
			_, after, found := strings.Cut(cId, "//")
			if !found {
				log.Errorf("unexpected container ID: %s", cId)
				continue
			}
			cId = after

			cgrpPath, err := GetContainerCgroupPath(cId)
			if err != nil {
				log.Errorf("failed to get container metadata for (%s): %v", cId, err)
				continue
			}
			fullCgrpPath := cgroups.GetCgroupRoot() + cgrpPath
			log.Infof("aditi-debug-cgrp %s %s", fullCgrpPath, cId)
			cgrpId, err := cgroups.GetCgroupID(fullCgrpPath)
			if err != nil {
				log.Errorf("failed to get cgroup id for cgroup path (%s): %v", fullCgrpPath, err)
				continue
			}
			log.Infof("aditi-debug-cgrp-id %s %d", fullCgrpPath, cgrpId)
			m.containerMetadata[cgrpId] = &containerMetadata{
				cgroupId:    cgrpId,
				cgroupPath:  fullCgrpPath,
				parentPodId: id,
			}
		}
	}
}

func (m *Manager) deletePodMetadata(pod *v1.Pod) {
	id := string(pod.ObjectMeta.UID)

	if _, ok := m.podMetadataById[id]; !ok {
		return
	}
	for k, cm := range m.containerMetadata {
		if cm.parentPodId == id {
			delete(m.containerMetadata, k)
		}
	}
	delete(m.podMetadataById, id)
}

func (m *Manager) getParentPodMetadata(cgroupId uint64, podMetadataOut chan PodMetadata) {
	cm, ok := m.containerMetadata[cgroupId]
	if !ok {
		log.Debugf("Metadata not found for container: %d", cgroupId)
		close(podMetadataOut)
	}

	pm, ok := m.podMetadataById[cm.parentPodId]
	if !ok {
		log.Debugf("Parent pod metadata not found for container: %d", cgroupId)
		close(podMetadataOut)
	}
	podMetadata := PodMetadata{
		name:      pm.name,
		namespace: pm.namespace,
	}
	podMetadata.ips = append(podMetadata.ips, pm.ips...)
	log.Debugf("Parent pod metadata for container (%d): %+v", cgroupId, podMetadata)

	podMetadataOut <- podMetadata
	close(podMetadataOut)
}
