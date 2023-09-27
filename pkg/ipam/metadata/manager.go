// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metadata

import (
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"

	"github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ipam-metadata-manager")
)

type ManagerStoppedError struct{}

func (m *ManagerStoppedError) Error() string {
	return "ipam-metadata-manager has been stopped"
}

type ResourceNotFound struct {
	Resource  string
	Name      string
	Namespace string
}

func (r *ResourceNotFound) Error() string {
	name := r.Name
	if r.Namespace != "" {
		name = r.Namespace + "/" + r.Name
	}
	return fmt.Sprintf("resource %s %q not found", r.Resource, name)
}

func (r *ResourceNotFound) Is(target error) bool {
	targetErr, ok := target.(*ResourceNotFound)
	if !ok {
		return false
	}
	if r != nil && targetErr.Resource != "" {
		return r.Resource == targetErr.Resource
	}
	return true
}

type Manager struct {
	namespaceResource resource.Resource[*slim_core_v1.Namespace]
	namespaceStore    resource.Store[*slim_core_v1.Namespace]
	podResource       k8s.LocalPodResource
	podStore          resource.Store[*slim_core_v1.Pod]
}

func (m *Manager) Start(ctx hive.HookContext) (err error) {
	m.namespaceStore, err = m.namespaceResource.Store(ctx)
	if err != nil {
		return fmt.Errorf("failed to obtain namespace store: %w", err)
	}

	m.podStore, err = m.podResource.Store(ctx)
	if err != nil {
		return fmt.Errorf("failed to obtain pod store: %w", err)
	}

	return nil
}

func (m *Manager) Stop(ctx hive.HookContext) error {
	m.namespaceStore = nil
	m.podStore = nil
	return nil
}

func splitK8sPodName(owner string) (namespace, name string, ok bool) {
	// Require namespace/name format
	namespace, name, ok = strings.Cut(owner, "/")
	if !ok {
		return "", "", false
	}
	// Check if components are a valid namespace name and pod name
	if validation.IsDNS1123Subdomain(namespace) != nil ||
		validation.IsDNS1123Subdomain(name) != nil {
		return "", "", false
	}
	return namespace, name, true
}

func determinePoolByAnnotations(annotations map[string]string, family ipam.Family) (pool string, ok bool) {
	switch family {
	case ipam.IPv4:
		if annotations[annotation.IPAMIPv4PoolKey] != "" {
			return annotations[annotation.IPAMIPv4PoolKey], true
		} else if annotations[annotation.IPAMPoolKey] != "" {
			return annotations[annotation.IPAMPoolKey], true
		}
	case ipam.IPv6:
		if annotations[annotation.IPAMIPv6PoolKey] != "" {
			return annotations[annotation.IPAMIPv6PoolKey], true
		} else if annotations[annotation.IPAMPoolKey] != "" {
			return annotations[annotation.IPAMPoolKey], true
		}
	}

	return "", false
}

func (m *Manager) GetIPPoolForPod(owner string, family ipam.Family) (pool string, err error) {
	if m.namespaceStore == nil || m.podStore == nil {
		return "", &ManagerStoppedError{}
	}

	if family != ipam.IPv6 && family != ipam.IPv4 {
		return "", fmt.Errorf("invalid IP family: %s", family)
	}

	namespace, name, ok := splitK8sPodName(owner)
	if !ok {
		log.WithField("owner", owner).
			Debug("IPAM metadata request for invalid pod name, falling back to default pool")
		return ipamOption.PoolDefault, nil
	}

	// Check annotation on pod
	pod, ok, err := m.podStore.GetByKey(resource.Key{
		Name:      name,
		Namespace: namespace,
	})
	if err != nil {
		return "", fmt.Errorf("failed to lookup pod %q: %w", namespace+"/"+name, err)
	} else if !ok {
		return "", &ResourceNotFound{Resource: "Pod", Namespace: namespace, Name: name}
	} else if ippool, ok := determinePoolByAnnotations(pod.Annotations, family); ok {
		return ippool, nil
	}

	// Check annotation on namespace
	podNamespace, ok, err := m.namespaceStore.GetByKey(resource.Key{
		Name: namespace,
	})
	if err != nil {
		return "", fmt.Errorf("failed to lookup namespace %q: %w", namespace, err)
	} else if !ok {
		return "", &ResourceNotFound{Resource: "Namespace", Name: namespace}
	} else if ippool, ok := determinePoolByAnnotations(podNamespace.Annotations, family); ok {
		return ippool, nil
	}

	// Fallback to default pool
	return ipamOption.PoolDefault, nil
}
