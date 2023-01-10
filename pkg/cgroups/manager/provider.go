// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/cilium/pkg/cgroups"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

var (
	cgroupRoot = cgroups.GetCgroupRoot()
	// example default cgroup path in kubernetes environments
	// /kubepods/burstable/pod1858680e-b044-4fd5-9dd4-f137e30e2180/e275d1a37782ab30008aa3ae6666cccefe53b3a14a2ab5a8dc459939107c8c0
	defaultCgroupBasePath = "/kubepods"
	// example cgroup path in environments with systemd cgroup driver
	// /kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-pod9ac48755_3968_48e4_b9dc_6d4b69f3bb42.slice/cri-containerd-3baf66ee56a52a8765c3deb2444315411a888fa3e2f8f7ddd75e9ded3c34425e.scope
	systemdCgroupBasePath = "/kubepods.slice"
	// example cgroup path in nested environments like kind
	// /kubelet/kubepods/pod4841248b-fc2f-41f4-9981-a685bf840ab5/d8f227cc24940cfdce8d8e601f3b92242ac9661b0e83f0ea57fdea1cb6bc93ec
	nestedCgroupBasePath = "/kubelet" + "/kubepods"
	// example cgroup path in nested environments with systemd cgroup driver
	// /kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-besteffort.slice/kubepods-besteffort-pod9ac48755_3968_48e4_b9dc_6d4b69f3bb42.slice/cri-containerd-3baf66ee56a52a8765c3deb2444315411a888fa3e2f8f7ddd75e9ded3c34425e.scope
	nestedSystemdCgroupBasePath = "/kubelet.slice/kubelet-kubepods.slice/"
	// List of cgroup providers for different environments
	providers = []cgroupPathProvider{
		newDefaultProvider(),
		newSystemdProvider(),
		newNestedProvider(),
		newNestedSystemdProvider(),
	}
	// Prefix added to container cgroup sub-path by containerd runtime
	containerdPrefix = "cri-containerd-"
	// Prefix added to container cgroup sub-path by crio runtime
	crioPrefix = "crio-"
	// Prefix added to container cgroup sub-path by crio runtime
	dockerPrefix = "docker-"
	// List of container runtime prefixes that can appear in container cgroup paths in systemd environments.
	containerRuntimePrefixes = []string{containerdPrefix, crioPrefix, dockerPrefix}
	// Suffix added to cgroup sub-paths for systemd
	systemdSuffix = ".slice"
	// Suffix added to container cgroup sub-paths for systemd
	systemdEndSuffix = ".scope"
	// File system interface for dependency injection
	fschecker fs = fsImpl{}
)

func getCgroupPathProvider() (cgroupPathProvider, error) {
	for _, provider := range providers {
		if _, err := provider.getBasePath(); err == nil {
			return provider, nil
		}
	}

	return nil, fmt.Errorf("no valid cgroup path provider found")
}

type cgroupPathProvider interface {
	getBasePath() (string, error)
	getContainerPath(podId string, containerId string, qos v1.PodQOSClass) (string, error)
}

type defaultProvider struct {
	basePath string
}

type systemdProvider struct {
	basePath string
}

type nestedProvider struct {
	basePath string
}

type nestedSystemProvider struct {
	basePath string
}

func newDefaultProvider() defaultProvider {
	return defaultProvider{basePath: defaultCgroupBasePath}
}

func newSystemdProvider() systemdProvider {
	return systemdProvider{basePath: systemdCgroupBasePath}
}

func newNestedProvider() nestedProvider {
	return nestedProvider{basePath: nestedCgroupBasePath}
}

func newNestedSystemdProvider() nestedSystemProvider {
	return nestedSystemProvider{basePath: nestedSystemdCgroupBasePath}
}

func (cp defaultProvider) getBasePath() (string, error) {
	return validateCgroupPath(cp.basePath)
}

func (cp defaultProvider) getContainerPath(podId string, containerId string, qos v1.PodQOSClass) (string, error) {
	return getDefaultContainerPathCommon(cp.basePath, podId, containerId, qos)
}

func (cp systemdProvider) getBasePath() (string, error) {
	return validateCgroupPath(cp.basePath)
}

func (cp systemdProvider) getContainerPath(podId string, containerId string, qos v1.PodQOSClass) (string, error) {
	subPaths := []string{"kubepods"}

	return getSystemdContainerPathCommon(subPaths, podId, containerId, qos)
}

func (cp nestedProvider) getBasePath() (string, error) {
	return validateCgroupPath(cp.basePath)
}

func (cp nestedProvider) getContainerPath(podId string, containerId string, qos v1.PodQOSClass) (string, error) {
	return getDefaultContainerPathCommon(cp.basePath, podId, containerId, qos)
}

func (cp nestedSystemProvider) getBasePath() (string, error) {
	return validateCgroupPath(cp.basePath)
}

func (cp nestedSystemProvider) getContainerPath(podId string, containerId string, qos v1.PodQOSClass) (string, error) {
	subPaths := []string{"kubelet", "kubepods"}

	return getSystemdContainerPathCommon(subPaths, podId, containerId, qos)
}

func getSystemdContainerPathCommon(subPaths []string, podId string, containerId string, qos v1.PodQOSClass) (string, error) {
	var (
		ret  string
		err  error
		path string
	)
	podIdStr := fmt.Sprintf("pod%s", podId)
	if qos == v1.PodQOSGuaranteed {
		if path, err = toSystemd(append(subPaths, podIdStr)); err != nil {
			return "", fmt.Errorf("unable to construct cgroup path %w", err)
		}
	} else {
		qosStr := strings.ToLower(string(qos))
		if path, err = toSystemd(append(subPaths, qosStr, podIdStr)); err != nil {
			return "", fmt.Errorf("unable to construct cgroup path %w", err)
		}
	}
	// construct and append container sub path with container id
	for _, prefix := range containerRuntimePrefixes {
		containerSubPath := fmt.Sprintf("%s%s%s", prefix, containerId, systemdEndSuffix)
		fullPath := filepath.Join(path, containerSubPath)
		ret, err = validateCgroupPath(fullPath)
		if err == nil {
			break
		}
	}

	return ret, err
}

func validateCgroupPath(path string) (string, error) {
	fullPath := cgroupRoot + path

	if _, err := fschecker.Stat(fullPath); err == nil {
		return fullPath, nil
	}

	return "", fmt.Errorf("no valid cgroup path found")
}

func getBaseCgroupPathForQos(path string, qos v1.PodQOSClass) string {
	if qos == v1.PodQOSGuaranteed {
		return path
	}
	return filepath.Join(path, strings.ToLower(string(qos)))
}

func getDefaultContainerPathCommon(path string, podId string, containerId string, qos v1.PodQOSClass) (string, error) {
	podIdStr := fmt.Sprintf("pod%s", podId)
	path = filepath.Join(getBaseCgroupPathForQos(path, qos), podIdStr, containerId)

	return validateCgroupPath(path)
}

// Sets up dependency injection for unit testing.
func initProviderTest(fsProvider fs) {
	fschecker = fsProvider
}

type fsImpl struct{}

func (f fsImpl) Stat(name string) (os.FileInfo, error) {
	return os.Stat(name)
}

// Following helpers are adapted from: https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/cm/cgroup_manager_linux.go.

// toSystemd converts the given cgroup name to a systemd name.
// For example, the name {"kubepods", "burstable", "pod1234-abcd-5678-efgh"} becomes
// "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1234_abcd_5678_efgh.slice"
func toSystemd(cgroupName []string) (string, error) {
	newparts := []string{}
	for _, part := range cgroupName {
		part = escapeSystemdCgroupName(part)
		newparts = append(newparts, part)
	}

	result, err := expandSlice(strings.Join(newparts, "-") + systemdSuffix)
	if err != nil {
		return "", fmt.Errorf("error converting cgroup name [%v] to systemd format: %v", cgroupName, err)
	}
	return result, nil
}

func escapeSystemdCgroupName(part string) string {
	return strings.Replace(part, "-", "_", -1)
}

// systemd represents slice hierarchy using `-`, so we need to follow suit when
// generating the path of slice. Essentially, test-a-b.slice becomes
// /test.slice/test-a.slice/test-a-b.slice.
func expandSlice(slice string) (string, error) {
	suffix := ".slice"
	// Name has to end with ".slice", but can't be just ".slice".
	if len(slice) < len(suffix) || !strings.HasSuffix(slice, suffix) {
		return "", fmt.Errorf("invalid slice name: %s", slice)
	}

	// Path-separators are not allowed.
	if strings.Contains(slice, "/") {
		return "", fmt.Errorf("invalid slice name: %s", slice)
	}

	var path, prefix string
	sliceName := strings.TrimSuffix(slice, suffix)
	// if input was -.slice, we should just return root now
	if sliceName == "-" {
		return "/", nil
	}
	for _, component := range strings.Split(sliceName, "-") {
		// test--a.slice isn't permitted, nor is -test.slice.
		if component == "" {
			return "", fmt.Errorf("invalid slice name: %s", slice)
		}

		// Append the component to the path and to the prefix.
		path += "/" + prefix + component + suffix
		prefix += component + "-"
	}
	return path, nil
}
