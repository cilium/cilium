// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/cgroups"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

var (
	fsMockDefault = fsMock{
		getFullPath(defaultCgroupBasePath): struct{}{},
	}
	fsMockSystemd = fsMock{
		getFullPath(systemdCgroupBasePath): struct{}{},
	}
	fsMockNested = fsMock{
		getFullPath(nestedCgroupBasePath): struct{}{},
	}
	fsMockSystemdNested = fsMock{
		getFullPath(nestedSystemdCgroupBasePath): struct{}{},
	}
	cgroupRoot             = cgroups.GetCgroupRoot()
	cDefaultPath           = cgroupRoot + "/kubepods/burstable/pod1858680e-b044-4fd5-9dd4-f137e30e2180/" + c1Id
	cDefaultGuaranteedPath = cgroupRoot + "/kubepods/pod1858680e-b044-4fd5-9dd4-f137e30e2180/" + c1Id
	cSystemdPath           = cgroupRoot + "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1858680e_b044_4fd5_9dd4_f137e30e2180.slice/" + "cri-containerd-" + c1Id + ".scope"
	cSystemdGuaranteedPath = cgroupRoot + "/kubepods.slice/kubepods-pod1858680e_b044_4fd5_9dd4_f137e30e2180.slice/" + "crio-" + c1Id + ".scope"
	cNestedPath            = cgroupRoot + "/kubelet/kubepods/burstable/pod1858680e-b044-4fd5-9dd4-f137e30e2180/" + c1Id
	cSystemdNestedPath     = cgroupRoot + "/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-burstable.slice/kubelet-kubepods-burstable-pod1858680e_b044_4fd5_9dd4_f137e30e2180.slice/" + "cri-containerd-" + c1Id + ".scope"
)

type fsMock map[string]struct{}

func (fs fsMock) Stat(file string) (info os.FileInfo, err error) {
	if _, ok := fs[file]; ok {
		return nil, nil
	}

	return nil, errors.New("")
}

func TestGetBasePath(t *testing.T) {
	type test struct {
		input fs
		want  string
	}
	tests := []test{
		{input: fsMockDefault, want: getFullPath(defaultCgroupBasePath)},
		{input: fsMockSystemd, want: getFullPath(systemdCgroupBasePath)},
		{input: fsMockNested, want: getFullPath(nestedCgroupBasePath)},
		{input: fsMockSystemdNested, want: getFullPath(nestedSystemdCgroupBasePath)},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprintf("Test index %d", i), func(t *testing.T) {
			initProviderTest(tt.input)
			got, err := getCgroupPathProvider()
			require.NoError(t, err)
			require.NotNil(t, got)
			path, err := got.getBasePath()
			require.NoError(t, err)
			require.Equal(t, tt.want, path)
		})

	}
}

type inputParams struct {
	provider    cgroupPathProvider
	podId       string
	containerId string
	qos         v1.PodQOSClass
	fsMock      fs
}

func getTestInput() *inputParams {
	return &inputParams{
		provider:    newDefaultProvider(),
		podId:       string(pod1.ObjectMeta.UID),
		containerId: c1Id,
		qos:         pod1.Status.QOSClass,
		fsMock: fsMock{
			cgroupRoot + defaultCgroupBasePath: struct{}{},
			cDefaultPath:                       struct{}{},
		},
	}
}

func TestGetContainerPath(t *testing.T) {
	tests := []struct {
		name    string
		input   func(input *inputParams)
		want    string
		wantErr bool
	}{
		{
			name: "default provider",
			want: cDefaultPath,
		},
		{
			name: "default provider + guaranteed qos pod",
			input: func(input *inputParams) {
				input.qos = v1.PodQOSGuaranteed
				input.fsMock = fsMock{
					cgroupRoot + defaultCgroupBasePath: struct{}{},
					cDefaultGuaranteedPath:             struct{}{},
				}
			},
			want: cDefaultGuaranteedPath,
		},
		{
			name: "systemd provider",
			input: func(input *inputParams) {
				input.provider = newSystemdProvider()
				input.fsMock = fsMock{
					cgroupRoot + systemdCgroupBasePath: struct{}{},
					cSystemdPath:                       struct{}{},
				}
			},
			want: cSystemdPath,
		},
		{
			name: "systemd provider + guaranteed qos pod + crio",
			input: func(input *inputParams) {
				input.provider = newSystemdProvider()
				input.qos = v1.PodQOSGuaranteed
				input.fsMock = fsMock{
					cgroupRoot + systemdCgroupBasePath: struct{}{},
					cSystemdGuaranteedPath:             struct{}{},
				}
			},
			want: cSystemdGuaranteedPath,
		},
		{
			name: "nested provider",
			input: func(input *inputParams) {
				input.provider = newNestedProvider()
				input.fsMock = fsMock{
					cgroupRoot + nestedCgroupBasePath: struct{}{},
					cNestedPath:                       struct{}{},
				}
			},
			want: cNestedPath,
		},
		{
			name: "nested systemd provider",
			input: func(input *inputParams) {
				input.provider = newNestedSystemdProvider()
				input.fsMock = fsMock{
					cgroupRoot + nestedSystemdCgroupBasePath: struct{}{},
					cSystemdNestedPath:                       struct{}{},
				}
			},
			want: cSystemdNestedPath,
		},
		{
			name: "default provider + no valid path",
			input: func(input *inputParams) {
				input.fsMock = fsMock{
					cgroupRoot + defaultCgroupBasePath: struct{}{},
					cgroupRoot + "/foo":                struct{}{},
				}
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "systemd provider + no valid path",
			input: func(input *inputParams) {
				input.provider = newSystemdProvider()
				input.fsMock = fsMock{
					cgroupRoot + systemdCgroupBasePath: struct{}{},
					cgroupRoot + "/foo":                struct{}{},
				}
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "nested systemd provider + no valid path",
			input: func(input *inputParams) {
				input.provider = newNestedSystemdProvider()
				input.fsMock = fsMock{
					cgroupRoot + nestedSystemdCgroupBasePath: struct{}{},
					cgroupRoot + "/foo":                      struct{}{},
				}
			},
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ti := getTestInput()
			if tt.input != nil {
				tt.input(ti)
			}
			initProviderTest(ti.fsMock)

			got, err := ti.provider.getContainerPath(ti.podId, ti.containerId, ti.qos)

			if !tt.wantErr {
				require.NoError(t, err)
				require.Equal(t, tt.want, got)
			} else {
				require.Error(t, err)
			}
		})
	}
}
