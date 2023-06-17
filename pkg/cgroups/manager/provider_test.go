// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"errors"
	"os"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

type ProviderSuite struct{}

var _ = Suite(&ProviderSuite{})

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

func (p *ProviderSuite) TestGetBasePath(c *C) {
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

	for _, t := range tests {
		initProviderTest(t.input)
		got, err := getCgroupPathProvider()

		c.Assert(err, IsNil)
		c.Assert(got, Not(IsNil))
		path, err := got.getBasePath()
		c.Assert(path, checker.Equals, t.want)
		c.Assert(err, IsNil)
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

func (p *ProviderSuite) TestGetContainerPath(c *C) {
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

	for _, t := range tests {
		ti := getTestInput()
		if t.input != nil {
			t.input(ti)
		}
		initProviderTest(ti.fsMock)

		got, err := ti.provider.getContainerPath(ti.podId, ti.containerId, ti.qos)

		if !t.wantErr {
			c.Assert(err, IsNil, Commentf("Test Name: %s", t.name))
			c.Assert(got, Equals, t.want, Commentf("Test Name: %s", t.name))
		} else {
			c.Assert(err, NotNil, Commentf("Test Name: %s", t.name))
		}
	}
}
