// Copyright 2017-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package workloads

import (
	"reflect"
	"sync"
	"testing"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type WorkloadsTestSuite struct{}

var _ = Suite(&WorkloadsTestSuite{})

type dummyEpSyncher struct{}

func (epSync *dummyEpSyncher) RunK8sCiliumEndpointSync(e *endpoint.Endpoint) {}

func (s *WorkloadsTestSuite) TestSetupWithoutStatusCheck(c *C) {
	// backup registered workload since None will unregister them all
	bakRegisteredWorkloads := map[WorkloadRuntimeType]workloadModule{}
	for k, v := range registeredWorkloads {
		bakRegisteredWorkloads[k] = v
	}
	defer func() {
		registeredWorkloads = bakRegisteredWorkloads
	}()

	dockerOpts := map[string]string{
		EpOpt:           "unix:///docker.sock",
		DatapathModeOpt: "ipvlan",
	}

	type args struct {
		containerRuntimes     []string
		containerRuntimesOpts map[WorkloadRuntimeType]map[string]string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Use Docker container runtime",
			args: args{
				containerRuntimes: []string{string(Docker)},
				containerRuntimesOpts: map[WorkloadRuntimeType]map[string]string{
					Docker: dockerOpts,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		epMgr := endpointmanager.NewEndpointManager(&dummyEpSyncher{})
		if err := setup(nil, epMgr, tt.args.containerRuntimes, tt.args.containerRuntimesOpts, true); (err != nil) != tt.wantErr {
			c.Errorf("setup() for %s error = %v, wantErr %v", tt.name, err, tt.wantErr)
		}
		setupOnce = sync.Once{}
	}

	if !reflect.DeepEqual(getWorkload(Docker).getConfig(), dockerOpts) {
		c.Errorf("setup() = %v, want %v", getWorkload(Docker).getConfig(), dockerOpts)
	}

	// Since None will unregister the backends we need to execute it on a
	// different set of tests
	tests = []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Do not use any container runtime",
			args: args{
				containerRuntimes: []string{string(ContainerD), string(None)},
				containerRuntimesOpts: map[WorkloadRuntimeType]map[string]string{
					Docker: {EpOpt: "unix:///foo.sock"},
				},
			},
			wantErr: false,
		},
		{
			name: "Do not use any container runtime (error)",
			args: args{
				containerRuntimes: []string{"does-not-exist", string(None)},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		epMgr := endpointmanager.NewEndpointManager(&dummyEpSyncher{})
		if err := setup(nil, epMgr, tt.args.containerRuntimes, tt.args.containerRuntimesOpts, true); (err != nil) != tt.wantErr {
			c.Errorf("setup() for %s error = %v, wantErr %v", tt.name, err, tt.wantErr)
		}
		setupOnce = sync.Once{}
	}
}

func (s *WorkloadsTestSuite) Test_parseRuntimeType(c *C) {
	type args struct {
		str string
	}
	tests := []struct {
		name    string
		args    args
		want    WorkloadRuntimeType
		wantErr bool
	}{
		{
			name: "containerd",
			args: args{
				str: "containerd",
			},
			want:    ContainerD,
			wantErr: false,
		},
		{
			name: "containerD",
			args: args{
				str: "containerD",
			},
			want:    ContainerD,
			wantErr: false,
		},
		{
			name: "docker",
			args: args{
				str: "docker",
			},
			want:    Docker,
			wantErr: false,
		},
		{
			name: "cri",
			args: args{
				str: "cri",
			},
			want:    None,
			wantErr: true,
		},
		{
			name: "none",
			args: args{
				str: "none",
			},
			want:    None,
			wantErr: false,
		},
		{
			name: "auto",
			args: args{
				str: "auto",
			},
			want:    Auto,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		got, err := parseRuntimeType(tt.args.str)
		if (err != nil) != tt.wantErr {
			c.Errorf("parseRuntimeType() for %s error = %v, wantErr %v", tt.name, err, tt.wantErr)
			return
		}
		if got != tt.want {
			c.Errorf("parseRuntimeType() for %s = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func (s *WorkloadsTestSuite) Test_unregisterWorkloads(c *C) {
	// backup registered workloads since they will unregistered
	bakRegisteredWorkloads := map[WorkloadRuntimeType]workloadModule{}
	for k, v := range registeredWorkloads {
		bakRegisteredWorkloads[k] = v
	}
	defer func() {
		registeredWorkloads = bakRegisteredWorkloads
	}()

	if len(registeredWorkloads) == 0 {
		c.Errorf("number of registeredWorkloads should not be 0")
	}
	unregisterWorkloads()
	if len(registeredWorkloads) != 0 {
		c.Errorf("number of registeredWorkloads should be 0")
	}
}

func (s *WorkloadsTestSuite) Test_getWorkload(c *C) {
	type args struct {
		name WorkloadRuntimeType
	}
	tests := []struct {
		name string
		args args
		want workloadModule
	}{
		{
			name: "containerD",
			args: args{
				name: ContainerD,
			},
			want: registeredWorkloads[ContainerD],
		},
	}
	for _, tt := range tests {
		if got := getWorkload(tt.args.name); !reflect.DeepEqual(got, tt.want) {
			c.Errorf("getWorkload() fot %s = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func (s *WorkloadsTestSuite) TestGetRuntimeDefaultOpt(c *C) {
	type args struct {
		crt WorkloadRuntimeType
		opt string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "containerd",
			args: args{
				crt: ContainerD,
				opt: EpOpt + "=" + containerDInstance.opts[EpOpt].value,
			},
		},
		{
			name: "docker",
			args: args{
				crt: Docker,
				opt: EpOpt + "=" + dockerInstance.opts[EpOpt].value,
			},
		},
	}
	for _, tt := range tests {
		if got := GetRuntimeDefaultOpt(tt.args.crt, tt.args.opt); got != tt.want {
			c.Errorf("GetRuntimeDefaultOpt() for %s = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func (s *WorkloadsTestSuite) TestGetRuntimeOptions(c *C) {
	tests := []struct {
		name string
		want string
	}{
		{
			name: "default options",
			want: EpOpt + "=" + containerDInstance.opts[EpOpt].value + "," +
				EpOpt + "=" + criOInstance.opts[EpOpt].value + "," +
				DatapathModeOpt + "=" + dockerInstance.opts[DatapathModeOpt].value + "," +
				EpOpt + "=" + dockerInstance.opts[EpOpt].value,
		},
	}
	for _, tt := range tests {
		if got := GetRuntimeOptions(); got != tt.want {
			c.Errorf("GetRuntimeOptions() for %s = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func (s *WorkloadsTestSuite) TestGetDefaultEPOptsStringWithPrefix(c *C) {
	type args struct {
		prefix string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "default ep options",
			args: args{
				prefix: "--container-runtime-endpoint=",
			},
			want: `--container-runtime-endpoint=` + string(ContainerD) + "=" + containerDInstance.opts[EpOpt].value + ", " +
				`--container-runtime-endpoint=` + string(CRIO) + "=" + criOInstance.opts[EpOpt].value + ", " +
				`--container-runtime-endpoint=` + string(Docker) + "=" + dockerInstance.opts[EpOpt].value,
		},
	}
	for _, tt := range tests {
		if got := GetDefaultEPOptsStringWithPrefix(tt.args.prefix); got != tt.want {
			c.Errorf("GetDefaultEPOptsStringWithPrefix() for %s = %v, want %v", tt.name, got, tt.want)
		}
	}
}
