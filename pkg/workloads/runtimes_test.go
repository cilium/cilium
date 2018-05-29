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

package workloads

import (
	"reflect"
	"testing"
)

func TestParseConfigEndpoint(t *testing.T) {
	// backup registered workload since None will unregister them all
	bakRegisteredWorkloads := map[workloadRuntimeType]workloadModule{}
	for k, v := range registeredWorkloads {
		bakRegisteredWorkloads[k] = v
	}
	defer func() {
		registeredWorkloads = bakRegisteredWorkloads
	}()

	containerDOpts := map[string]string{
		epOpt: "unix:///foo.sock",
	}
	dockerOpts := map[string]string{
		epOpt: "unix:///docker.sock",
	}

	type args struct {
		containerRuntimes       []string
		containerRuntimesEPOpts map[string]string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "Do not use any container runtime",
			args: args{
				containerRuntimes: []string{string(ContainerD), string(Docker)},
				containerRuntimesEPOpts: map[string]string{
					string(ContainerD): containerDOpts[epOpt],
					string(Docker):     dockerOpts[epOpt],
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ParseConfigEndpoint(tt.args.containerRuntimes, tt.args.containerRuntimesEPOpts); (err != nil) != tt.wantErr {
				t.Errorf("ParseConfigEndpoint() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}

	if !reflect.DeepEqual(getWorkload(ContainerD).getConfig(), containerDOpts) {
		t.Errorf("ParseConfigEndpoint() = %v, want %v", getWorkload(ContainerD).getConfig(), containerDOpts)
	}
	if !reflect.DeepEqual(getWorkload(Docker).getConfig(), dockerOpts) {
		t.Errorf("ParseConfigEndpoint() = %v, want %v", getWorkload(Docker).getConfig(), dockerOpts)
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
				containerRuntimesEPOpts: map[string]string{
					string(ContainerD): epOpt + "=unix:///foo.sock",
				},
			},
			wantErr: false,
		},
		{
			name: "Do not use any container runtime",
			args: args{
				containerRuntimes: []string{"does-not-exist", string(None)},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ParseConfigEndpoint(tt.args.containerRuntimes, tt.args.containerRuntimesEPOpts); (err != nil) != tt.wantErr {
				t.Errorf("ParseConfigEndpoint() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_parseRuntimeType(t *testing.T) {
	type args struct {
		str string
	}
	tests := []struct {
		name    string
		args    args
		want    workloadRuntimeType
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
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRuntimeType(tt.args.str)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseRuntimeType() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parseRuntimeType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_unregisterWorkloads(t *testing.T) {
	// backup registered workloads since they will unregistered
	bakRegisteredWorkloads := map[workloadRuntimeType]workloadModule{}
	for k, v := range registeredWorkloads {
		bakRegisteredWorkloads[k] = v
	}
	defer func() {
		registeredWorkloads = bakRegisteredWorkloads
	}()

	tests := []struct {
		name string
	}{
		{
			name: "unregister backends",
		},
	}

	if len(registeredWorkloads) == 0 {
		t.Errorf("number of registeredWorkloads should not be 0")
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unregisterWorkloads()
		})
	}
	if len(registeredWorkloads) != 0 {
		t.Errorf("number of registeredWorkloads should be 0")
	}
}

func Test_getWorkload(t *testing.T) {
	type args struct {
		name workloadRuntimeType
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
		t.Run(tt.name, func(t *testing.T) {
			if got := getWorkload(tt.args.name); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getWorkload() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetRuntimeDefaultOpt(t *testing.T) {
	type args struct {
		crt workloadRuntimeType
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
				opt: epOpt + "=" + containerDInstance.opts[epOpt].value,
			},
		},
		{
			name: "docker",
			args: args{
				crt: Docker,
				opt: epOpt + "=" + dockerInstance.opts[epOpt].value,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetRuntimeDefaultOpt(tt.args.crt, tt.args.opt); got != tt.want {
				t.Errorf("GetRuntimeDefaultOpt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetRuntimeOptions(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{
			name: "default options",
			want: epOpt + "=" + containerDInstance.opts[epOpt].value + "," +
				epOpt + "=" + criOInstance.opts[epOpt].value + "," +
				epOpt + "=" + dockerInstance.opts[epOpt].value,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetRuntimeOptions(); got != tt.want {
				t.Errorf("GetRuntimeOptions() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetDefaultEPOptsStringWithPrefix(t *testing.T) {
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
			want: `--container-runtime-endpoint=` + string(ContainerD) + "=" + containerDInstance.opts[epOpt].value + ", " +
				`--container-runtime-endpoint=` + string(CRIO) + "=" + criOInstance.opts[epOpt].value + ", " +
				`--container-runtime-endpoint=` + string(Docker) + "=" + dockerInstance.opts[epOpt].value,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetDefaultEPOptsStringWithPrefix(tt.args.prefix); got != tt.want {
				t.Errorf("GetDefaultEPOptsStringWithPrefix() = %v, want %v", got, tt.want)
			}
		})
	}
}
