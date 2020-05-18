// Copyright 2019 Authors of Hubble
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

package k8s

import (
	"testing"
)

func TestParseNamespaceName(t *testing.T) {
	type args struct {
		namespaceName string
	}
	tests := []struct {
		name     string
		args     args
		wantNS   string
		wantName string
	}{
		{
			args: args{
				namespaceName: "default/pod-1",
			},
			wantNS:   "default",
			wantName: "pod-1",
		},
		{
			args: args{
				namespaceName: "default/",
			},
			wantNS:   "default",
			wantName: "",
		},
		{
			args: args{
				namespaceName: "pod-1",
			},
			wantNS:   "default",
			wantName: "pod-1",
		},
		{
			args: args{
				namespaceName: "",
			},
			wantNS:   "",
			wantName: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotNS, gotPod := ParseNamespaceName(tt.args.namespaceName)
			if gotNS != tt.wantNS {
				t.Errorf("ParseNamespaceName() gotNS = %v, wantNS %v", gotNS, tt.wantNS)
			}
			if gotPod != tt.wantName {
				t.Errorf("ParseNamespaceName() gotPod = %v, wantName %v", gotPod, tt.wantName)
			}
		})
	}
}
