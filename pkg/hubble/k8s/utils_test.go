// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

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
