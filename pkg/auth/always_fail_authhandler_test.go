// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"reflect"
	"testing"
)

func Test_alwaysFailAuthHandler_authenticate(t *testing.T) {
	tests := []struct {
		name    string
		want    *authResponse
		wantErr bool
	}{
		{
			name:    "Always fail",
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &alwaysFailAuthHandler{}
			got, err := r.authenticate(&authRequest{
				localIdentity:  1000,
				remoteIdentity: 1001,
				remoteNodeIP:   "::1",
			})
			if (err != nil) != tt.wantErr {
				t.Errorf("alwaysFailAuthHandler.authenticate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("alwaysFailAuthHandler.authenticate() = %v, want %v", got, tt.want)
			}
		})
	}
}
