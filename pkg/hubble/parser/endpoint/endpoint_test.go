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

package endpoint

import (
	"net"
	"reflect"
	"testing"

	"github.com/cilium/cilium/api/v1/models"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/cilium/cilium/pkg/monitor/api"
)

func TestParseEndpointFromModel(t *testing.T) {
	type args struct {
		modelEP *models.Endpoint
	}
	tests := []struct {
		name string
		args args
		want *v1.Endpoint
	}{
		{
			name: "full endpoint",
			args: args{
				modelEP: &models.Endpoint{
					ID: 1,
					Status: &models.EndpointStatus{
						ExternalIdentifiers: &models.EndpointIdentifiers{
							ContainerID: "313c63b8b164a19ec0fe42cd86c4159f3276ba8a415d77f340817fcfee2cb479",
							PodName:     "default/foo",
						},
						Networking: &models.EndpointNetworking{
							Addressing: []*models.AddressPair{
								{
									IPV4: "1.1.1.1",
									IPV6: "fd00::",
								},
							},
						},
					},
				},
			},
			want: &v1.Endpoint{
				ContainerIDs: []string{"313c63b8b164a19ec0fe42cd86c4159f3276ba8a415d77f340817fcfee2cb479"},
				ID:           1,
				IPv4:         net.ParseIP("1.1.1.1").To4(),
				IPv6:         net.ParseIP("fd00::").To16(),
				PodName:      "foo",
				PodNamespace: "default",
			},
		},
		{
			name: "endpoint without IPs",
			args: args{
				modelEP: &models.Endpoint{
					ID: 1,
					Status: &models.EndpointStatus{
						ExternalIdentifiers: &models.EndpointIdentifiers{
							ContainerID: "313c63b8b164a19ec0fe42cd86c4159f3276ba8a415d77f340817fcfee2cb479",
							PodName:     "default/foo",
						},
					},
				},
			},
			want: &v1.Endpoint{
				ContainerIDs: []string{"313c63b8b164a19ec0fe42cd86c4159f3276ba8a415d77f340817fcfee2cb479"},
				ID:           1,
				PodName:      "foo",
				PodNamespace: "default",
			},
		},
		{
			name: "endpoint without an endpoint status",
			args: args{
				modelEP: &models.Endpoint{
					ID: 1,
				},
			},
			want: &v1.Endpoint{
				ID: 1,
			},
		},
		{
			name: "endpoint with identity labels",
			args: args{
				modelEP: &models.Endpoint{
					ID: 1,
					Status: &models.EndpointStatus{
						Identity: &models.Identity{
							ID:     1234,
							Labels: []string{"a=b", "c=d"},
						},
					},
				},
			},
			want: &v1.Endpoint{
				ID:       1,
				Identity: 1234,
				Labels:   []string{"a=b", "c=d"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseEndpointFromModel(tt.args.modelEP)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseEndpointFromModel()\n =   %+v, \nwant %+v", got, tt.want)
			}
		})
	}
}

func TestParseEndpointFromEndpointDeleteNotification(t *testing.T) {
	type args struct {
		edn api.EndpointDeleteNotification
	}
	tests := []struct {
		name string
		args args
		want *v1.Endpoint
	}{
		{
			name: "full endpoint",
			args: args{
				edn: api.EndpointDeleteNotification{
					EndpointRegenNotification: api.EndpointRegenNotification{
						ID: 1,
					},
					PodName:   "foo",
					Namespace: "bar",
				},
			},
			want: &v1.Endpoint{
				ID:           1,
				PodName:      "foo",
				PodNamespace: "bar",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseEndpointFromEndpointDeleteNotification(tt.args.edn)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseEndpointFromEndpointDeleteNotification() = %v, want %v", got, tt.want)
			}
		})
	}
}
