// Copyright 2020 Authors of Hubble
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

package servicecache

import (
	"net"
	"testing"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/api/v1/models"

	"github.com/stretchr/testify/assert"
)

func TestServiceCache_Upsert(t *testing.T) {
	type args struct {
		id   int64
		name string
		typ  string
		ns   string
		ip   net.IP
		port uint16
	}
	tests := []struct {
		name   string
		fields map[string]*entry
		args   args
		want   map[string]*entry
	}{
		{
			name:   "upsert into empty cache",
			fields: map[string]*entry{},
			args: args{
				id:   100,
				name: "service",
				typ:  "ClusterIP",
				ns:   "default",
				ip:   net.IPv4(1, 1, 1, 1),
				port: 53,
			},
			want: map[string]*entry{
				"addr:1.1.1.1:53": {
					ID:           100,
					Name:         "service",
					Namespace:    "default",
					FrontendIP:   net.IPv4(1, 1, 1, 1),
					FrontendPort: 53,
				},
				"id:100": {
					ID:           100,
					Name:         "service",
					Namespace:    "default",
					FrontendIP:   net.IPv4(1, 1, 1, 1),
					FrontendPort: 53,
				},
			},
		}, {
			name: "normal upsert",
			fields: map[string]*entry{
				"addr:2.2.2.2:42": {
					ID:           200,
					Name:         "service",
					Namespace:    "default",
					FrontendIP:   net.IPv4(2, 2, 2, 2),
					FrontendPort: 42,
				},
				"id:200": {
					ID:           200,
					Name:         "service",
					Namespace:    "default",
					FrontendIP:   net.IPv4(2, 2, 2, 2),
					FrontendPort: 42,
				},
			},
			args: args{
				id:   200,
				name: "service",
				typ:  "NodePort",
				ns:   "default",
				ip:   net.IPv4(3, 3, 3, 3),
				port: 24,
			},
			want: map[string]*entry{
				"addr:3.3.3.3:24": {
					ID:           200,
					Name:         "service",
					Namespace:    "default",
					FrontendIP:   net.IPv4(3, 3, 3, 3),
					FrontendPort: 24,
				},
				"id:200": {
					ID:           200,
					Name:         "service",
					Namespace:    "default",
					FrontendIP:   net.IPv4(3, 3, 3, 3),
					FrontendPort: 24,
				},
			},
		}, {
			name: "upsert additional",
			fields: map[string]*entry{
				"addr:1.1.1.1:53": {
					ID:           100,
					Name:         "service",
					Namespace:    "default",
					FrontendIP:   net.IPv4(1, 1, 1, 1),
					FrontendPort: 53,
				},
				"id:100": {
					ID:           100,
					Name:         "service",
					Namespace:    "default",
					FrontendIP:   net.IPv4(1, 1, 1, 1),
					FrontendPort: 53,
				},
			},
			args: args{
				id:   200,
				name: "service",
				typ:  "NodePort",
				ns:   "default",
				ip:   net.IPv4(2, 2, 2, 2),
				port: 42,
			},
			want: map[string]*entry{
				"addr:1.1.1.1:53": {
					ID:           100,
					Name:         "service",
					Namespace:    "default",
					FrontendIP:   net.IPv4(1, 1, 1, 1),
					FrontendPort: 53,
				},
				"addr:2.2.2.2:42": {
					ID:           200,
					Name:         "service",
					Namespace:    "default",
					FrontendIP:   net.IPv4(2, 2, 2, 2),
					FrontendPort: 42,
				},
				"id:100": {
					ID:           100,
					Name:         "service",
					Namespace:    "default",
					FrontendIP:   net.IPv4(1, 1, 1, 1),
					FrontendPort: 53,
				},
				"id:200": {
					ID:           200,
					Name:         "service",
					Namespace:    "default",
					FrontendIP:   net.IPv4(2, 2, 2, 2),
					FrontendPort: 42,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svcc := New()
			svcc.cache = tt.fields
			svcc.Upsert(tt.args.id, tt.args.name, tt.args.typ, tt.args.ns, tt.args.ip, tt.args.port)
			// ensure that the 2 entries point to the same address
			assert.True(t, svcc.cache[genIDKey(tt.args.id)] == svcc.cache[genAddrKey(tt.args.ip, tt.args.port)])
			assert.Equal(t, tt.want, svcc.cache)
		})
	}
}

func TestServiceCache_DeleteByAddr(t *testing.T) {
	type args struct {
		ip   net.IP
		port uint16
	}
	type want struct {
		result bool
		cache  map[string]*entry
	}
	tests := []struct {
		name   string
		fields map[string]*entry
		args   args
		want   want
	}{
		{
			name: "normal delete",
			fields: map[string]*entry{
				"addr:2.2.2.2:42": {
					ID:           200,
					Name:         "service",
					Namespace:    "default",
					FrontendIP:   net.IPv4(2, 2, 2, 2),
					FrontendPort: 42,
				},
				"id:200": {
					ID:           200,
					Name:         "service",
					Namespace:    "default",
					FrontendIP:   net.IPv4(2, 2, 2, 2),
					FrontendPort: 42,
				},
			},
			args: args{
				ip:   net.IPv4(2, 2, 2, 2),
				port: 42,
			},
			want: want{
				result: true,
				cache:  map[string]*entry{},
			},
		}, {
			name: "delete nonexisting",
			fields: map[string]*entry{
				"addr:2.2.2.2:42": {
					ID:           200,
					Name:         "service",
					Namespace:    "default",
					FrontendIP:   net.IPv4(2, 2, 2, 2),
					FrontendPort: 42,
				},
				"id:200": {
					ID:           200,
					Name:         "service",
					Namespace:    "default",
					FrontendIP:   net.IPv4(2, 2, 2, 2),
					FrontendPort: 42,
				},
			},
			args: args{
				ip:   net.IPv4(1, 1, 1, 1),
				port: 53,
			},
			want: want{
				result: false,
				cache: map[string]*entry{
					"addr:2.2.2.2:42": {
						ID:           200,
						Name:         "service",
						Namespace:    "default",
						FrontendIP:   net.IPv4(2, 2, 2, 2),
						FrontendPort: 42,
					},
					"id:200": {
						ID:           200,
						Name:         "service",
						Namespace:    "default",
						FrontendIP:   net.IPv4(2, 2, 2, 2),
						FrontendPort: 42,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svcc := New()
			svcc.cache = tt.fields
			got := svcc.DeleteByAddr(tt.args.ip, tt.args.port)
			if got != tt.want.result {
				t.Errorf("ServiceCache.DeleteByAddr() = %v, want %v", got, tt.want.result)
			}
			assert.Equal(t, tt.want.cache, svcc.cache)
		})
	}
}

func TestServiceCache_DeleteByID(t *testing.T) {
	type args struct {
		id int64
	}
	type want struct {
		result bool
		cache  map[string]*entry
	}
	tests := []struct {
		name   string
		fields map[string]*entry
		args   args
		want   want
	}{
		{
			name: "normal delete",
			fields: map[string]*entry{
				"addr:2.2.2.2:42": {
					ID:           200,
					Name:         "service",
					Namespace:    "default",
					FrontendIP:   net.IPv4(2, 2, 2, 2),
					FrontendPort: 42,
				},
				"id:200": {
					ID:           200,
					Name:         "service",
					Namespace:    "default",
					FrontendIP:   net.IPv4(2, 2, 2, 2),
					FrontendPort: 42,
				},
			},
			args: args{id: 200},
			want: want{
				result: true,
				cache:  map[string]*entry{},
			},
		}, {
			name: "delete nonexisting",
			fields: map[string]*entry{
				"addr:2.2.2.2:42": {
					ID:           200,
					Name:         "service",
					Namespace:    "default",
					FrontendIP:   net.IPv4(2, 2, 2, 2),
					FrontendPort: 42,
				},
				"id:200": {
					ID:           200,
					Name:         "service",
					Namespace:    "default",
					FrontendIP:   net.IPv4(2, 2, 2, 2),
					FrontendPort: 42,
				},
			},
			args: args{id: 100},
			want: want{
				result: false,
				cache: map[string]*entry{
					"addr:2.2.2.2:42": {
						ID:           200,
						Name:         "service",
						Namespace:    "default",
						FrontendIP:   net.IPv4(2, 2, 2, 2),
						FrontendPort: 42,
					},
					"id:200": {
						ID:           200,
						Name:         "service",
						Namespace:    "default",
						FrontendIP:   net.IPv4(2, 2, 2, 2),
						FrontendPort: 42,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svcc := New()
			svcc.cache = tt.fields

			got := svcc.DeleteByID(tt.args.id)
			if got != tt.want.result {
				t.Errorf("ServiceCache.DeleteByAddr() = %v, want %v", got, tt.want.result)
			}
			assert.Equal(t, tt.want.cache, svcc.cache)
		})
	}
}

func TestServiceCache_InitializeFrom(t *testing.T) {
	type args struct {
		entries []*models.Service
	}
	type want struct {
		hasErr bool
		cache  map[string]*entry
	}
	tests := []struct {
		name string
		args args
		want want
	}{
		{
			name: "normal initialize",
			args: args{
				entries: []*models.Service{
					{
						Spec: &models.ServiceSpec{
							ID: 100,
							FrontendAddress: &models.FrontendAddress{
								IP:   "1.1.1.1",
								Port: 53,
							},
							Flags: &models.ServiceSpecFlags{
								Name:      "service",
								Namespace: "default",
							},
						},
					}, {
						Spec: &models.ServiceSpec{
							ID: 200,
							FrontendAddress: &models.FrontendAddress{
								IP:   "2.2.2.2",
								Port: 42,
							},
							Flags: &models.ServiceSpecFlags{
								Name:      "service",
								Namespace: "default",
							},
						},
					},
				},
			},
			want: want{
				cache: map[string]*entry{
					"addr:1.1.1.1:53": {
						ID:           100,
						Name:         "service",
						Namespace:    "default",
						FrontendIP:   net.IPv4(1, 1, 1, 1),
						FrontendPort: 53,
					},
					"addr:2.2.2.2:42": {
						ID:           200,
						Name:         "service",
						Namespace:    "default",
						FrontendIP:   net.IPv4(2, 2, 2, 2),
						FrontendPort: 42,
					},
					"id:100": {
						ID:           100,
						Name:         "service",
						Namespace:    "default",
						FrontendIP:   net.IPv4(1, 1, 1, 1),
						FrontendPort: 53,
					},
					"id:200": {
						ID:           200,
						Name:         "service",
						Namespace:    "default",
						FrontendIP:   net.IPv4(2, 2, 2, 2),
						FrontendPort: 42,
					},
				},
			},
		}, {
			name: "nil entry",
			args: args{
				entries: []*models.Service{nil},
			},
			want: want{
				hasErr: true,
				cache:  map[string]*entry{},
			},
		}, {
			name: "missing spec",
			args: args{
				entries: []*models.Service{{}, {}},
			},
			want: want{
				hasErr: true,
				cache:  map[string]*entry{},
			},
		}, {
			name: "missing frontend address",
			args: args{
				entries: []*models.Service{{
					Spec: &models.ServiceSpec{
						ID: 100,
						Flags: &models.ServiceSpecFlags{
							Name:      "service",
							Namespace: "default",
						},
					},
				}},
			},
			want: want{
				hasErr: true,
				cache:  map[string]*entry{},
			},
		}, {
			name: "missing flags",
			args: args{
				entries: []*models.Service{{
					Spec: &models.ServiceSpec{
						ID: 100,
						FrontendAddress: &models.FrontendAddress{
							IP:   "1.1.1.1",
							Port: 53,
						},
					},
				}},
			},
			want: want{
				hasErr: true,
				cache:  map[string]*entry{},
			},
		}, {
			name: "invalid frontend address",
			args: args{
				entries: []*models.Service{{
					Spec: &models.ServiceSpec{
						ID: 100,
						FrontendAddress: &models.FrontendAddress{
							IP:   "in-fact-i-m-not-an-ip",
							Port: 53,
						},
						Flags: &models.ServiceSpecFlags{
							Name:      "service",
							Namespace: "default",
						},
					},
				}},
			},
			want: want{
				hasErr: true,
				cache:  map[string]*entry{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svcc := New()
			if err := svcc.InitializeFrom(tt.args.entries); (err != nil) != tt.want.hasErr {
				t.Errorf("ServiceCache.InitializeFrom() error = %v, wantErr %v", err, tt.want.hasErr)
			}
			assert.Equal(t, tt.want.cache, svcc.cache)
		})
	}
}

func TestServiceCache_GetServiceByAddr(t *testing.T) {
	type args struct {
		ip   net.IP
		port uint16
	}
	type want struct {
		service pb.Service
		ok      bool
	}
	tests := []struct {
		name   string
		fields map[string]*entry
		args   args
		want   want
	}{
		{
			name: "get IPv4 service",
			fields: map[string]*entry{
				"addr:2.2.2.2:42": {
					ID:           200,
					Name:         "service",
					Namespace:    "default",
					FrontendIP:   net.IPv4(2, 2, 2, 2),
					FrontendPort: 42,
				},
				"id:200": {
					ID:           200,
					Name:         "service",
					Namespace:    "default",
					FrontendIP:   net.IPv4(2, 2, 2, 2),
					FrontendPort: 42,
				},
			},
			args: args{
				ip:   net.IPv4(2, 2, 2, 2),
				port: 42,
			},
			want: want{
				service: pb.Service{
					Name:      "service",
					Namespace: "default",
				},
				ok: true,
			},
		}, {
			name: "get IPv6 service",
			fields: map[string]*entry{
				"addr:[2001:db8::68]:42": {
					ID:           200,
					Name:         "service",
					Namespace:    "default",
					FrontendIP:   net.ParseIP("2001:db8::68"),
					FrontendPort: 42,
				},
				"id:200": {
					ID:           200,
					Name:         "service",
					Namespace:    "default",
					FrontendIP:   net.ParseIP("2001:db8::68"),
					FrontendPort: 42,
				},
			},
			args: args{
				ip:   net.ParseIP("2001:db8::68"),
				port: 42,
			},
			want: want{
				service: pb.Service{
					Name:      "service",
					Namespace: "default",
				},
				ok: true,
			},
		}, {
			name: "missing entry",
			args: args{
				ip:   net.ParseIP("2001:db8::68"),
				port: 42,
			},
			want: want{
				service: pb.Service{},
				ok:      false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svcc := New()
			svcc.cache = tt.fields
			gotService, gotOK := svcc.GetServiceByAddr(tt.args.ip, tt.args.port)
			assert.Equal(t, tt.want.service, gotService)
			if gotOK != tt.want.ok {
				t.Errorf("ServiceCache.GetServiceByAddr() gotOK = %v, want %v", gotOK, tt.want.ok)
			}
		})
	}
}

func TestServiceCache_genAddrKey(t *testing.T) {
	type args struct {
		ip   net.IP
		port uint16
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "normal IPv4 address",
			args: args{
				ip:   net.IPv4(2, 2, 2, 2),
				port: 42,
			},
			want: "addr:2.2.2.2:42",
		}, {
			name: "normal IPv6 address",
			args: args{
				ip:   net.ParseIP("2001:db8::68"),
				port: 42,
			},
			want: "addr:[2001:db8::68]:42",
		}, {
			name: "nil ip address",
			args: args{
				ip:   nil,
				port: 42,
			},
			want: "addr::42",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := genAddrKey(tt.args.ip, tt.args.port)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestServiceCache_genIDKey(t *testing.T) {
	type args struct {
		id int64
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "normal ID",
			args: args{
				id: 42,
			},
			want: "id:42",
		}, {
			name: "default ID value",
			args: args{},
			want: "id:0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := genIDKey(tt.args.id)
			assert.Equal(t, tt.want, got)
		})
	}
}
