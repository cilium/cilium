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

package ipcache

import (
	"net"
	"testing"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/source"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIPCache_Upsert(t *testing.T) {
	_, cidr1111, err := net.ParseCIDR("1.1.1.1/32")
	require.NoError(t, err)

	_, cidr2222, err := net.ParseCIDR("2.2.2.2/32")
	require.NoError(t, err)

	type cache map[string]entry
	type fields struct {
		cache map[string]entry
	}
	type args struct {
		key        string
		id         identity.NumericIdentity
		hostIP     net.IP
		encryptKey uint8
		namespace  string
		podName    string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   cache
	}{
		{
			name: "upsert into empty cache",
			fields: fields{
				cache: cache{},
			},
			args: args{
				key:        "1.1.1.1/32",
				id:         100,
				encryptKey: 8,
				namespace:  "default",
				podName:    "xwing",
			},
			want: cache{
				"1.1.1.1/32": {
					CIDR:       cidr1111,
					Identity:   100,
					EncryptKey: 8,
					Namespace:  "default",
					PodName:    "xwing",
				},
			},
		},
		{
			name: "normal upsert",
			fields: fields{
				cache: cache{
					"1.1.1.1/32": {
						CIDR:     cidr1111,
						Identity: 100,
						HostIP:   net.ParseIP("2.2.2.2"),
					},
				},
			},
			args: args{
				key:        "1.1.1.1/32",
				id:         200,
				hostIP:     net.ParseIP("3.3.3.3"),
				encryptKey: 8,
				namespace:  "default",
				podName:    "xwing",
			},
			want: cache{
				"1.1.1.1/32": {
					CIDR:       cidr1111,
					Identity:   200,
					EncryptKey: 8,
					HostIP:     net.ParseIP("3.3.3.3"),
					Namespace:  "default",
					PodName:    "xwing",
				},
			},
		},
		{
			name: "upsert additional",
			fields: fields{
				cache: cache{
					"1.1.1.1/32": {
						CIDR:     cidr1111,
						Identity: 200,
					},
				},
			},
			args: args{
				key: "2.2.2.2/32",
				id:  100,
			},
			want: cache{
				"1.1.1.1/32": {
					CIDR:     cidr1111,
					Identity: 200,
				},
				"2.2.2.2/32": {
					CIDR:     cidr2222,
					Identity: 100,
				},
			},
		},
		{
			name: "invalid cidr upsert",
			fields: fields{
				cache: cache{
					"1.1.1.1/32": {
						CIDR:     cidr1111,
						Identity: 100,
					},
				},
			},
			args: args{
				key: "1.1.1.1",
				id:  200,
			},
			want: cache{
				"1.1.1.1/32": {
					CIDR:     cidr1111,
					Identity: 100,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipc := &IPCache{
				cache: tt.fields.cache,
			}
			ipc.Upsert(tt.args.key, tt.args.id, tt.args.hostIP, tt.args.encryptKey, tt.args.namespace, tt.args.podName)
			assert.Equal(t, tt.want, cache(ipc.cache))
		})
	}
}

func TestIPCache_Delete(t *testing.T) {
	_, cidr1111, err := net.ParseCIDR("1.1.1.1/32")
	require.NoError(t, err)

	type cache map[string]entry
	type fields struct {
		cache map[string]entry
	}
	type args struct {
		key string
	}
	type want struct {
		result bool
		cache  cache
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   want
	}{
		{
			name: "normal delete",
			fields: fields{
				cache: cache{
					"1.1.1.1/32": {
						CIDR:     cidr1111,
						Identity: 100,
					},
				},
			},
			args: args{
				key: "1.1.1.1/32",
			},
			want: want{
				result: true,
				cache:  cache{},
			},
		},
		{
			name: "delete nonexisting",
			fields: fields{
				cache: cache{
					"1.1.1.1/32": {
						CIDR:     cidr1111,
						Identity: 100,
					},
				},
			},
			args: args{
				key: "2.2.2.2/32",
			},
			want: want{
				result: false,
				cache: cache{
					"1.1.1.1/32": {
						CIDR:     cidr1111,
						Identity: 100,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipc := &IPCache{
				cache: tt.fields.cache,
			}
			got := ipc.Delete(tt.args.key)
			if got != tt.want.result {
				t.Errorf("IPCache.Delete() = %v, want %v", got, tt.want.result)
			}
			assert.Equal(t, tt.want.cache, cache(ipc.cache))
		})
	}
}

func TestIPCache_UpsertChecked(t *testing.T) {
	_, cidr1111, err := net.ParseCIDR("1.1.1.1/32")
	require.NoError(t, err)

	id100 := identity.NumericIdentity(100)

	type cache map[string]entry
	type fields struct {
		cache map[string]entry
	}
	type args struct {
		key        string
		newID      identity.NumericIdentity
		oldID      *identity.NumericIdentity
		newHostIP  net.IP
		oldHostIP  net.IP
		encryptKey uint8
		namespace  string
		podName    string
	}
	type want struct {
		result bool
		cache  cache
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   want
	}{
		{
			name: "upsert into empty cache",
			fields: fields{
				cache: cache{},
			},
			args: args{
				key:        "1.1.1.1/32",
				newID:      100,
				encryptKey: 8,
				namespace:  "default",
				podName:    "xwing",
			},
			want: want{
				result: true,
				cache: cache{
					"1.1.1.1/32": {
						CIDR:       cidr1111,
						Identity:   100,
						EncryptKey: 8,
						Namespace:  "default",
						PodName:    "xwing",
					},
				},
			},
		},
		{
			name: "normal upsert",
			fields: fields{
				cache: cache{
					"1.1.1.1/32": {
						CIDR:     cidr1111,
						Identity: 100,
						HostIP:   net.ParseIP("2.2.2.2"),
					},
				},
			},
			args: args{
				key:        "1.1.1.1/32",
				newID:      200,
				oldID:      &id100,
				oldHostIP:  net.ParseIP("2.2.2.2"),
				newHostIP:  net.ParseIP("3.3.3.3"),
				encryptKey: 8,
				namespace:  "default",
				podName:    "xwing",
			},
			want: want{
				result: true,
				cache: cache{
					"1.1.1.1/32": {
						CIDR:       cidr1111,
						Identity:   200,
						EncryptKey: 8,
						HostIP:     net.ParseIP("3.3.3.3"),
						Namespace:  "default",
						PodName:    "xwing",
					},
				},
			},
		},
		{
			name: "stale upsert with wrong identity",
			fields: fields{
				cache: cache{
					"1.1.1.1/32": {
						CIDR:     cidr1111,
						Identity: 200,
					},
				},
			},
			args: args{
				key:   "1.1.1.1/32",
				newID: 200,
				oldID: &id100,
			},
			want: want{
				result: false,
				cache: cache{
					"1.1.1.1/32": {
						CIDR:     cidr1111,
						Identity: 200,
					},
				},
			},
		},
		{
			name: "stale upsert with wrong hostip",
			fields: fields{
				cache: cache{
					"1.1.1.1/32": {
						CIDR:     cidr1111,
						HostIP:   net.ParseIP("2.2.2.2"),
						Identity: 100,
					},
				},
			},
			args: args{
				key:       "1.1.1.1/32",
				newID:     200,
				oldID:     &id100,
				oldHostIP: net.ParseIP("3.3.3.3"),
			},
			want: want{
				result: false,
				cache: cache{
					"1.1.1.1/32": {
						CIDR:     cidr1111,
						HostIP:   net.ParseIP("2.2.2.2"),
						Identity: 100,
					},
				},
			},
		},
		{
			name: "invalid cidr upsert",
			fields: fields{
				cache: cache{
					"1.1.1.1/32": {
						CIDR:     cidr1111,
						Identity: 100,
					},
				},
			},
			args: args{
				key:   "1.1.1.1",
				newID: 200,
				oldID: &id100,
			},
			want: want{
				result: false,
				cache: cache{
					"1.1.1.1/32": {
						CIDR:     cidr1111,
						Identity: 100,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipc := &IPCache{
				cache: tt.fields.cache,
			}
			got := ipc.UpsertChecked(tt.args.key, tt.args.newID, tt.args.oldID, tt.args.newHostIP, tt.args.oldHostIP, tt.args.encryptKey, tt.args.namespace, tt.args.podName)
			if got != tt.want.result {
				t.Errorf("IPCache.UpsertChecked() = %v, want %v", got, tt.want.result)
			}
			assert.Equal(t, tt.want.cache, cache(ipc.cache))
		})
	}
}

func TestIPCache_InitializeFrom(t *testing.T) {
	cidr1111Str := "1.1.1.1/32"
	_, cidr1111, err := net.ParseCIDR(cidr1111Str)
	require.NoError(t, err)
	cidr2222Str := "2.2.2.2/32"
	_, cidr2222, err := net.ParseCIDR(cidr2222Str)
	require.NoError(t, err)
	cidr3333Str := "3.3.3.3/32"
	_, cidr3333, err := net.ParseCIDR(cidr3333Str)
	require.NoError(t, err)

	invalidCIDRStr := "1.1.1.1/128"

	id100 := int64(100)
	id200 := int64(200)
	id300 := int64(300)

	type cache map[string]entry
	type fields struct {
		cache map[string]entry
	}
	type args struct {
		entries []*models.IPListEntry
	}
	type want struct {
		hasErr bool
		cache  cache
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   want
	}{
		{
			name: "normal initialize",
			args: args{
				entries: []*models.IPListEntry{
					{
						Cidr:       &cidr1111Str,
						Identity:   &id100,
						EncryptKey: 8,
						HostIP:     "4.4.4.4",
						Metadata: &models.IPListEntryMetadata{
							Source:    string(source.Kubernetes),
							Name:      "xwing",
							Namespace: "default",
						},
					},
					{
						Cidr:     &cidr2222Str,
						Identity: &id200,
					},
					{
						Cidr:       &cidr3333Str,
						Identity:   &id300,
						EncryptKey: 12,
						Metadata: &models.IPListEntryMetadata{
							Source:    "other",
							Name:      "whoknows",
							Namespace: "none",
						},
					},
				},
			},
			want: want{
				cache: cache{
					"1.1.1.1/32": {
						CIDR:       cidr1111,
						Identity:   100,
						HostIP:     net.ParseIP("4.4.4.4"),
						EncryptKey: 8,
						Namespace:  "default",
						PodName:    "xwing",
					},
					"2.2.2.2/32": {
						CIDR:     cidr2222,
						Identity: 200,
					},
					"3.3.3.3/32": {
						CIDR:       cidr3333,
						Identity:   300,
						EncryptKey: 12,
					},
				},
			},
		},
		{
			name: "missing cidr",
			args: args{
				entries: []*models.IPListEntry{
					{
						Cidr:     nil,
						Identity: &id100,
					},
				},
			},
			want: want{
				hasErr: true,
			},
		},
		{
			name: "missing id",
			args: args{
				entries: []*models.IPListEntry{
					{
						Cidr:     &cidr1111Str,
						Identity: nil,
					},
				},
			},
			want: want{
				hasErr: true,
			},
		},
		{
			name: "missing entry",
			args: args{
				entries: []*models.IPListEntry{
					nil,
				},
			},
			want: want{
				hasErr: true,
			},
		},
		{
			name: "invalid cidr",
			args: args{
				entries: []*models.IPListEntry{
					{Cidr: &invalidCIDRStr, Identity: &id100},
				},
			},
			want: want{
				hasErr: true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipc := &IPCache{
				cache: tt.fields.cache,
			}
			if err := ipc.InitializeFrom(tt.args.entries); (err != nil) != tt.want.hasErr {
				t.Errorf("IPCache.InitializeFrom() error = %v, wantErr %v", err, tt.want.hasErr)
			}
			assert.Equal(t, tt.want.cache, cache(ipc.cache))
		})
	}
}

func TestIPCache_GetIPIdentity(t *testing.T) {
	_, cidrv4, err := net.ParseCIDR("1.1.1.1/32")
	require.NoError(t, err)
	_, cidrv6, err := net.ParseCIDR("::1/128")
	require.NoError(t, err)

	type cache map[string]entry
	type fields struct {
		cache map[string]entry
	}
	type args struct {
		ip net.IP
	}
	type want struct {
		id IPIdentity
		ok bool
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   want
	}{
		{
			name: "get ipv4 pod",
			fields: fields{
				cache: cache{
					"1.1.1.1/32": entry{
						CIDR:      cidrv4,
						Identity:  100,
						Namespace: "default",
						PodName:   "xwing",
					},
				},
			},
			args: args{
				ip: net.ParseIP("1.1.1.1"),
			},
			want: want{
				id: IPIdentity{100, "default", "xwing"},
				ok: true,
			},
		},
		{
			name: "get ipv6 pod",
			fields: fields{
				cache: cache{
					"::1/128": entry{
						CIDR:      cidrv6,
						Identity:  100,
						Namespace: "default",
						PodName:   "xwing",
					},
				},
			},
			args: args{
				ip: net.ParseIP("::1"),
			},
			want: want{
				id: IPIdentity{100, "default", "xwing"},
				ok: true,
			},
		},
		{
			name: "missing entry",
			fields: fields{
				cache: cache{
					"1.1.1.1/32": entry{
						CIDR:      cidrv4,
						Identity:  100,
						Namespace: "default",
						PodName:   "xwing",
					},
				},
			},
			args: args{
				ip: net.ParseIP("2.2.2.2"),
			},
			want: want{
				ok: false,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ipc := &IPCache{
				cache: tt.fields.cache,
			}
			gotID, gotOk := ipc.GetIPIdentity(tt.args.ip)
			if gotID != tt.want.id {
				t.Errorf("IPCache.GetIPIdentity() gotID = %v, want %v", gotID, tt.want.id)
			}
			if gotOk != tt.want.ok {
				t.Errorf("IPCache.GetIPIdentity() gotOk = %v, want %v", gotOk, tt.want.ok)
			}
		})
	}
}
