// Copyright 2018 Authors of Cilium
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

package versioned

import (
	"testing"

	"github.com/cilium/cilium/pkg/lock"

	"gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	check.TestingT(t)
}

type VersionedSuite struct{}

var _ = check.Suite(&VersionedSuite{})

func (s *VersionedSuite) TestComparableMap_AddEqual(c *check.C) {
	type fields struct {
		m          Map
		deepEquals DeepEqualFunc
	}
	type args struct {
		uuid UUID
		obj  Object
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "same object inserted twice should return true because the version is the same",
			fields: fields{
				m: Map{
					"foo": {
						Data:    nil,
						Version: ParseVersion("1"),
					},
				},
				deepEquals: DeepEqualFunc(func(o1, o2 interface{}) bool {
					return true
				}),
			},
			args: args{
				uuid: "foo",
				obj: Object{
					Data:    nil,
					Version: ParseVersion("1"),
				},
			},
			want: true,
		},
		{
			name: "new object inserted should return false",
			fields: fields{
				m: Map{},
				deepEquals: DeepEqualFunc(func(o1, o2 interface{}) bool {
					return true
				}),
			},
			args: args{
				uuid: "foo",
				obj: Object{
					Data:    nil,
					Version: ParseVersion("1"),
				},
			},
			want: false,
		},
		{
			name: "new object with new version but deep equaled should return true",
			fields: fields{
				m: Map{
					"foo": {
						Data:    nil,
						Version: ParseVersion("1"),
					},
				},
				deepEquals: DeepEqualFunc(func(o1, o2 interface{}) bool {
					return true
				}),
			},
			args: args{
				uuid: "foo",
				obj: Object{
					Data:    nil,
					Version: ParseVersion("2"),
				},
			},
			want: true,
		},
		{
			name: "new object with new version but not equaled should return false",
			fields: fields{
				m: Map{
					"foo": {
						Data:    nil,
						Version: ParseVersion("1"),
					},
				},
				deepEquals: DeepEqualFunc(func(o1, o2 interface{}) bool {
					return false
				}),
			},
			args: args{
				uuid: "foo",
				obj: Object{
					Data:    nil,
					Version: ParseVersion("2"),
				},
			},
			want: false,
		},
		{
			name: "new object with old version should return true as it already exists in the map",
			fields: fields{
				m: Map{
					"foo": {
						Data:    nil,
						Version: ParseVersion("2"),
					},
				},
				deepEquals: DeepEqualFunc(func(o1, o2 interface{}) bool {
					return false
				}),
			},
			args: args{
				uuid: "foo",
				obj: Object{
					Data:    nil,
					Version: ParseVersion("1"),
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		m := &ComparableMap{
			Map:        tt.fields.m,
			DeepEquals: tt.fields.deepEquals,
		}
		if got := m.AddEqual(tt.args.uuid, tt.args.obj); got != tt.want {
			c.Assert(got, check.DeepEquals, tt.want, check.Commentf("Test name: %q", tt.name))
		}
	}
}

func (s *VersionedSuite) TestSyncComparableMap_DoLocked(c *check.C) {
	m := NewComparableMap(DeepEqualFunc(func(o1, o2 interface{}) bool {
		return true
	}))
	m.Map = Map{
		UUID("foo"): {
			Data:    "bar",
			Version: ParseVersion("1"),
		},
	}
	type fields struct {
		mutex *lock.RWMutex
		cm    *ComparableMap
	}
	type args struct {
		replace func(old *ComparableMap) (*ComparableMap, error)
	}
	tests := []struct {
		name            string
		fields          fields
		args            args
		wantErr         bool
		functionsCalled []string
	}{
		{
			name: "testing replace function",
			fields: fields{
				mutex: &lock.RWMutex{},
				cm: NewComparableMap(DeepEqualFunc(func(o1, o2 interface{}) bool {
					return true
				})),
			},
			args: args{
				replace: func(old *ComparableMap) (*ComparableMap, error) {
					return m, nil
				},
			},
			wantErr:         false,
			functionsCalled: []string{"replace"},
		},
	}
	for _, tt := range tests {
		sm := &SyncComparableMap{
			mutex: tt.fields.mutex,
			cm:    tt.fields.cm,
		}
		if err := sm.Replace(tt.args.replace); (err != nil) != tt.wantErr {
			c.Assert(err, check.DeepEquals, tt.wantErr, check.Commentf("Test name: %q", tt.name))
		}
		for _, v := range tt.functionsCalled {
			switch v {
			case "replace":
				c.Assert(sm.cm, check.DeepEquals, m,
					check.Commentf("%s", "replace function was not called, otherwise the maps would be the same"))
			}
		}
	}
}
