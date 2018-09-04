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

package versioned

import (
	"github.com/weaveworks/scope/test/reflect"
	"testing"

	"github.com/cilium/cilium/pkg/lock"
)

func TestComparableMap_AddEqual(t *testing.T) {
	type fields struct {
		m          map[UUID]Object
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
				m: map[UUID]Object{
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
				m: map[UUID]Object{},
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
				m: map[UUID]Object{
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
				m: map[UUID]Object{
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &ComparableMap{
				Map:        tt.fields.m,
				DeepEquals: tt.fields.deepEquals,
			}
			if got := m.AddEqual(tt.args.uuid, tt.args.obj); got != tt.want {
				t.Errorf("ComparableMap.AddEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSyncComparableMap_DoLocked(t *testing.T) {
	m := NewComparableMap(DeepEqualFunc(func(o1, o2 interface{}) bool {
		return true
	}))
	m.Map = map[UUID]Object{
		UUID("foo"): Object{
			Data:    "bar",
			Version: ParseVersion("1"),
		},
	}
	type fields struct {
		mutex *lock.RWMutex
		cm    *ComparableMap
	}
	type args struct {
		iterate func(key UUID, value Object)
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
			name: "testing i function",
			fields: fields{
				mutex: &lock.RWMutex{},
				cm:    m,
			},
			args: args{
				iterate: func(key UUID, value Object) {
					if wantValue := m.Map[key]; wantValue != value {
						t.Errorf("provided key is different than given value: got: %#v want: %#v", value, wantValue)
					}
					value.Version = Version(123)
				},
			},
			wantErr:         false,
			functionsCalled: []string{"iterate"},
		},
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
		t.Run(tt.name, func(t *testing.T) {
			sm := &SyncComparableMap{
				mutex: tt.fields.mutex,
				cm:    tt.fields.cm,
			}
			if err := sm.DoLocked(tt.args.iterate, tt.args.replace); (err != nil) != tt.wantErr {
				t.Errorf("SyncComparableMap.DoLocked() error = %v, wantErr %v", err, tt.wantErr)
			}
			for _, v := range tt.functionsCalled {
				switch v {
				case "replace":
					if !reflect.DeepEqual(sm.cm, m) {
						t.Errorf("replace function was not called, otherwise the maps would be the same")
					}
				case "iterate":
					fooObj, _ := sm.Get("foo")
					if fooObj.Version != Version(1) {
						t.Errorf("iterate modifed the object and it shouldn't")
					}
				}
			}
		})
	}
}
