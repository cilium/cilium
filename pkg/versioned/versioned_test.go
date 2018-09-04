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

import "testing"

func TestParseVersion(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name string
		args args
		want Version
	}{
		{
			name: "valid version",
			args: args{
				"123456789",
			},
			want: Version(123456789),
		},
		{
			name: "invalid version max than uint64",
			args: args{
				"123456789123456789123456789123456789123456789123456789123456789",
			},
			want: Version(9223372036854775807),
		},
		{
			name: "invalid version with letters",
			args: args{
				"a",
			},
			want: Version(0),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ParseVersion(tt.args.s); got != tt.want {
				t.Errorf("ParseVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestObject_CompareVersion(t *testing.T) {
	type fields struct {
		Data    interface{}
		Version Version
	}
	type args struct {
		other Object
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   int64
	}{
		{
			name: "same version objects",
			fields: fields{
				Version: Version(0),
			},
			args: args{
				Object{
					Version: Version(0),
				},
			},
			want: 0,
		},
		{
			name: "receiver is newer",
			fields: fields{
				Version: Version(1),
			},
			args: args{
				Object{
					Version: Version(0),
				},
			},
			want: 1,
		},
		{
			name: "receiver is older",
			fields: fields{
				Version: Version(-1),
			},
			args: args{
				Object{
					Version: Version(0),
				},
			},
			want: -1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &Object{
				Data:    tt.fields.Data,
				Version: tt.fields.Version,
			}
			if got := o.CompareVersion(tt.args.other); got != tt.want {
				t.Errorf("Object.CompareVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}
