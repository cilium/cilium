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

package loadbalancer

import (
	"net"
	"testing"

	"gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	check.TestingT(t)
}

type TypesSuite struct{}

var _ = check.Suite(&TypesSuite{})

func (s *TypesSuite) TestIsK8ServiceExternal(c *check.C) {
	si := K8sServiceInfo{}

	c.Assert(si.IsExternal(), check.Equals, true)

	si.Selector = map[string]string{"l": "v"}
	c.Assert(si.IsExternal(), check.Equals, false)
}

func TestL4Addr_Equals(t *testing.T) {
	type args struct {
		o *L4Addr
	}
	tests := []struct {
		name   string
		fields *L4Addr
		args   args
		want   bool
	}{
		{
			name: "both equal",
			fields: &L4Addr{
				Protocol: NONE,
				Port:     1,
			},
			args: args{
				o: &L4Addr{
					Protocol: NONE,
					Port:     1,
				},
			},
			want: true,
		},
		{
			name: "both different",
			fields: &L4Addr{
				Protocol: NONE,
				Port:     0,
			},
			args: args{
				o: &L4Addr{
					Protocol: NONE,
					Port:     1,
				},
			},
			want: false,
		},
		{
			name: "both nil",
			args: args{},
			want: true,
		},
		{
			name: "other nil",
			fields: &L4Addr{
				Protocol: NONE,
				Port:     1,
			},
			args: args{},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := tt.fields
			if got := l.Equals(tt.args.o); got != tt.want {
				t.Errorf("L4Addr.Equals() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFEPort_EqualsIgnoreID(t *testing.T) {
	type args struct {
		o *FEPort
	}
	tests := []struct {
		name   string
		fields *FEPort
		args   args
		want   bool
	}{
		{
			name: "both equal",
			fields: &FEPort{
				L4Addr: &L4Addr{
					Protocol: NONE,
					Port:     1,
				},
				ID: 1,
			},
			args: args{
				o: &FEPort{
					L4Addr: &L4Addr{
						Protocol: NONE,
						Port:     1,
					},
					ID: 1,
				},
			},
			want: true,
		},
		{
			name: "IDs different are considered equal",
			fields: &FEPort{
				L4Addr: &L4Addr{
					Protocol: NONE,
					Port:     1,
				},
				ID: 1,
			},
			args: args{
				o: &FEPort{
					L4Addr: &L4Addr{
						Protocol: NONE,
						Port:     1,
					},
					ID: 1001,
				},
			},
			want: true,
		},
		{
			name: "both nil",
			args: args{},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := tt.fields
			if got := f.EqualsIgnoreID(tt.args.o); got != tt.want {
				t.Errorf("FEPort.EqualsIgnoreID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFEPort_Equals(t *testing.T) {
	type args struct {
		o *FEPort
	}
	tests := []struct {
		name   string
		fields *FEPort
		args   args
		want   bool
	}{
		{
			name: "both equal",
			fields: &FEPort{
				L4Addr: &L4Addr{
					Protocol: NONE,
					Port:     1,
				},
				ID: 1,
			},
			args: args{
				o: &FEPort{
					L4Addr: &L4Addr{
						Protocol: NONE,
						Port:     1,
					},
					ID: 1,
				},
			},
			want: true,
		},
		{
			name: "IDs different are considered different",
			fields: &FEPort{
				L4Addr: &L4Addr{
					Protocol: NONE,
					Port:     1,
				},
				ID: 1,
			},
			args: args{
				o: &FEPort{
					L4Addr: &L4Addr{
						Protocol: NONE,
						Port:     1,
					},
					ID: 1001,
				},
			},
			want: false,
		},
		{
			name: "both nil",
			args: args{},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := tt.fields
			if got := f.Equals(tt.args.o); got != tt.want {
				t.Errorf("FEPort.Equals() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestK8sServiceInfo_Equals(t *testing.T) {
	type args struct {
		o *K8sServiceInfo
	}
	tests := []struct {
		name   string
		fields *K8sServiceInfo
		args   args
		want   bool
	}{
		{
			name: "both equal",
			fields: &K8sServiceInfo{
				FEIP:       net.ParseIP("1.1.1.1"),
				IsHeadless: true,
				Ports: map[FEPortName]*FEPort{
					FEPortName("foo"): {
						L4Addr: &L4Addr{
							Protocol: NONE,
							Port:     1,
						},
						ID: 1,
					},
				},
				Labels: map[string]string{
					"foo": "bar",
				},
				Selector: map[string]string{
					"baz": "foz",
				},
			},
			args: args{
				o: &K8sServiceInfo{
					FEIP:       net.ParseIP("1.1.1.1"),
					IsHeadless: true,
					Ports: map[FEPortName]*FEPort{
						FEPortName("foo"): {
							L4Addr: &L4Addr{
								Protocol: NONE,
								Port:     1,
							},
							ID: 1,
						},
					},
					Labels: map[string]string{
						"foo": "bar",
					},
					Selector: map[string]string{
						"baz": "foz",
					},
				},
			},
			want: true,
		},
		{
			name: "different labels",
			fields: &K8sServiceInfo{
				FEIP:       net.ParseIP("1.1.1.1"),
				IsHeadless: true,
				Ports: map[FEPortName]*FEPort{
					FEPortName("foo"): {
						L4Addr: &L4Addr{
							Protocol: NONE,
							Port:     1,
						},
						ID: 1,
					},
				},
				Labels: map[string]string{},
				Selector: map[string]string{
					"baz": "foz",
				},
			},
			args: args{
				o: &K8sServiceInfo{
					FEIP:       net.ParseIP("1.1.1.1"),
					IsHeadless: true,
					Ports: map[FEPortName]*FEPort{
						FEPortName("foo"): {
							L4Addr: &L4Addr{
								Protocol: NONE,
								Port:     1,
							},
							ID: 1,
						},
					},
					Labels: map[string]string{
						"foo": "bar",
					},
					Selector: map[string]string{
						"baz": "foz",
					},
				},
			},
			want: false,
		},
		{
			name: "different selector",
			fields: &K8sServiceInfo{
				FEIP:       net.ParseIP("1.1.1.1"),
				IsHeadless: true,
				Ports: map[FEPortName]*FEPort{
					FEPortName("foo"): {
						L4Addr: &L4Addr{
							Protocol: NONE,
							Port:     1,
						},
						ID: 1,
					},
				},
				Labels:   map[string]string{},
				Selector: map[string]string{},
			},
			args: args{
				o: &K8sServiceInfo{
					FEIP:       net.ParseIP("1.1.1.1"),
					IsHeadless: true,
					Ports: map[FEPortName]*FEPort{
						FEPortName("foo"): {
							L4Addr: &L4Addr{
								Protocol: NONE,
								Port:     1,
							},
							ID: 1,
						},
					},
					Labels: map[string]string{},
					Selector: map[string]string{
						"baz": "foz",
					},
				},
			},
			want: false,
		},
		{
			name: "ports different name",
			fields: &K8sServiceInfo{
				FEIP:       net.ParseIP("1.1.1.1"),
				IsHeadless: true,
				Ports: map[FEPortName]*FEPort{
					FEPortName("foz"): {
						L4Addr: &L4Addr{
							Protocol: NONE,
							Port:     1,
						},
						ID: 1,
					},
				},
				Labels:   map[string]string{},
				Selector: map[string]string{},
			},
			args: args{
				o: &K8sServiceInfo{
					FEIP:       net.ParseIP("1.1.1.1"),
					IsHeadless: true,
					Ports: map[FEPortName]*FEPort{
						FEPortName("foo"): {
							L4Addr: &L4Addr{
								Protocol: NONE,
								Port:     1,
							},
							ID: 1,
						},
					},
					Labels:   map[string]string{},
					Selector: map[string]string{},
				},
			},
			want: false,
		},
		{
			name: "ports different content",
			fields: &K8sServiceInfo{
				FEIP:       net.ParseIP("1.1.1.1"),
				IsHeadless: true,
				Ports: map[FEPortName]*FEPort{
					FEPortName("foo"): {
						L4Addr: &L4Addr{
							Protocol: NONE,
							Port:     1,
						},
						ID: 1,
					},
				},
				Labels:   map[string]string{},
				Selector: map[string]string{},
			},
			args: args{
				o: &K8sServiceInfo{
					FEIP:       net.ParseIP("1.1.1.1"),
					IsHeadless: true,
					Ports: map[FEPortName]*FEPort{
						FEPortName("foo"): {
							L4Addr: &L4Addr{
								Protocol: NONE,
								Port:     2,
							},
							ID: 1,
						},
					},
					Labels:   map[string]string{},
					Selector: map[string]string{},
				},
			},
			want: false,
		},
		{
			name: "ports different one is bigger",
			fields: &K8sServiceInfo{
				FEIP:       net.ParseIP("1.1.1.1"),
				IsHeadless: true,
				Ports: map[FEPortName]*FEPort{
					FEPortName("foo"): {
						L4Addr: &L4Addr{
							Protocol: NONE,
							Port:     1,
						},
						ID: 1,
					},
				},
				Labels:   map[string]string{},
				Selector: map[string]string{},
			},
			args: args{
				o: &K8sServiceInfo{
					FEIP:       net.ParseIP("1.1.1.1"),
					IsHeadless: true,
					Ports: map[FEPortName]*FEPort{
						FEPortName("foo"): {
							L4Addr: &L4Addr{
								Protocol: NONE,
								Port:     1,
							},
							ID: 1,
						},
						FEPortName("baz"): {
							L4Addr: &L4Addr{
								Protocol: NONE,
								Port:     2,
							},
							ID: 2,
						},
					},
					Labels:   map[string]string{},
					Selector: map[string]string{},
				},
			},
			want: false,
		},
		{
			name: "ports different one is nil",
			fields: &K8sServiceInfo{
				FEIP:       net.ParseIP("1.1.1.1"),
				IsHeadless: true,
				Labels:     map[string]string{},
				Selector:   map[string]string{},
			},
			args: args{
				o: &K8sServiceInfo{
					FEIP:       net.ParseIP("1.1.1.1"),
					IsHeadless: true,
					Ports: map[FEPortName]*FEPort{
						FEPortName("foo"): {
							L4Addr: &L4Addr{
								Protocol: NONE,
								Port:     1,
							},
							ID: 1,
						},
					},
					Labels:   map[string]string{},
					Selector: map[string]string{},
				},
			},
			want: false,
		},
		{
			name: "both nil",
			args: args{},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			si := tt.fields
			if got := si.Equals(tt.args.o); got != tt.want {
				t.Errorf("K8sServiceInfo.Equals() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestK8sServiceEndpoint_DeepEqual(t *testing.T) {
	type fields struct {
		svcEP *K8sServiceEndpoint
	}
	type args struct {
		o *K8sServiceEndpoint
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{

		{
			name: "both equal",
			fields: fields{
				svcEP: &K8sServiceEndpoint{
					BEIPs: map[string]bool{
						"172.20.0.1": true,
					},
					Ports: map[FEPortName]*L4Addr{
						FEPortName("foo"): {
							Protocol: NONE,
							Port:     1,
						},
					},
				},
			},
			args: args{
				o: &K8sServiceEndpoint{
					BEIPs: map[string]bool{
						"172.20.0.1": true,
					},
					Ports: map[FEPortName]*L4Addr{
						FEPortName("foo"): {
							Protocol: NONE,
							Port:     1,
						},
					},
				},
			},
			want: true,
		},
		{
			name: "different BE IPs",
			fields: fields{
				svcEP: &K8sServiceEndpoint{
					BEIPs: map[string]bool{
						"172.20.0.1": true,
					},
					Ports: map[FEPortName]*L4Addr{
						FEPortName("foo"): {
							Protocol: NONE,
							Port:     1,
						},
					},
				},
			},
			args: args{
				o: &K8sServiceEndpoint{
					BEIPs: map[string]bool{
						"172.20.0.2": true,
					},
					Ports: map[FEPortName]*L4Addr{
						FEPortName("foo"): {
							Protocol: NONE,
							Port:     1,
						},
					},
				},
			},
			want: false,
		},
		{
			name: "ports different name",
			fields: fields{
				svcEP: &K8sServiceEndpoint{
					BEIPs: map[string]bool{
						"172.20.0.1": true,
					},
					Ports: map[FEPortName]*L4Addr{
						FEPortName("foo"): {
							Protocol: NONE,
							Port:     1,
						},
					},
				},
			},
			args: args{
				o: &K8sServiceEndpoint{
					BEIPs: map[string]bool{
						"172.20.0.1": true,
					},
					Ports: map[FEPortName]*L4Addr{
						FEPortName("foz"): {
							Protocol: NONE,
							Port:     1,
						},
					},
				},
			},
			want: false,
		},
		{
			name: "ports different content",
			fields: fields{
				svcEP: &K8sServiceEndpoint{
					BEIPs: map[string]bool{
						"172.20.0.1": true,
					},
					Ports: map[FEPortName]*L4Addr{
						FEPortName("foo"): {
							Protocol: NONE,
							Port:     1,
						},
					},
				},
			},
			args: args{
				o: &K8sServiceEndpoint{
					BEIPs: map[string]bool{
						"172.20.0.1": true,
					},
					Ports: map[FEPortName]*L4Addr{
						FEPortName("foo"): {
							Protocol: NONE,
							Port:     2,
						},
					},
				},
			},
			want: false,
		},
		{
			name: "ports different one is bigger",
			fields: fields{
				svcEP: &K8sServiceEndpoint{
					Ports: map[FEPortName]*L4Addr{
						FEPortName("foo"): {
							Protocol: NONE,
							Port:     1,
						},
					},
				},
			},
			args: args{
				o: &K8sServiceEndpoint{
					Ports: map[FEPortName]*L4Addr{
						FEPortName("foo"): {
							Protocol: NONE,
							Port:     1,
						},
						FEPortName("baz"): {
							Protocol: NONE,
							Port:     2,
						},
					},
				},
			},
			want: false,
		},
		{
			name:   "ports different one is nil",
			fields: fields{},
			args: args{
				o: &K8sServiceEndpoint{
					Ports: map[FEPortName]*L4Addr{
						FEPortName("foo"): {
							Protocol: NONE,
							Port:     1,
						},
					},
				},
			},
			want: false,
		},
		{
			name: "both nil",
			args: args{},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.fields.svcEP.DeepEqual(tt.args.o); got != tt.want {
				t.Errorf("K8sServiceEndpoint.DeepEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}
