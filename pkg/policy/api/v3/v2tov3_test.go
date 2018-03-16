// Copyright 2017-2018 Authors of Cilium
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

package v3

import (
	"reflect"
	"testing"

	"github.com/cilium/cilium/pkg/policy/api/v2"
)

func TestV2RulesTov3Rules(t *testing.T) {
	type args struct {
		v2Rules *v2.Rules
	}
	tests := []struct {
		name string
		args args
		want *Rules
	}{
	// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := V2RulesTov3Rules(tt.args.v2Rules); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("V2RulesTov3Rules() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestV2RuleTov3Rule(t *testing.T) {
	type args struct {
		v2Rule *v2.Rule
	}
	tests := []struct {
		name string
		args args
		want *Rule
	}{
	// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := V2RuleTov3Rule(tt.args.v2Rule); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("V2RuleTov3Rule() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_v2ESTov3ES(t *testing.T) {
	type args struct {
		v2ES *v2.EndpointSelector
	}
	tests := []struct {
		name string
		args args
		want *IdentitySelector
	}{
	// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := v2ESTov3ES(tt.args.v2ES); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("v2ESTov3ES() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_v2IRTov3IR(t *testing.T) {
	type args struct {
		v2IR *v2.IngressRule
	}
	tests := []struct {
		name string
		args args
		want []IngressRule
	}{
	// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := v2IRTov3IR(tt.args.v2IR); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("v2IRTov3IR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_v2ERTov3ER(t *testing.T) {
	type args struct {
		v2ER *v2.EgressRule
	}
	tests := []struct {
		name string
		args args
		want []EgressRule
	}{
	// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := v2ERTov3ER(tt.args.v2ER); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("v2ERTov3ER() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_v2CIDRRuleTov3CIDRRule(t *testing.T) {
	type args struct {
		v2CR *v2.CIDRRule
	}
	tests := []struct {
		name string
		args args
		want *CIDRRule
	}{
	// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := v2CIDRRuleTov3CIDRRule(tt.args.v2CR); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("v2CIDRRuleTov3CIDRRule() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_v2CIDRTov3CIDR(t *testing.T) {
	type args struct {
		v2C v2.CIDR
	}
	tests := []struct {
		name string
		args args
		want CIDR
	}{
	// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := v2CIDRTov3CIDR(tt.args.v2C); got != tt.want {
				t.Errorf("v2CIDRTov3CIDR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_v2EntityTov3Entity(t *testing.T) {
	type args struct {
		v2E *v2.Entity
	}
	tests := []struct {
		name string
		args args
		want *Entity
	}{
	// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := v2EntityTov3Entity(tt.args.v2E); got != tt.want {
				t.Errorf("v2EntityTov3Entity() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_v2PRTov3PR(t *testing.T) {
	type args struct {
		v2PR *v2.PortRule
	}
	tests := []struct {
		name string
		args args
		want *PortRule
	}{
	// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := v2PRTov3PR(tt.args.v2PR); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("v2PRTov3PR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_v2PRHTTPTov3PRHTTP(t *testing.T) {
	type args struct {
		v2PRH *v2.PortRuleHTTP
	}
	tests := []struct {
		name string
		args args
		want *PortRuleHTTP
	}{
	// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := v2PRHTTPTov3PRHTTP(tt.args.v2PRH); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("v2PRHTTPTov3PRHTTP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_v2PRKafkaTov3PRKafka(t *testing.T) {
	type args struct {
		v2K *v2.PortRuleKafka
	}
	tests := []struct {
		name string
		args args
		want *PortRuleKafka
	}{
	// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := v2PRKafkaTov3PRKafka(tt.args.v2K); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("v2PRKafkaTov3PRKafka() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_v2PPTov3PP(t *testing.T) {
	type args struct {
		v2PP *v2.PortProtocol
	}
	tests := []struct {
		name string
		args args
		want *PortProtocol
	}{
	// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := v2PPTov3PP(tt.args.v2PP); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("v2PPTov3PP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_v2K8sSNTov3K8sSN(t *testing.T) {
	type args struct {
		v2K8sSN *v2.K8sServiceNamespace
	}
	tests := []struct {
		name string
		args args
		want *K8sServiceNamespace
	}{
	// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := v2K8sSNTov3K8sSN(tt.args.v2K8sSN); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("v2K8sSNTov3K8sSN() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_v2K8sSSNTov3K8sSSN(t *testing.T) {
	type args struct {
		k8sSSN *v2.K8sServiceSelectorNamespace
	}
	tests := []struct {
		name string
		args args
		want *K8sServiceSelectorNamespace
	}{
	// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := v2K8sSSNTov3K8sSSN(tt.args.k8sSSN); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("v2K8sSSNTov3K8sSSN() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_v2SSTov3SS(t *testing.T) {
	type args struct {
		v2SS v2.ServiceSelector
	}
	tests := []struct {
		name string
		args args
		want ServiceSelector
	}{
	// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := v2SSTov3SS(tt.args.v2SS); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("v2SSTov3SS() = %v, want %v", got, tt.want)
			}
		})
	}
}
