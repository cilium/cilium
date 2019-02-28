// Copyright 2019 Authors of Cilium
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

package alignchecker

import (
	"reflect"

	check "github.com/cilium/cilium/pkg/alignchecker"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/configmap"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/eppolicymap"
	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/metricsmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/maps/proxymap"
	"github.com/cilium/cilium/pkg/maps/sockmap"
	"github.com/cilium/cilium/pkg/maps/tunnel"
)

// CheckStructAlignments checks whether size and offsets of the C and Go
// structs for the datapath match.
//
// C struct size info is extracted from the given ELF object file debug section
// encoded in DWARF.
//
// To find a matching C struct field, a Go field has to be tagged with
// `align:"field_name_in_c_struct". In the case of unnamed union field, such
// union fields can be referred with special tags - `align:"$union0"`,
// `align:"$union1"`, etc.
func CheckStructAlignments(path string) error {
	// Validate alignments of C and Go equivalent structs
	toCheck := map[string][]reflect.Type{
		"ipv4_ct_tuple":        []reflect.Type{reflect.TypeOf(ctmap.CtKey4{})},
		"ipv6_ct_tuple":        []reflect.Type{reflect.TypeOf(ctmap.CtKey6{})},
		"ct_entry":             []reflect.Type{reflect.TypeOf(ctmap.CtEntry{})},
		"ipcache_key":          []reflect.Type{reflect.TypeOf(ipcachemap.Key{})},
		"remote_endpoint_info": []reflect.Type{reflect.TypeOf(ipcachemap.RemoteEndpointInfo{})},
		"lb4_key":              []reflect.Type{reflect.TypeOf(lbmap.Service4Key{})},
		"lb4_service":          []reflect.Type{reflect.TypeOf(lbmap.Service4Value{})},
		"lb6_key":              []reflect.Type{reflect.TypeOf(lbmap.Service6Key{})},
		"lb6_service":          []reflect.Type{reflect.TypeOf(lbmap.Service6Value{})},
		"endpoint_info":        []reflect.Type{reflect.TypeOf(lxcmap.EndpointInfo{})},
		"metrics_key":          []reflect.Type{reflect.TypeOf(metricsmap.Key{})},
		"metrics_value":        []reflect.Type{reflect.TypeOf(metricsmap.Value{})},
		"policy_key":           []reflect.Type{reflect.TypeOf(policymap.PolicyKey{})},
		"policy_entry":         []reflect.Type{reflect.TypeOf(policymap.PolicyEntry{})},
		"proxy4_tbl_key":       []reflect.Type{reflect.TypeOf(proxymap.Proxy4Key{})},
		"proxy4_tbl_value":     []reflect.Type{reflect.TypeOf(proxymap.Proxy4Value{})},
		"proxy6_tbl_key":       []reflect.Type{reflect.TypeOf(proxymap.Proxy6Key{})},
		"proxy6_tbl_value":     []reflect.Type{reflect.TypeOf(proxymap.Proxy6Value{})},
		"sock_key":             []reflect.Type{reflect.TypeOf(sockmap.SockmapKey{})},
		"ep_config":            []reflect.Type{reflect.TypeOf(configmap.EndpointConfig{})},
		"endpoint_key": []reflect.Type{
			reflect.TypeOf(bpf.EndpointKey{}),
			reflect.TypeOf(eppolicymap.EndpointKey{}),
			reflect.TypeOf(tunnel.TunnelEndpoint{}),
		},
	}
	return check.CheckStructAlignments(path, toCheck)
}
