// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package alignchecker

import (
	check "github.com/cilium/cilium/pkg/alignchecker"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/authmap"
	"github.com/cilium/cilium/pkg/maps/bwmap"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/egressmap"
	"github.com/cilium/cilium/pkg/maps/eventsmap"
	"github.com/cilium/cilium/pkg/maps/fragmap"
	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/maps/metricsmap"
	"github.com/cilium/cilium/pkg/maps/neighborsmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/maps/ratelimitmap"
	"github.com/cilium/cilium/pkg/maps/recorder"
	"github.com/cilium/cilium/pkg/maps/signalmap"
	"github.com/cilium/cilium/pkg/maps/srv6map"
	"github.com/cilium/cilium/pkg/maps/tunnel"
	"github.com/cilium/cilium/pkg/maps/vtep"
)

var (
	toCheck      = map[string][]any{}
	toCheckSizes = map[string][]any{}
)

func registerToCheck(c map[string][]any) {
	for typ, str := range c {
		toCheck[typ] = append(toCheck[typ], str...)
	}
}

func registerToCheckSizes(c map[string][]any) {
	for size, str := range c {
		toCheckSizes[size] = append(toCheckSizes[size], str...)
	}
}

// CheckStructAlignments checks whether size and offsets of the C and Go
// structs for the datapath match.
//
// C struct layout is extracted from the given ELF object file's BTF info.
//
// To find a matching C struct field, a Go field has to be tagged with
// `align:"field_name_in_c_struct". In the case of unnamed union field, such
// union fields can be referred with special tags - `align:"$union0"`,
// `align:"$union1"`, etc.
func CheckStructAlignments(path string) error {
	// Validate alignments of C and Go equivalent structs
	if err := check.CheckStructAlignments(path, toCheck, true); err != nil {
		return err
	}
	return check.CheckStructAlignments(path, toCheckSizes, false)
}

func init() {
	registerToCheck(map[string][]any{
		"ipv4_ct_tuple":        {ctmap.CtKey4{}, ctmap.CtKey4Global{}},
		"ipv6_ct_tuple":        {ctmap.CtKey6{}, ctmap.CtKey6Global{}},
		"ct_entry":             {ctmap.CtEntry{}},
		"ipcache_key":          {ipcachemap.Key{}},
		"remote_endpoint_info": {ipcachemap.RemoteEndpointInfo{}},
		"lb4_key":              {lbmap.Service4Key{}},
		"lb4_service":          {lbmap.Service4Value{}},
		"lb4_backend":          {lbmap.Backend4ValueV3{}},
		"lb6_key":              {lbmap.Service6Key{}},
		"lb6_service":          {lbmap.Service6Value{}},
		"lb6_backend":          {lbmap.Backend6ValueV3{}},
		"endpoint_info":        {lxcmap.EndpointInfo{}},
		"metrics_key":          {metricsmap.Key{}},
		"metrics_value":        {metricsmap.Value{}},
		"policy_key":           {policymap.PolicyKey{}},
		"policy_entry":         {policymap.PolicyEntry{}},
		"ipv4_revnat_tuple":    {lbmap.SockRevNat4Key{}},
		"ipv4_revnat_entry":    {lbmap.SockRevNat4Value{}},
		"ipv6_revnat_tuple":    {lbmap.SockRevNat6Key{}},
		"ipv6_revnat_entry":    {lbmap.SockRevNat6Value{}},
		"v6addr": {
			neighborsmap.Key6{},
			srv6map.PolicyValue{},
			srv6map.SIDKey{},
		},
		"macaddr":           {neighborsmap.Value{}},
		"ipv4_frag_id":      {fragmap.FragmentKey{}},
		"ipv4_frag_l4ports": {fragmap.FragmentValue{}},
		"capture4_wcard":    {recorder.CaptureWcard4{}},
		"capture6_wcard":    {recorder.CaptureWcard6{}},
		"capture_rule":      {recorder.CaptureRule4{}},
		// TODO: alignchecker does not support nested structs yet.
		// "capture_rule":      {recorder.CaptureRule6{}},
		// "ipv4_nat_entry":    {nat.NatEntry4{}},
		// "ipv6_nat_entry":    {nat.NatEntry6{}},
		"endpoint_key":            {bpf.EndpointKey{}},
		"lb4_affinity_key":        {lbmap.Affinity4Key{}},
		"lb6_affinity_key":        {lbmap.Affinity6Key{}},
		"lb_affinity_match":       {lbmap.AffinityMatchKey{}},
		"lb_affinity_val":         {lbmap.AffinityValue{}},
		"lb4_src_range_key":       {lbmap.SourceRangeKey4{}},
		"lb6_src_range_key":       {lbmap.SourceRangeKey6{}},
		"edt_id":                  {bwmap.EdtId{}},
		"edt_info":                {bwmap.EdtInfo{}},
		"egress_gw_policy_key":    {egressmap.EgressPolicyKey4{}},
		"egress_gw_policy_entry":  {egressmap.EgressPolicyVal4{}},
		"srv6_vrf_key4":           {srv6map.VRFKey4{}},
		"srv6_vrf_key6":           {srv6map.VRFKey6{}},
		"srv6_policy_key4":        {srv6map.PolicyKey4{}},
		"srv6_policy_key6":        {srv6map.PolicyKey6{}},
		"tunnel_key":              {tunnel.TunnelKey{}},
		"tunnel_value":            {tunnel.TunnelValue{}},
		"vtep_key":                {vtep.Key{}},
		"vtep_value":              {vtep.VtepEndpointInfo{}},
		"auth_key":                {authmap.AuthKey{}},
		"auth_info":               {authmap.AuthInfo{}},
		"skip_lb4_key":            {lbmap.SkipLB4Key{}},
		"skip_lb6_key":            {lbmap.SkipLB6Key{}},
		"ratelimit_key":           {ratelimitmap.Key{}},
		"ratelimit_value":         {ratelimitmap.Value{}},
		"ratelimit_metrics_key":   {ratelimitmap.MetricsKey{}},
		"ratelimit_metrics_value": {ratelimitmap.MetricsValue{}},
	})

	registerToCheckSizes(map[string][]any{
		"__u16": {
			lbmap.Backend4Key{},
			lbmap.Backend6Key{},
			lbmap.RevNat4Key{},
			lbmap.RevNat6Key{},
		},
		"__u32": {
			lbmap.Backend4KeyV3{},
			lbmap.Backend6KeyV3{},
			signalmap.Key{},
			signalmap.Value{},
			eventsmap.Key{},
			eventsmap.Value{},
			policymap.CallKey{},
			policymap.CallValue{},
			srv6map.VRFValue{},
			srv6map.SIDValue{},
		},
		"__be32": {neighborsmap.Key4{}},
	})
}
