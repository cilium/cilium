// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import (
	"github.com/cilium/cilium/api/v1/flow"
)

// Layer7 tracks flow layer 7 information.
type Layer7 struct {
	DNS       DNS             `json:"dns,omitempty"`
	HTTP      HTTP            `json:"http,omitempty"`
	LatencyNs uint64          `json:"latencyNs,omitempty"`
	Type      flow.L7FlowType `json:"type,omitempty"`
}

func protoToL7(l7 *flow.Layer7) Layer7 {
	if l7 == nil {
		return Layer7{}
	}

	return Layer7{
		DNS:       protoToDNS(l7.GetDns()),
		HTTP:      protoToHTTP(l7.GetHttp()),
		LatencyNs: l7.LatencyNs,
		Type:      l7.Type,
	}
}

// IsEmpty returns true if target has no data.
// NOTE: Leaving Type and LatencyNs fields unchecked since if no other fields are set the Layer7 will be deemed empty.
func (l7 Layer7) IsEmpty() bool {
	return l7.DNS.IsEmpty() && l7.HTTP.IsEmpty()
}

func (l7 Layer7) toProto() *flow.Layer7 {
	if l7.IsEmpty() {
		return nil
	}

	l := flow.Layer7{
		LatencyNs: l7.LatencyNs,
		Type:      l7.Type,
	}

	switch {
	case !l7.DNS.IsEmpty():
		l.Record = l7.DNS.toProto()
	case !l7.HTTP.IsEmpty():
		l.Record = l7.HTTP.toProto()
	}

	return &l
}

// DNS tracks flow DNS information.
type DNS struct {
	Query             string   `json:"query,omitempty"`
	Ips               []string `json:"ips,omitempty"`
	TTL               uint32   `json:"ttl,omitempty"`
	CNames            []string `json:"cnames,omitempty"`
	ObservationSource string   `json:"observationSource,omitempty"`
	RCode             uint32   `json:"rcode,omitempty"`
	Qtypes            []string `json:"qtypes,omitempty"`
	Rtypes            []string `json:"rtypes,omitempty"`
}

// IsEmpty returns true if target has no data.
// NOTE: Leaving TTL and RCode fields unchecked since if no other fields are set the DNS will be deemed empty.
func (d DNS) IsEmpty() bool {
	return d.Query == "" &&
		d.ObservationSource == "" &&
		len(d.Ips) == 0 &&
		len(d.CNames) == 0 &&
		len(d.Qtypes) == 0 &&
		len(d.Rtypes) == 0
}

func (d DNS) toProto() *flow.Layer7_Dns {
	if d.IsEmpty() {
		return nil
	}

	return &flow.Layer7_Dns{
		Dns: &flow.DNS{
			Query:             d.Query,
			Ips:               d.Ips,
			Ttl:               d.TTL,
			Cnames:            d.CNames,
			ObservationSource: d.ObservationSource,
			Rcode:             d.RCode,
			Qtypes:            d.Qtypes,
			Rrtypes:           d.Rtypes,
		},
	}
}

func protoToDNS(d *flow.DNS) DNS {
	if d == nil {
		return DNS{}
	}

	return DNS{
		Query:             d.Query,
		Ips:               d.Ips,
		TTL:               d.Ttl,
		CNames:            d.Cnames,
		ObservationSource: d.ObservationSource,
		RCode:             d.Rcode,
		Qtypes:            d.Qtypes,
		Rtypes:            d.Rrtypes,
	}
}

type (
	// HTTP tracks flow HTTP information.
	HTTP struct {
		Method   string       `json:"method,omitempty"`
		URL      string       `json:"url,omitempty"`
		Protocol string       `json:"protocol,omitempty"`
		Headers  []HTTPHeader `json:"headers,omitempty"`
		Code     uint32       `json:"code,omitempty"`
	}

	// HTTPHeader tracks flow HTTP header information.
	HTTPHeader struct {
		Key   string `json:"key,omitempty"`
		Value string `json:"value,omitempty"`
	}
)

func (h HTTP) toProto() *flow.Layer7_Http {
	if h.IsEmpty() {
		return nil
	}

	l := flow.Layer7_Http{
		Http: &flow.HTTP{
			Method:   h.Method,
			Url:      h.URL,
			Protocol: h.Protocol,
			Code:     h.Code,
		},
	}

	if len(h.Headers) == 0 {
		return &l
	}

	l.Http.Headers = make([]*flow.HTTPHeader, 0, len(h.Headers))
	for i := range h.Headers {
		l.Http.Headers = append(l.Http.Headers, &flow.HTTPHeader{
			Key:   h.Headers[i].Key,
			Value: h.Headers[i].Value,
		})
	}

	return &l
}

func protoToHTTP(h *flow.HTTP) HTTP {
	if h == nil {
		return HTTP{}
	}

	headers := make([]HTTPHeader, 0, len(h.Headers))
	for i := range h.Headers {
		headers = append(headers, HTTPHeader{
			Key:   h.Headers[i].Key,
			Value: h.Headers[i].Value,
		})
	}

	return HTTP{
		Method:   h.Method,
		URL:      h.Url,
		Protocol: h.Protocol,
		Headers:  headers,
		Code:     h.Code,
	}
}

// IsEmpty returns true if target has no data.
func (H HTTP) IsEmpty() bool {
	return H.Method == "" &&
		H.URL == "" &&
		H.Protocol == "" &&
		len(H.Headers) == 0 &&
		H.Code == 0
}
