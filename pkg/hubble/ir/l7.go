// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import "github.com/cilium/cilium/api/v1/flow"

type Layer7 struct {
	Type      flow.L7FlowType
	LatencyNs uint64
	DNS       DNS
	HTTP      HTTP
	Kafka     Kafka
}

func protoToL7(l7 *flow.Layer7) Layer7 {
	if l7 == nil {
		return Layer7{}
	}
	return Layer7{
		Type:      l7.Type,
		LatencyNs: l7.LatencyNs,
		DNS:       protoToDNS(l7.GetDns()),
		HTTP:      protoToHTTP(l7.GetHttp()),
		Kafka:     protoToKafka(l7.GetKafka()),
	}
}

func (l7 Layer7) isEmpty() bool {
	return l7.DNS.isEmpty() && l7.HTTP.isEmpty() && l7.Kafka.IsEmpty()
}

func (l7 Layer7) toProto() *flow.Layer7 {
	if l7.isEmpty() {
		return nil
	}

	l := flow.Layer7{
		Type:      l7.Type,
		LatencyNs: l7.LatencyNs,
	}

	if !l7.DNS.isEmpty() {
		l.Record = l7.DNS.toProto()
	}
	if !l7.HTTP.isEmpty() {
		l.Record = l7.HTTP.toProto()
	}
	if !l7.Kafka.IsEmpty() {
		l.Record = l7.Kafka.toProto()
	}

	return &l
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

// Kafka tracks flow Kafka information.
type Kafka struct {
	APIVersion    int32
	APIKey        string
	CorrelationId int32
	Topic         string
	ErrorCode     int32
}

func (k Kafka) toProto() *flow.Layer7_Kafka {
	if k.IsEmpty() {
		return nil
	}

	return &flow.Layer7_Kafka{
		Kafka: &flow.Kafka{
			ApiVersion:    k.APIVersion,
			ApiKey:        k.APIKey,
			CorrelationId: k.CorrelationId,
			Topic:         k.Topic,
			ErrorCode:     k.ErrorCode,
		},
	}
}

func protoToKafka(k *flow.Kafka) Kafka {
	if k == nil {
		return Kafka{}
	}

	return Kafka{
		APIVersion:    k.ApiVersion,
		APIKey:        k.ApiKey,
		CorrelationId: k.CorrelationId,
		Topic:         k.Topic,
		ErrorCode:     k.ErrorCode,
	}
}

// IsEmpty returns true if target is empty.
func (k Kafka) IsEmpty() bool {
	return k.APIKey == "" && k.Topic == ""
}

// DNS tracks flow DNS information.
type DNS struct {
	Query             string
	Ips               []string
	TTL               uint32
	CNames            []string
	ObservationSource string
	RCode             uint32
	Qtypes            []string
	Rtypes            []string
}

func (d DNS) isEmpty() bool {
	return d.Query == "" && len(d.Ips) == 0 && len(d.CNames) == 0 && d.ObservationSource == "" && len(d.Qtypes) == 0 && len(d.Rtypes) == 0
}

func (d DNS) toProto() *flow.Layer7_Dns {
	if d.isEmpty() {
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

type (
	// HTTP tracks flow HTTP information.
	HTTP struct {
		Code     uint32
		Method   string
		URL      string
		Protocol string
		Headers  []HTTPHeader
	}

	// HTTPHeader tracks flow HTTP header information.
	HTTPHeader struct {
		Key   string
		Value string
	}
)

func (h HTTP) toProto() *flow.Layer7_Http {
	if h.isEmpty() {
		return nil
	}
	l := flow.Layer7_Http{
		Http: &flow.HTTP{
			Code:     h.Code,
			Method:   h.Method,
			Url:      h.URL,
			Protocol: h.Protocol,
		},
	}
	for _, hdr := range h.Headers {
		l.Http.Headers = append(l.Http.Headers, &flow.HTTPHeader{
			Key:   hdr.Key,
			Value: hdr.Value,
		})
	}

	return &l
}

func protoToHTTP(h *flow.HTTP) HTTP {
	if h == nil {
		return HTTP{}
	}

	headers := make([]HTTPHeader, 0, len(h.Headers))
	for _, hdr := range h.Headers {
		headers = append(headers, HTTPHeader{
			Key:   hdr.Key,
			Value: hdr.Value,
		})
	}

	return HTTP{
		Code:     h.Code,
		Method:   h.Method,
		URL:      h.Url,
		Protocol: h.Protocol,
		Headers:  headers,
	}
}

func (H HTTP) isEmpty() bool {
	return H.Code == 0 && H.Method == "" && H.URL == "" && H.Protocol == "" && len(H.Headers) == 0
}
