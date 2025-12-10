// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package options

import (
	"net/netip"
	"strings"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/monitor"
)

// Option is used to configure parsers
type Option func(*Options)

// Options contains all parser options
type Options struct {
	CacheSize                      int
	HubbleRedactSettings           HubbleRedactSettings
	EnableNetworkPolicyCorrelation bool
	SkipUnknownCGroupIDs           bool

	DropNotifyDecoder          DropNotifyDecoderFunc
	DebugMsgDecoder            DebugMsgDecoderFunc
	DebugCaptureDecoder        DebugCaptureDecoderFunc
	TraceNotifyDecoder         TraceNotifyDecoderFunc
	PolicyVerdictNotifyDecoder PolicyVerdictNotifyDecoderFunc
	TraceSockNotifyDecoder     TraceSockNotifyDecoderFunc
	L34PacketDecoder           L34PacketDecoder
}

// HubbleRedactSettings contains all hubble redact related options
type HubbleRedactSettings struct {
	Enabled            bool
	RedactHTTPQuery    bool
	RedactHTTPUserInfo bool
	RedactKafkaAPIKey  bool
	RedactHttpHeaders  HttpHeadersList
}

// HttpHeadersList contains the allow/deny list of headers
type HttpHeadersList struct {
	Allow map[string]struct{}
	Deny  map[string]struct{}
}

// CacheSize configures the amount of L7 requests cached for latency calculation
func CacheSize(size int) Option {
	return func(opt *Options) {
		opt.CacheSize = size
	}
}

// WithRedact configures which data Hubble will redact.
func WithRedact(httpQuery, httpUserInfo, kafkaApiKey bool, allowHeaders, denyHeaders []string) Option {
	return func(opt *Options) {
		opt.HubbleRedactSettings.Enabled = true
		opt.HubbleRedactSettings.RedactHTTPQuery = httpQuery
		opt.HubbleRedactSettings.RedactHTTPUserInfo = httpUserInfo
		opt.HubbleRedactSettings.RedactKafkaAPIKey = kafkaApiKey
		opt.HubbleRedactSettings.RedactHttpHeaders = HttpHeadersList{
			Allow: headerSliceToMap(allowHeaders),
			Deny:  headerSliceToMap(denyHeaders),
		}
	}
}

// WithNetworkPolicyCorrelation configures the Network Policy correlation of Hubble Flows.
func WithNetworkPolicyCorrelation(enabled bool) Option {
	return func(opt *Options) {
		opt.EnableNetworkPolicyCorrelation = enabled
	}
}

// WithSkipUnknownCGroupIDs configures whether Hubble will skip events with unknown CGroup IDs.
func WithSkipUnknownCGroupIDs(enabled bool) Option {
	return func(opt *Options) {
		opt.SkipUnknownCGroupIDs = enabled
	}
}

type DropNotifyDecoderFunc func(data []byte, decoded *pb.Flow) (*monitor.DropNotify, error)

func WithDropNotifyDecoder(decode DropNotifyDecoderFunc) Option {
	return func(opt *Options) {
		opt.DropNotifyDecoder = decode
	}
}

type DebugMsgDecoderFunc func(data []byte) (*monitor.DebugMsg, error)

func WithDebugMsgDecoder(decode DebugMsgDecoderFunc) Option {
	return func(opt *Options) {
		opt.DebugMsgDecoder = decode
	}
}

type DebugCaptureDecoderFunc func(data []byte, decoded *pb.Flow) (*monitor.DebugCapture, error)

func WithDebugCaptureDecoder(decode DebugCaptureDecoderFunc) Option {
	return func(opt *Options) {
		opt.DebugCaptureDecoder = decode
	}
}

type TraceNotifyDecoderFunc func(data []byte, decoded *pb.Flow) (*monitor.TraceNotify, error)

func WithTraceNotifyDecoder(decode TraceNotifyDecoderFunc) Option {
	return func(opt *Options) {
		opt.TraceNotifyDecoder = decode
	}
}

type PolicyVerdictNotifyDecoderFunc func(data []byte, decoded *pb.Flow) (*monitor.PolicyVerdictNotify, error)

func WithPolicyVerdictNotifyDecoder(decode PolicyVerdictNotifyDecoderFunc) Option {
	return func(opt *Options) {
		opt.PolicyVerdictNotifyDecoder = decode
	}
}

type TraceSockNotifyDecoderFunc func(data []byte, decoded *pb.Flow) (*monitor.TraceSockNotify, error)

func WithTraceSockNotifyDecoder(decode TraceSockNotifyDecoderFunc) Option {
	return func(opt *Options) {
		opt.TraceSockNotifyDecoder = decode
	}
}

type L34PacketDecoder interface {
	DecodePacket(payload []byte, decoded *pb.Flow, isL3Device, isIPv6, isVXLAN, isGeneve bool) (
		sourceIP, destinationIP netip.Addr,
		sourcePort, destinationPort uint16,
		err error,
	)
}

func WithL34PacketDecoder(decoder L34PacketDecoder) Option {
	return func(opt *Options) {
		opt.L34PacketDecoder = decoder
	}
}

func headerSliceToMap(headerList []string) map[string]struct{} {
	headerMap := make(map[string]struct{}, len(headerList))
	for _, header := range headerList {
		headerMap[strings.ToLower(header)] = struct{}{}
	}
	return headerMap
}
