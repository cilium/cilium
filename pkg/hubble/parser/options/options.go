// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package options

import "strings"

// Option is used to configure parsers
type Option func(*Options)

// Options contains all parser options
type Options struct {
	CacheSize                      int
	HubbleRedactSettings           HubbleRedactSettings
	EnableNetworkPolicyCorrelation bool
	SkipUnknownCGroupIDs           bool
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

func headerSliceToMap(headerList []string) map[string]struct{} {
	headerMap := make(map[string]struct{}, len(headerList))
	for _, header := range headerList {
		headerMap[strings.ToLower(header)] = struct{}{}
	}
	return headerMap
}
