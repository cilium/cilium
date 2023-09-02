// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package options

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

// Option is used to configure parsers
type Option func(*Options)

// Options contains all parser options
type Options struct {
	CacheSize            int
	HubbleRedactSettings HubbleRedactSettings
}

// HubbleRedactSettings contains all hubble redact related options
type HubbleRedactSettings struct {
	Enabled           bool
	RedactHTTPQuery   bool
	RedactKafkaAPIKey bool
	RedactHttpHeaders HttpHeadersList
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

// Redact configures which data Hubble will redact.
func Redact(logger logrus.FieldLogger, httpQuery, kafkaApiKey bool, allowHeaders, denyHeaders []string) Option {
	return func(opt *Options) {
		opt.HubbleRedactSettings.Enabled = true
		opt.HubbleRedactSettings.RedactHTTPQuery = httpQuery
		opt.HubbleRedactSettings.RedactKafkaAPIKey = kafkaApiKey
		opt.HubbleRedactSettings.RedactHttpHeaders = HttpHeadersList{
			Allow: headerSliceToMap(allowHeaders),
			Deny:  headerSliceToMap(denyHeaders),
		}
		if logger != nil {
			logger.WithField(
				"options",
				fmt.Sprintf("%+v", opt)).Info("configured Hubble with redact options")
		}
	}
}

func headerSliceToMap(headerList []string) map[string]struct{} {
	headerMap := make(map[string]struct{}, len(headerList))
	for _, header := range headerList {
		headerMap[strings.ToLower(header)] = struct{}{}
	}
	return headerMap
}
