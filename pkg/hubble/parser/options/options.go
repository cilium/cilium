// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package options

import (
	"github.com/sirupsen/logrus"
)

const (
	HttpUrlQuery = "http-url-query"
	KafkaApiKey  = "kafka-api-key"
)

// Option is used to configure parsers
type Option func(*Options)

// Options contains all parser options
type Options struct {
	CacheSize         int
	RedactHTTPQuery   bool
	RedactKafkaAPIKey bool
}

// CacheSize configures the amount of L7 requests cached for latency calculation
func CacheSize(size int) Option {
	return func(opt *Options) {
		opt.CacheSize = size
	}
}

// Redact configures which data Hubble will redact.
func Redact(logger logrus.FieldLogger, hubbleRedactOptions []string) Option {
	return func(opt *Options) {
		validOpts := []string{}
		for _, option := range hubbleRedactOptions {
			switch option {
			case HttpUrlQuery:
				opt.RedactHTTPQuery = true
			case KafkaApiKey:
				opt.RedactKafkaAPIKey = true
			default:
				if logger != nil {
					logger.WithField("option", option).Warn("ignoring unknown Hubble redact option")
				}
				continue
			}
			validOpts = append(validOpts, option)
		}
		if logger != nil {
			logger.WithField("options", validOpts).Info("configured Hubble with redact options")
		}
	}
}
