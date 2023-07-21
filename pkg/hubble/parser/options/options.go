// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package options

import (
	"fmt"

	"github.com/sirupsen/logrus"
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
func Redact(logger logrus.FieldLogger, httpQuery bool, kafkaApiKey bool) Option {
	return func(opt *Options) {
		opt.RedactHTTPQuery = httpQuery
		opt.RedactKafkaAPIKey = kafkaApiKey
		if logger != nil {
			logger.WithField(
				"options",
				fmt.Sprintf("%+v", opt)).Info("configured Hubble with redact options")
		}
	}
}
