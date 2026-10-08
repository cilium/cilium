// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsclient

import (
	"time"

	"google.golang.org/grpc/codes"
)

type ConnectionOptions struct {
	RetryBackoff    BackoffParams
	RetryConnection bool
	IsRetriable     func(code codes.Code) (retry bool)
}

type BackoffParams struct {
	Min, Max, Reset time.Duration
}

var Defaults = ConnectionOptions{
	RetryBackoff: BackoffParams{
		Min:   time.Second,
		Max:   time.Minute,
		Reset: 2 * time.Minute,
	},

	IsRetriable: func(code codes.Code) bool {
		switch code {
		case codes.PermissionDenied, codes.Aborted, codes.Unauthenticated, codes.Unavailable, codes.Canceled:
			return false
		}
		return true
	},
}
