// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	subsysLogAttr = []any{logfields.LogSubsys, "eni"}
)

const (
	fieldEniID         = "eniID"
	fieldStatusCode    = "statusCode"
	fieldProto         = "proto"
	fieldContentLength = "contentLength"
	fieldHeader        = "header"
	fieldBodyLength    = "bodyLength"
	fieldBodyContent   = "bodyContent"
)
