// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package client

import (
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func mustMarshalAny(src proto.Message) *anypb.Any {
	res, err := anypb.New(src)
	if err != nil {
		panic(fmt.Errorf("marshal any: %w", err))
	}
	return res
}
