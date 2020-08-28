// Copyright 2019-2020 Authors of Hubble
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package filters

import (
	"context"
	"fmt"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	"github.com/golang/protobuf/proto"
)

func filterByTCPFlags(flags []*flowpb.TCPFlags) (FilterFunc, error) {
	return func(ev *v1.Event) bool {
		l4tcp := ev.GetFlow().GetL4().GetTCP()
		if l4tcp == nil {
			return false
		}
		for i := 0; i < len(flags); i++ {
			if proto.Equal(flags[i], l4tcp.GetFlags()) {
				return true
			}
		}
		return false
	}, nil
}

// TCPFilter implements filtering based on TCP protocol header
type TCPFilter struct{}

// OnBuildFilter builds a L4 protocol filter
func (p *TCPFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc

	if ff.GetTcpFlags() != nil {
		pf, err := filterByTCPFlags(ff.GetTcpFlags())
		if err != nil {
			return nil, fmt.Errorf("invalid tcp protocol filter: %v", err)
		}
		fs = append(fs, pf)
	}

	return fs, nil
}
