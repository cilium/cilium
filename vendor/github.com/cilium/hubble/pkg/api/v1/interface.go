// Copyright 2019 Authors of Hubble
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

package v1

import (
	pb "github.com/cilium/hubble/api/v1/flow"

	"github.com/gogo/protobuf/types"
	"github.com/golang/protobuf/proto"
)

// Flow is an interface matching pb.Flow
type Flow interface {
	proto.Message
	GetTime() *types.Timestamp
	GetVerdict() pb.Verdict
	GetDropReason() uint32
	GetEthernet() *pb.Ethernet
	GetIP() *pb.IP
	GetL4() *pb.Layer4
	GetSource() *pb.Endpoint
	GetDestination() *pb.Endpoint
	GetType() pb.FlowType
	GetNodeName() string
	GetSourceNames() []string
	GetDestinationNames() []string
	GetL7() *pb.Layer7
	GetReply() bool
	GetEventType() *pb.CiliumEventType
	GetSourceService() *pb.Service
	GetDestinationService() *pb.Service
	GetSummary() string
}

// This ensures that the protobuf definition implements the interface
var _ Flow = &pb.Flow{}
