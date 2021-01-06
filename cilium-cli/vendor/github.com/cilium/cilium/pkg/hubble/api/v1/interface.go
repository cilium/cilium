// Copyright 2019 Authors of Hubble
// Copyright 2020 Authors of Cilium
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
	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/identity"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/golang/protobuf/ptypes/wrappers"
)

// Flow is an interface matching pb.Flow
type Flow interface {
	proto.Message
	GetTime() *timestamp.Timestamp
	GetVerdict() flowpb.Verdict
	GetDropReason() uint32
	GetEthernet() *flowpb.Ethernet
	GetIP() *flowpb.IP
	GetL4() *flowpb.Layer4
	GetSource() *flowpb.Endpoint
	GetDestination() *flowpb.Endpoint
	GetType() flowpb.FlowType
	GetNodeName() string
	GetSourceNames() []string
	GetDestinationNames() []string
	GetL7() *flowpb.Layer7
	GetIsReply() *wrappers.BoolValue
	GetEventType() *flowpb.CiliumEventType
	GetSourceService() *flowpb.Service
	GetDestinationService() *flowpb.Service
	GetTrafficDirection() flowpb.TrafficDirection
	GetPolicyMatchType() uint32
	GetSummary() string
	GetDropReasonDesc() flowpb.DropReason
}

// This ensures that the protobuf definition implements the interface
var _ Flow = &flowpb.Flow{}

// EndpointInfo defines readable fields of a Cilium endpoint.
type EndpointInfo interface {
	GetID() uint64
	GetIdentity() identity.NumericIdentity
	GetK8sPodName() string
	GetK8sNamespace() string
	GetLabels() []string
}
