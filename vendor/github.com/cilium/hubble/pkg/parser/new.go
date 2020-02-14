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

package parser

import (
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"

	pb "github.com/cilium/hubble/api/v1/flow"
	"github.com/cilium/hubble/pkg/parser/errors"
	"github.com/cilium/hubble/pkg/parser/getters"
	"github.com/cilium/hubble/pkg/parser/options"
	"github.com/cilium/hubble/pkg/parser/seven"
	"github.com/cilium/hubble/pkg/parser/threefour"
)

// Parser for all flows
type Parser struct {
	l34 *threefour.Parser
	l7  *seven.Parser
}

// New creates a new parser
func New(
	endpointGetter getters.EndpointGetter,
	identityGetter getters.IdentityGetter,
	dnsGetter getters.DNSGetter,
	ipGetter getters.IPGetter,
	serviceGetter getters.ServiceGetter,
	opts ...options.Option,
) (*Parser, error) {

	l34, err := threefour.New(endpointGetter, identityGetter, dnsGetter, ipGetter, serviceGetter)
	if err != nil {
		return nil, err
	}

	l7, err := seven.New(dnsGetter, ipGetter, serviceGetter, opts...)
	if err != nil {
		return nil, err
	}

	return &Parser{
		l34: l34,
		l7:  l7,
	}, nil
}

// Decode decodes the data from 'payload' into 'decoded'
func (p *Parser) Decode(payload *pb.Payload, decoded *pb.Flow) error {
	if payload == nil || len(payload.Data) == 0 {
		return errors.ErrEmptyData
	}

	eventType := payload.Data[0]
	switch eventType {
	case monitorAPI.MessageTypeDrop:
		fallthrough
	case monitorAPI.MessageTypeTrace:
		return p.l34.Decode(payload, decoded)
	case monitorAPI.MessageTypeAccessLog:
		return p.l7.Decode(payload, decoded)
	default:
		return errors.NewErrInvalidType(eventType)
	}
}
