// Copyright 2019 Authors of Cilium
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

package policy

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/u8proto"
)

var annotationRegex = regexp.MustCompile("^((<(Ingress|Egress)/([0-9]{1,6})/(TCP|UDP|ANY)/([A-Za-z]{3,32})>,)+)$")

func validateL7ProtocolWithDirection(dir string, proto L7ParserType) error {
	switch proto {
	case ParserTypeHTTP:
		return nil
	case ParserTypeDNS:
		if dir == "Egress" {
			return nil
		}
	case ParserTypeKafka:
		if dir == "Ingress" {
			return nil
		}
	default:
		return fmt.Errorf("unsupported parser type %s", proto)

	}
	return fmt.Errorf("%s not allowed with direction %s", proto, dir)
}

func NewVisibilityPolicy(anno string) (*VisibilityPolicy, error) {
	// Add a trailing comma so we can match the regex, which expects a comma
	// after each tuple. This is hacky :(
	if anno[len(anno)-1] != ',' {
		anno = anno + ","
	}
	if !annotationRegex.MatchString(anno) {
		return nil, fmt.Errorf("annotation for proxy visibility did not match expected format %s", annotationRegex.String())
	}

	nvp := &VisibilityPolicy{
		Ingress: make(DirectionalVisibilityPolicy),
		Egress:  make(DirectionalVisibilityPolicy),
	}

	anSplit := strings.Split(anno, ",")
	for i := range anSplit {
		// Avoid empty string
		if len(anSplit[i]) == 0 {
			continue
		}
		proxyAnnoSplit := strings.Split(anSplit[i], "/")
		if len(proxyAnnoSplit) != 4 {
			err := fmt.Errorf("invalid number of fields (%d) in annotation", len(proxyAnnoSplit))
			return nil, err
		}
		// <Ingress|Egress --> Ingress|Egress
		// Don't need to validate the content itself, regex already did that.
		direction := proxyAnnoSplit[0][1:]
		port := proxyAnnoSplit[1]
		portInt, err := strconv.Atoi(port)
		if err != nil {
			err = fmt.Errorf("annotation for proxy visibility did not conform to expected format: %s", err)
			return nil, err
		}
		// Don't need to validate, regex already did that.
		l4Proto := proxyAnnoSplit[2]
		u8Prot, err := u8proto.ParseProtocol(l4Proto)
		if err != nil {
			return nil, fmt.Errorf("invalid L4 protocol %s", l4Proto)
		}
		// Remove trailing >.
		l7Protocol := L7ParserType(strings.ToLower(proxyAnnoSplit[3][:len(proxyAnnoSplit[3])-1]))

		if err := validateL7ProtocolWithDirection(direction, l7Protocol); err != nil {
			return nil, err
		}

		var dvp DirectionalVisibilityPolicy
		var ingress bool
		if direction == "Ingress" {
			dvp = nvp.Ingress
			ingress = true
		} else {
			dvp = nvp.Egress
			ingress = false
		}

		pp := fmt.Sprintf("%d/%s", portInt, l4Proto)
		if res, ok := dvp[pp]; ok {
			if res.Parser != l7Protocol {
				return nil, fmt.Errorf("duplicate annotations with different L7 protocols %s and %s for %s", res.Parser, l7Protocol, pp)
			}
		}
		dvp[pp] = &VisibilityMetadata{
			Parser:  l7Protocol,
			Port:    uint16(portInt),
			Proto:   u8Prot,
			Ingress: ingress,
		}
	}

	return nvp, nil
}

// TODO make L4Filter compose this
type VisibilityMetadata struct {
	Parser  L7ParserType
	Port    uint16
	Proto   u8proto.U8proto
	Ingress bool
}

// 80/TCP --> *VisibilityMetadata
type DirectionalVisibilityPolicy map[string]*VisibilityMetadata

type VisibilityPolicy struct {
	Ingress DirectionalVisibilityPolicy
	Egress  DirectionalVisibilityPolicy
}

func (v *VisibilityMetadata) CopyL7RulesPerEndpoint() L7DataMap {
	return nil
}
func (v *VisibilityMetadata) GetL7Parser() L7ParserType {
	return v.Parser
}
func (v *VisibilityMetadata) GetIngress() bool {
	return v.Ingress
}

func (v *VisibilityMetadata) GetPort() uint16 {
	return v.Port
}
