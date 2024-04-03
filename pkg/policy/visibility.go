// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/u8proto"
)

var (
	singleAnnotationRegex = "<(Ingress|Egress)/([1-9][0-9]{1,5})/(TCP|UDP|SCTP|ANY)/([A-Za-z]{3,32})>"
	annotationRegex       = regexp.MustCompile(fmt.Sprintf(`^((%s)(,(%s))*)$`, singleAnnotationRegex, singleAnnotationRegex))
)

func validateL7ProtocolWithDirection(dir string, proto L7ParserType) error {
	switch proto {
	case ParserTypeHTTP:
		return nil
	case ParserTypeDNS:
		if dir == "Egress" {
			return nil
		}
	case ParserTypeKafka:
		return nil
	default:
		return fmt.Errorf("unsupported parser type %s", proto)

	}
	return fmt.Errorf("%s not allowed with direction %s", proto, dir)
}

// NewVisibilityPolicy generates the VisibilityPolicy that is encoded in the
// annotation parameter.
// Returns an error:
//   - if the annotation does not correspond to the expected
//     format for a visibility annotation.
//   - if there is a conflict between the state encoded in the annotation (e.g.,
//     different L7 protocols for the same L4 port / protocol / traffic direction.
func NewVisibilityPolicy(anno string) (*VisibilityPolicy, error) {
	if !annotationRegex.MatchString(anno) {
		return nil, fmt.Errorf("annotation for proxy visibility did not match expected format %s", annotationRegex.String())
	}

	nvp := &VisibilityPolicy{
		Ingress: make(DirectionalVisibilityPolicy),
		Egress:  make(DirectionalVisibilityPolicy),
	}

	// TODO: look into using regex groups.
	anSplit := strings.Split(anno, ",")
	for i := range anSplit {
		proxyAnnoSplit := strings.Split(anSplit[i], "/")
		if len(proxyAnnoSplit) != 4 {
			err := fmt.Errorf("invalid number of fields (%d) in annotation", len(proxyAnnoSplit))
			return nil, err
		}
		// <Ingress|Egress --> Ingress|Egress
		// Don't need to validate the content itself, regex already did that.
		direction := proxyAnnoSplit[0][1:]
		port := proxyAnnoSplit[1]

		portInt, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("unable to parse port: %s", err)
		}

		// Don't need to validate, regex already did that.
		l4Proto := proxyAnnoSplit[2]
		u8Prot, err := u8proto.ParseProtocol(l4Proto)
		if err != nil {
			return nil, fmt.Errorf("invalid L4 protocol %s", l4Proto)
		}

		// ANY equates to TCP and UDP in the datapath; the datapath itself does
		// not support 'Any' protocol paired with a port at L4.
		var protos []u8proto.U8proto
		if u8Prot == u8proto.ANY {
			protos = append(protos, u8proto.TCP)
			protos = append(protos, u8proto.UDP)
			protos = append(protos, u8proto.SCTP)
		} else {
			protos = append(protos, u8Prot)
		}
		// Remove trailing '>'.
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

		for _, prot := range protos {
			pp := strconv.FormatUint(portInt, 10) + "/" + prot.String()
			if res, ok := dvp[pp]; ok {
				if res.Parser != l7Protocol {
					return nil, fmt.Errorf("duplicate annotations with different L7 protocols %s and %s for %s", res.Parser, l7Protocol, pp)
				}
			}

			l7Meta := generateL7AllowAllRules(l7Protocol)

			dvp[pp] = &VisibilityMetadata{
				Parser:     l7Protocol,
				Port:       uint16(portInt),
				Proto:      prot,
				Ingress:    ingress,
				L7Metadata: l7Meta,
			}
		}
	}

	return nvp, nil
}

func generateL7AllowAllRules(parser L7ParserType) L7DataMap {
	var m L7DataMap
	switch parser {
	case ParserTypeDNS:
		m = L7DataMap{}
		// Create an entry to explicitly allow all at L7 for DNS.
		emptyL3Selector := &identitySelector{source: &labelIdentitySelector{selector: api.WildcardEndpointSelector}, key: wildcardSelectorKey}
		m[emptyL3Selector] = &PerSelectorPolicy{
			L7Rules: api.L7Rules{
				DNS: []api.PortRuleDNS{
					{
						MatchPattern: "*",
					},
				},
			},
		}
	}
	return m
}

// VisibilityMetadata encodes state about what type of traffic should be
// redirected to an L7Proxy. Implements the ProxyPolicy interface.
// TODO: an L4Filter could be composed of this type.
type VisibilityMetadata struct {
	// Parser represents the proxy to which traffic should be redirected.
	Parser L7ParserType

	// Port, in tandem with Proto, signifies which L4 port for which traffic
	// should be redirected.
	Port uint16

	// Proto, in tandem with port, signifies which L4 protocol for which traffic
	// should be redirected.
	Proto u8proto.U8proto

	// Ingress specifies whether ingress traffic at the given L4 port / protocol
	// should be redirected to the proxy.
	Ingress bool

	// L7Metadata encodes optional information what is allowed at L7 for
	// visibility. Some specific protocol parsers do not need this set for
	// allowing of traffic (e.g., HTTP), but some do (e.g., DNS).
	L7Metadata L7DataMap
}

// DirectionalVisibilityPolicy is a mapping of VisibilityMetadata keyed by
// L4 Port / L4 Protocol (e.g., 80/TCP) for a given traffic direction (e.g.,
// ingress or egress). This encodes at which L4 Port / L4 Protocol traffic
// should be redirected to a given L7 proxy. An empty instance of this type
// indicates that no traffic should be redirected.
type DirectionalVisibilityPolicy map[string]*VisibilityMetadata

// VisibilityPolicy represents for both ingress and egress which types of
// traffic should be redirected to a given L7 proxy.
type VisibilityPolicy struct {
	Ingress DirectionalVisibilityPolicy
	Egress  DirectionalVisibilityPolicy
	Error   error
}

// CopyL7RulesPerEndpoint returns a shallow copy of the L7Metadata of the
// L4Filter.
func (v *VisibilityMetadata) CopyL7RulesPerEndpoint() L7DataMap {
	if v.L7Metadata != nil {
		return v.L7Metadata.ShallowCopy()
	}
	return nil
}

// GetL7Parser returns the L7ParserType for this VisibilityMetadata.
func (v *VisibilityMetadata) GetL7Parser() L7ParserType {
	return v.Parser
}

// GetIngress returns whether the VisibilityMetadata applies at ingress or
// egress.
func (v *VisibilityMetadata) GetIngress() bool {
	return v.Ingress
}

// GetPort returns at which port the VisibilityMetadata applies.
func (v *VisibilityMetadata) GetPort() uint16 {
	return v.Port
}

// GetListener returns the optional listener name.
func (l4 *VisibilityMetadata) GetListener() string {
	return ""
}
