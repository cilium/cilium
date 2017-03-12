// Copyright 2016-2017 Authors of Cilium
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
	"bytes"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/u8proto"
)

type AuxRule struct {
	Expr string `json:"expr"`
}

type L4Filter struct {
	Port     int       `json:"port,omitempty"`
	Protocol string    `json:"protocol,omitempty"`
	Redirect string    `json:"redirect,omitempty"`
	Rules    []AuxRule `json:"rules,omitempty"`
}

func (l4 *L4Filter) String() string {
	b, err := json.MarshalIndent(l4, "", "  ")
	if err != nil {
		return err.Error()
	}
	return string(b)
}

func (l4 *L4Filter) UnmarshalJSON(data []byte) error {
	var l4filter struct {
		Port     int       `json:"port,omitempty"`
		Protocol string    `json:"protocol,omitempty"`
		Redirect string    `json:"redirect,omitempty"`
		Rules    []AuxRule `json:"rules,omitempty"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))

	if err := decoder.Decode(&l4filter); err != nil {
		return fmt.Errorf("decode of L4Filter failed: %s", err)
	}

	if l4filter.Protocol != "" {
		if _, err := u8proto.ParseProtocol(l4filter.Protocol); err != nil {
			return fmt.Errorf("decode of L4Filter failed: %s", err)
		}
	}

	l4.Port = l4filter.Port
	l4.Protocol = l4filter.Protocol
	l4.Redirect = l4filter.Redirect
	l4.Rules = make([]AuxRule, len(l4filter.Rules))
	copy(l4.Rules, l4filter.Rules)

	return nil
}

func (f *L4Filter) Merge(result *L4Policy, m map[string]L4Filter, proto string) {
	fmt := fmt.Sprintf("%s:%d", proto, f.Port)

	if _, ok := m[fmt]; !ok {
		m[fmt] = *f
	}
}

type AllowL4 struct {
	Ingress []L4Filter `json:"in-ports,omitempty"`
	Egress  []L4Filter `json:"out-ports,omitempty"`
}

func (l4 *AllowL4) Merge(result *L4Policy) {
	for _, f := range l4.Ingress {
		if f.Protocol == "" {
			f.Merge(result, result.Ingress, "tcp")
			f.Merge(result, result.Ingress, "udp")
		} else {
			f.Merge(result, result.Ingress, f.Protocol)
		}
	}

	for _, f := range l4.Egress {
		if f.Protocol == "" {
			f.Merge(result, result.Egress, "tcp")
			f.Merge(result, result.Egress, "udp")
		} else {
			f.Merge(result, result.Egress, f.Protocol)
		}
	}
}

type RuleL4 struct {
	Coverage []labels.Label `json:"coverage,omitempty"`
	Allow    []AllowL4      `json:"l4"`
}

func (l4 *RuleL4) IsMergeable() bool {
	return true
}

func (l4 *RuleL4) GetL4Policy(ctx *SearchContext, result *L4Policy) *L4Policy {
	if len(l4.Coverage) > 0 && !ctx.TargetCoveredBy(l4.Coverage) {
		policyTrace(ctx, "L4 Rule %v has no coverage\n", l4)
		return nil
	}

	for _, a := range l4.Allow {
		a.Merge(result)
	}

	return result
}

func (l4 *RuleL4) Resolve(node *Node) error {
	log.Debugf("Resolving L4 rule %+v\n", l4)
	for k := range l4.Coverage {
		l := &l4.Coverage[k]
		l.Resolve(node)

		if !strings.HasPrefix(l.AbsoluteKey(), node.Path()) &&
			!(l.Source == common.ReservedLabelSource) {
			return fmt.Errorf("label %s does not share prefix of node %s",
				l.AbsoluteKey(), node.Path())
		}
	}

	return nil
}

func (l4 *RuleL4) SHA256Sum() (string, error) {
	sha := sha512.New512_256()
	if err := json.NewEncoder(sha).Encode(l4); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha.Sum(nil)), nil
}

func (l4 *RuleL4) CoverageSHA256Sum() (string, error) {
	sha := sha512.New512_256()
	if err := json.NewEncoder(sha).Encode(l4.Coverage); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha.Sum(nil)), nil
}

type L4PolicyMap map[string]L4Filter

type L4Policy struct {
	// key format: "proto:port"
	Ingress L4PolicyMap
	Egress  L4PolicyMap
}

func NewL4Policy() *L4Policy {
	return &L4Policy{
		Ingress: make(L4PolicyMap),
		Egress:  make(L4PolicyMap),
	}
}

func (l4 *L4Policy) GetModel() *models.L4Policy {
	if l4 == nil {
		return nil
	}

	ingress := []string{}
	for _, v := range l4.Ingress {
		ingress = append(ingress, v.String())
	}

	egress := []string{}
	for _, v := range l4.Egress {
		ingress = append(ingress, v.String())
	}

	return &models.L4Policy{
		Ingress: ingress,
		Egress:  egress,
	}
}

func (l4 *L4Policy) DeepCopy() *L4Policy {
	cpy := &L4Policy{
		Ingress: make(map[string]L4Filter, len(l4.Ingress)),
		Egress:  make(map[string]L4Filter, len(l4.Ingress)),
	}

	for k, v := range l4.Ingress {
		cpy.Ingress[k] = v
	}

	for k, v := range l4.Egress {
		cpy.Egress[k] = v
	}

	return cpy
}
