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

package api

import (
	"fmt"
	"strconv"
)

// Validate validates a policy rule
func (r Rule) Validate() error {
	for _, i := range r.Ingress {
		if err := i.Validate(); err != nil {
			return err
		}
	}

	for _, e := range r.Egress {
		if err := e.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// Validate validates an ingress policy rule
func (i IngressRule) Validate() error {
	for _, p := range i.ToPorts {
		if err := p.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// Validate validates an egress policy rule
func (e EgressRule) Validate() error {
	for _, p := range e.ToPorts {
		if err := p.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// Validate validates a port policy rule
func (pr PortRule) Validate() error {
	for _, p := range pr.Ports {
		if err := p.Validate(); err != nil {
			return err
		}
	}

	return nil
}

// Validate validates a port/protocol pair
func (pp PortProtocol) Validate() error {
	if pp.Port == "" {
		return fmt.Errorf("Port must be specified")
	}

	p, err := strconv.ParseUint(pp.Port, 0, 16)
	if err != nil {
		return fmt.Errorf("Unable to parse port: %s", err)
	}

	if p == 0 {
		return fmt.Errorf("Port cannot be 0")
	}

	if pp.Protocol != "" && pp.Protocol != "any" &&
		pp.Protocol != "tcp" && pp.Protocol != "udp" {
		return fmt.Errorf("Invalid protocol \"%s\", must be { tcp | udp }",
			pp.Protocol)
	}

	return nil
}
