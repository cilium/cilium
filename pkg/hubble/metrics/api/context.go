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

package api

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	pb "github.com/cilium/cilium/api/v1/flow"
)

// ContextIdentifier describes the identification method of a transmission or
// receiving context
type ContextIdentifier int

const (
	// ContextDisabled disables context identification
	ContextDisabled ContextIdentifier = iota
	// ContextIdentity uses the full set of identity labels for identification purposes
	ContextIdentity
	// ContextNamespace uses the namespace name for identification purposes
	ContextNamespace
	// ContextPod uses the pod name for identification purposes
	ContextPod
	// ContextPodShort uses a short version of the pod name. It should
	// typically map to the deployment/replicaset name
	ContextPodShort
	// ContextDNS uses the DNS name for identification purposes
	ContextDNS
)

// ContextOptionsHelp is the help text for context options
const ContextOptionsHelp = `
 sourceContext          := { identity | namespace | pod | pod-short | dns }
 destinationContext     := { identity | namespace | pod | pod-short | dns }`

var shortPodPattern = regexp.MustCompile("^(.+?)(-[a-z0-9]+){1,2}$")

// String return the context identifier as string
func (c ContextIdentifier) String() string {
	switch c {
	case ContextDisabled:
		return "disabled"
	case ContextIdentity:
		return "identity"
	case ContextNamespace:
		return "namespace"
	case ContextPod:
		return "pod"
	case ContextPodShort:
		return "pod-short"
	case ContextDNS:
		return "dns"
	}
	return fmt.Sprintf("%d", c)
}

// ContextOptions is the set of options to define whether and how to include
// sending and/or receiving context information
type ContextOptions struct {
	// Destination is the destination context to include in metrics
	Destination ContextIdentifier
	// Source is the source context to include in metrics
	Source ContextIdentifier
}

func parseContext(s string) (ContextIdentifier, error) {
	switch strings.ToLower(s) {
	case "identity":
		return ContextIdentity, nil
	case "namespace":
		return ContextNamespace, nil
	case "pod":
		return ContextPod, nil
	case "pod-short":
		return ContextPodShort, nil
	case "dns":
		return ContextDNS, nil
	default:
		return ContextDisabled, fmt.Errorf("unknown context '%s'", s)
	}
}

// ParseContextOptions parses a set of options and extracts the context
// relevant options
func ParseContextOptions(options Options) (*ContextOptions, error) {
	o := &ContextOptions{}
	for key, value := range options {
		switch strings.ToLower(key) {
		case "destinationcontext":
			c, err := parseContext(value)
			if err != nil {
				return nil, err
			}
			o.Destination = c
		case "sourcecontext":
			c, err := parseContext(value)
			if err != nil {
				return nil, err
			}
			o.Source = c
		}
	}

	return o, nil
}

func sourceNamespaceContext(flow *pb.Flow) (context string) {
	if flow.GetSource() != nil {
		context = flow.GetSource().Namespace
	}
	return
}

func sourceIdentityContext(flow *pb.Flow) (context string) {
	if flow.GetSource() != nil {
		context = strings.Join(flow.GetSource().Labels, ",")
	}
	return
}

func sourcePodContext(flow *pb.Flow) (context string) {
	if flow.GetSource() != nil {
		context = flow.GetSource().PodName
		if flow.GetSource().Namespace != "" {
			context = flow.GetSource().Namespace + "/" + context
		}
	}
	return
}

func shortenPodName(name string) string {
	return shortPodPattern.ReplaceAllString(name, "${1}")
}

func sourcePodShortContext(flow *pb.Flow) (context string) {
	if flow.GetSource() != nil {
		context = shortenPodName(flow.GetSource().PodName)
		if flow.GetSource().Namespace != "" {
			context = flow.GetSource().Namespace + "/" + context
		}
	}
	return
}

func sourceDNSContext(flow *pb.Flow) (context string) {
	if flow.GetSourceNames() != nil {
		context = strings.Join(flow.GetSourceNames(), ",")
	}
	return
}

func destinationNamespaceContext(flow *pb.Flow) (context string) {
	if flow.GetDestination() != nil {
		context = flow.GetDestination().Namespace
	}
	return
}

func destinationIdentityContext(flow *pb.Flow) (context string) {
	if flow.GetDestination() != nil {
		context = strings.Join(flow.GetDestination().Labels, ",")
	}
	return
}

func destinationPodContext(flow *pb.Flow) (context string) {
	if flow.GetDestination() != nil {
		context = flow.GetDestination().PodName
		if flow.GetDestination().Namespace != "" {
			context = flow.GetDestination().Namespace + "/" + context
		}
	}
	return
}

func destinationPodShortContext(flow *pb.Flow) (context string) {
	if flow.GetDestination() != nil {
		context = shortenPodName(flow.GetDestination().PodName)
		if flow.GetDestination().Namespace != "" {
			context = flow.GetDestination().Namespace + "/" + context
		}
	}
	return
}

func destinationDNSContext(flow *pb.Flow) (context string) {
	if flow.GetDestinationNames() != nil {
		context = strings.Join(flow.GetDestinationNames(), ",")
	}
	return
}

// GetLabelValues returns the values of the context relevant labels according
// to the configured options. The order of the values is the same as the order
// of the label names returned by GetLabelNames()
func (o *ContextOptions) GetLabelValues(flow *pb.Flow) (labels []string) {
	switch o.Source {
	case ContextNamespace:
		labels = append(labels, sourceNamespaceContext(flow))
	case ContextIdentity:
		labels = append(labels, sourceIdentityContext(flow))
	case ContextPod:
		labels = append(labels, sourcePodContext(flow))
	case ContextPodShort:
		labels = append(labels, sourcePodShortContext(flow))
	case ContextDNS:
		labels = append(labels, sourceDNSContext(flow))
	}

	switch o.Destination {
	case ContextNamespace:
		labels = append(labels, destinationNamespaceContext(flow))
	case ContextIdentity:
		labels = append(labels, destinationIdentityContext(flow))
	case ContextPod:
		labels = append(labels, destinationPodContext(flow))
	case ContextPodShort:
		labels = append(labels, destinationPodShortContext(flow))
	case ContextDNS:
		labels = append(labels, destinationDNSContext(flow))
	}

	return
}

// GetLabelNames returns a slice of label names required to fulfil the
// configured context description requirements
func (o *ContextOptions) GetLabelNames() (labels []string) {
	if o.Source != ContextDisabled {
		labels = append(labels, "source")
	}

	if o.Destination != ContextDisabled {
		labels = append(labels, "destination")
	}

	return
}

// Status returns the configuration status of context options suitable for use
// with Handler.Status
func (o *ContextOptions) Status() string {
	var status []string
	if o.Source != ContextDisabled {
		status = append(status, "source="+o.Source.String())
	}

	if o.Destination != ContextDisabled {
		status = append(status, "destination="+o.Destination.String())
	}

	sort.Strings(status)

	return strings.Join(status, ",")
}
