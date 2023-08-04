// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/annotation"
)

// ErrNotVRouterAnno is an error returned from parseAnnotation() when the
// the casted string is not a `cilium.io/bgp-virtual-router` annotation
type ErrNotVRouterAnno struct {
	a string
}

func (e ErrNotVRouterAnno) Error() string {
	return "annotation " + e.a + " is not a valid cilium.io/bgp-virtual-router annotation"
}

// ErrNoASNAnno is an error returned from parseAnnotation() when the bgp-virtual-router
// annotation does not include a local ASN.
type ErrNoASNAnno struct {
	a string
}

func (e ErrNoASNAnno) Error() string {
	return "annotation " + e.a + " provides no asn"
}

// ErrASN is an error returned from parseAnnotation() when the bgp-virtual-router
// annotation includes an ASN that cannot be parsed into an
type ErrASNAnno struct {
	err  string
	asn  string
	anno string
}

func (e ErrASNAnno) Error() string {
	return "ASN" + e.asn + " in annotation " + e.anno + " cannot be parsed into integer: " + e.err
}

// ErrAttrib is an error returned from parseAnnotation() when an attribute is
// provided but its value is malformed.
type ErrAttrib struct {
	anno string
	attr string
	err  string
}

func (e ErrAttrib) Error() string {
	return "annotation " + e.anno + " failed to parse attribute " + e.attr + ":" + e.err
}

// The BGP control plane may need some node-specific configuration for
// instantiating virtual routers.
//
// For example, BGP router IDs cannot repeat in a BGP peering topology.
// When Cilium cannot generate a unique router ID it will look for a unique
// router ID for the virtual router identified by its local ASN.
//
// We define a set of attributes which can be defined via Node-specific
// kubernetes annotations.
//
// This Kubernetes annotation's syntax is:
// `cilium.io/bgp-virtual-router.{asn}="attr1=value1,attr2=value2"
//
// Where {asn} is replaced by the local ASN of the virtual router.
//
// Currently supported attributes are:
//
//	router-id=IPv4 (string): when present on a specific node, use this value for
//	                         the router ID of the virtual router with local {asn}
//	local-port=port (int):  the local port to listen on for incoming BGP connections
type Attributes struct {
	// The local ASN of the virtual router these Attributes targets.
	ASN int64
	// The router ID to use for the virtual router with the above local ASN.
	RouterID string
	// The local BGP port to listen on.
	LocalPort int32
}

// AnnotationMap coorelates a parsed Annotations structure with the local
// ASN its annotating.
type AnnotationMap map[int64]Attributes

// ErrMulti holds multiple errors and formats them sanely when printed.
type ErrMulti struct {
	errs []error
}

func (e ErrMulti) Error() string {
	s := strings.Builder{}
	for _, err := range e.errs {
		s.WriteString(err.Error() + ",")
	}
	return s.String()
}

func (a AnnotationMap) ResolveRouterID(localASN int64) (string, error) {
	if _, ok := a[localASN]; ok {
		var err error
		var parsed netip.Addr
		if parsed, err = netip.ParseAddr(a[localASN].RouterID); err == nil && !parsed.IsUnspecified() {
			return parsed.String(), nil
		}
		return "", fmt.Errorf("failed to parse RouterID for local ASN %v: %w", localASN, err)
	}
	return "", fmt.Errorf("router id not specified by annotation, cannot resolve router id for local ASN %v", localASN)
}

// NewAnnotationMap parses a Node's annotations into a AnnotationMap
// and returns the latter.
//
// An error is returned containing one or more parsing errors.
//
// This is for convenience so the caller can log all parsing errors at once.
// The error should still be treated as a normal descrete error and an empty
// AnnotationMap is returned.
func NewAnnotationMap(a map[string]string) (AnnotationMap, error) {
	am := AnnotationMap{}
	errs := make([]error, 0, len(a))
	for key, value := range a {
		asn, attrs, err := parseAnnotation(key, value)
		if err != nil && !errors.As(err, &ErrNotVRouterAnno{}) {
			errs = append(errs, err)
			continue
		}
		am[asn] = attrs
	}
	if len(errs) > 0 {
		return am, ErrMulti{errs}
	}
	return am, nil
}

// parseAnnotation will attempt to parse a `cilium.io/bgp-virtual-router`
// annotation into an Attributes structure.
//
// Errors returned by this parse method are defined at top of file.
func parseAnnotation(key string, value string) (int64, Attributes, error) {
	var out Attributes
	// is this an annotation we care about?
	if !strings.HasPrefix(key, annotation.BGPVRouterAnnoPrefix) {
		return 0, out, ErrNotVRouterAnno{key}
	}

	// parse out asn from annotation key, if split at "." will be 3rd element
	var asn int64
	if anno := strings.Split(key, "."); len(anno) != 3 {
		return 0, out, ErrNoASNAnno{key}
	} else {
		var err error
		asn, err = strconv.ParseInt(anno[2], 10, 64)
		if err != nil {
			return 0, out, ErrASNAnno{}
		}
	}
	out.ASN = asn

	// split annotation value into multiple "key=value" formatted attributes.
	attrs := strings.Split(value, ",")
	if len(attrs) == 0 {
		return 0, out, nil // empty attributes, not an error
	}
	// parse string attributes into Attributes structure.
	for _, attr := range attrs {
		kv := strings.Split(attr, "=")
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "router-id":
			addr, _ := netip.ParseAddr(kv[1])
			if addr.IsUnspecified() {
				return 0, out, ErrAttrib{key, kv[0], "could not parse in an IPv4 address"}
			}
			out.RouterID = kv[1]
		case "local-port":
			port, err := strconv.ParseInt(kv[1], 10, 0)
			if err != nil {
				return 0, out, ErrAttrib{key, kv[0], "could not parse into port number"}
			}
			if port > math.MaxUint16 {
				return 0, out, ErrAttrib{key, kv[0], "local port must be smaller then 65535"}
			}
			out.LocalPort = int32(port)
		}
	}
	return asn, out, nil
}
