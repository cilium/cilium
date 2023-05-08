// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"fmt"
	"strings"

	"github.com/go-openapi/loads"
	"github.com/go-openapi/spec"
)

var (
	ErrUnknownWildcard = fmt.Errorf("Unsupported API wildcard")
	ErrUnknownFlag     = fmt.Errorf("Unknown API flag")
)

func pascalize(in string) string {
	if len(in) < 2 {
		return strings.ToUpper(in)
	}
	switch in {
	case "bgp":
		return "BGP"
	case "id":
		return "ID"
	case "ip":
		return "IP"
	case "ipam":
		return "IPAM"
	case "lrp":
		return "LRP"
	}
	return strings.ToUpper(in[0:1]) + strings.ToLower(in[1:])
}

func pathToFlagSuffix(path string) string {
	result := ""
	path = strings.TrimPrefix(path, "/")
	for _, hunk := range strings.Split(path, "/") {
		// TODO: Maybe we can just rename the /cgroup-dump-metadata API to /cgroups to avoid this loop?
		for _, word := range strings.Split(hunk, "-") {
			trimmed := strings.Trim(word, "{}")
			result = result + pascalize(trimmed)
		}
	}

	return result
}

func parseSpecPaths(paths *spec.Paths) PathSet {
	results := make(PathSet)

	for path, item := range paths.Paths {
		suffix := pathToFlagSuffix(path)
		ops := map[string]*spec.Operation{
			"Delete": item.Delete,
			"Get":    item.Get,
			"Patch":  item.Patch,
			"Post":   item.Post,
			"Put":    item.Put,
		}
		for prefix, op := range ops {
			if op != nil {
				flag := prefix + suffix
				results[flag] = Endpoint{
					Method:      strings.ToUpper(prefix),
					Path:        path,
					Description: op.Description,
				}
			}
		}
	}

	return PathSet(results)
}

func generateDeniedAPIEndpoints(allPaths PathSet, allowed []string) (PathSet, error) {
	// default to "deny all", then allow specified APIs by flag
	denied := allPaths

	var wildcardPrefixes []string
	for _, opt := range allowed {
		switch strings.Index(opt, "*") {
		case -1: // No wildcard
			break
		case len(opt) - 1: // suffix
			prefix := strings.TrimSuffix(opt, "*")
			if len(prefix) == 0 { // Full opt "*", ie allow all
				return PathSet{}, nil
			}
			wildcardPrefixes = append(wildcardPrefixes, prefix)
			continue
		default:
			return nil, fmt.Errorf("%w: %q", ErrUnknownWildcard, opt)
		}
		if _, ok := denied[opt]; ok {
			delete(denied, opt)
		} else {
			return nil, fmt.Errorf("%w: %q", ErrUnknownFlag, opt)
		}
	}

	for _, prefix := range wildcardPrefixes {
		for f := range denied {
			if strings.HasPrefix(f, prefix) {
				delete(denied, f)
			}
		}
	}
	return denied, nil
}

// Endpoint is an API Endpoint for a parsed API specification.
type Endpoint struct {
	Method      string
	Path        string
	Description string
}

// PathSet is a set of APIs in the form of a map of canonical pascalized flag
// name to MethodPath, for example:
// "GetEndpointID": {"GET", "/endpoint/{id}"}
type PathSet map[string]Endpoint

func NewPathSet(spec *loads.Document) PathSet {
	return parseSpecPaths(spec.Spec().Paths)
}

// AllowedFlagsToDeniedPaths parses the input API specification and the provided
// commandline flags, and returns the PathSet that should be administratively
// disabled using a subsequent call to DisableAPIs().
func AllowedFlagsToDeniedPaths(spec *loads.Document, allowed []string) (PathSet, error) {
	paths := parseSpecPaths(spec.Spec().Paths)
	return generateDeniedAPIEndpoints(paths, allowed)
}
