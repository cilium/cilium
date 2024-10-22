/*
Copyright 2023 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package suite

import (
	"fmt"

	"k8s.io/apimachinery/pkg/util/sets"

	"sigs.k8s.io/gateway-api/pkg/features"
)

// -----------------------------------------------------------------------------
// Conformance Profiles - Public Types
// -----------------------------------------------------------------------------

// ConformanceProfile is a group of features that have a related purpose, e.g.
// to cover specific protocol support or a specific feature present in Gateway
// API.
//
// For more details see the relevant GEP: https://gateway-api.sigs.k8s.io/geps/gep-1709/
type ConformanceProfile struct {
	Name             ConformanceProfileName
	CoreFeatures     sets.Set[features.FeatureName]
	ExtendedFeatures sets.Set[features.FeatureName]
}

type ConformanceProfileName string

const (
	// GatewayHTTPConformanceProfileName indicates the name of the conformance profile
	// which covers HTTP functionality with Gateways.
	GatewayHTTPConformanceProfileName ConformanceProfileName = "GATEWAY-HTTP"

	// GatewayTLSConformanceProfileName indicates the name of the conformance profile
	// which covers TLS stream functionality with Gateways.
	GatewayTLSConformanceProfileName ConformanceProfileName = "GATEWAY-TLS"

	// GatewayGRPCConformanceProfileName indicates the name of the conformance profile
	// which covers GRPC functionality with Gateways.
	GatewayGRPCConformanceProfileName ConformanceProfileName = "GATEWAY-GRPC"

	// MeshHTTPConformanceProfileName indicates the name of the conformance profile
	// which covers HTTP functionality with service mesh.
	MeshHTTPConformanceProfileName ConformanceProfileName = "MESH-HTTP"

	// MeshGRPCConformanceProfileName indicates the name of the conformance profile
	// which covers GRPC functionality with service mesh.
	MeshGRPCConformanceProfileName ConformanceProfileName = "MESH-GRPC"
)

// -----------------------------------------------------------------------------
// Conformance Profiles - Public Vars
// -----------------------------------------------------------------------------

var (
	// GatewayHTTPConformanceProfile is a ConformanceProfile that covers testing HTTP
	// related functionality with Gateways.
	GatewayHTTPConformanceProfile = ConformanceProfile{
		Name: GatewayHTTPConformanceProfileName,
		CoreFeatures: sets.New(
			features.SupportGateway,
			features.SupportReferenceGrant,
			features.SupportHTTPRoute,
		),
		ExtendedFeatures: sets.New[features.FeatureName]().
			Insert(features.SetsToNamesSet(
				features.GatewayExtendedFeatures,
				features.HTTPRouteExtendedFeatures,
			).UnsortedList()...),
	}

	// GatewayTLSConformanceProfile is a ConformanceProfile that covers testing TLS
	// related functionality with Gateways.
	GatewayTLSConformanceProfile = ConformanceProfile{
		Name: GatewayTLSConformanceProfileName,
		CoreFeatures: sets.New(
			features.SupportGateway,
			features.SupportReferenceGrant,
			features.SupportTLSRoute,
		),
		ExtendedFeatures: features.SetsToNamesSet(features.GatewayExtendedFeatures),
	}

	// GatewayGRPCConformanceProfile is a ConformanceProfile that covers testing GRPC
	// related functionality with Gateways.
	GatewayGRPCConformanceProfile = ConformanceProfile{
		Name: GatewayGRPCConformanceProfileName,
		CoreFeatures: sets.New(
			features.SupportGateway,
			features.SupportReferenceGrant,
			features.SupportGRPCRoute,
		),
		ExtendedFeatures: features.SetsToNamesSet(features.GatewayExtendedFeatures),
	}

	// MeshHTTPConformanceProfile is a ConformanceProfile that covers testing HTTP
	// service mesh related functionality.
	MeshHTTPConformanceProfile = ConformanceProfile{
		Name: MeshHTTPConformanceProfileName,
		CoreFeatures: sets.New(
			features.SupportMesh,
			features.SupportHTTPRoute,
		),
		ExtendedFeatures: sets.New[features.FeatureName]().
			Insert(features.SetsToNamesSet(
				features.MeshExtendedFeatures,
				features.HTTPRouteExtendedFeatures,
			).UnsortedList()...),
	}

	// MeshGRPCConformanceProfile is a ConformanceProfile that covers testing GRPC
	// service mesh related functionality.
	MeshGRPCConformanceProfile = ConformanceProfile{
		Name: MeshHTTPConformanceProfileName,
		CoreFeatures: sets.New(
			features.SupportMesh,
			features.SupportGRPCRoute,
		),
		ExtendedFeatures: features.SetsToNamesSet(features.MeshExtendedFeatures),
	}
)

// RegisterConformanceProfile allows downstream tests to register unique profiles that
// define their own set of features
func RegisterConformanceProfile(p ConformanceProfile) {
	_, ok := conformanceProfileMap[p.Name]
	if ok {
		panic(fmt.Sprintf("ConformanceProfile named %q is already registered", p.Name))
	}
	conformanceProfileMap[p.Name] = p
}

// -----------------------------------------------------------------------------
// Conformance Profiles - Private Profile Mapping Helpers
// -----------------------------------------------------------------------------

// conformanceProfileMap maps short human-readable names to their respective
// ConformanceProfiles.
var conformanceProfileMap = map[ConformanceProfileName]ConformanceProfile{
	GatewayHTTPConformanceProfileName: GatewayHTTPConformanceProfile,
	GatewayTLSConformanceProfileName:  GatewayTLSConformanceProfile,
	GatewayGRPCConformanceProfileName: GatewayGRPCConformanceProfile,
	MeshHTTPConformanceProfileName:    MeshHTTPConformanceProfile,
	MeshGRPCConformanceProfileName:    MeshGRPCConformanceProfile,
}

// getConformanceProfileForName retrieves a known ConformanceProfile by its simple
// human readable ConformanceProfileName.
func getConformanceProfileForName(name ConformanceProfileName) (ConformanceProfile, error) {
	profile, ok := conformanceProfileMap[name]
	if !ok {
		return profile, fmt.Errorf("%s is not a valid conformance profile", name)
	}

	return profile, nil
}

// getConformanceProfilesForTest retrieves the ConformanceProfiles a test belongs to.
func getConformanceProfilesForTest(test ConformanceTest, conformanceProfiles sets.Set[ConformanceProfileName]) sets.Set[*ConformanceProfile] {
	matchingConformanceProfiles := sets.New[*ConformanceProfile]()
	for _, conformanceProfileName := range conformanceProfiles.UnsortedList() {
		cp := conformanceProfileMap[conformanceProfileName]
		hasAllFeatures := true
		for _, feature := range test.Features {
			if !cp.CoreFeatures.Has(feature) && !cp.ExtendedFeatures.Has(feature) {
				hasAllFeatures = false
				break
			}
		}
		if hasAllFeatures {
			matchingConformanceProfiles.Insert(&cp)
		}
	}

	return matchingConformanceProfiles
}
