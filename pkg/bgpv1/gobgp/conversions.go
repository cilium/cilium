// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"errors"
	"fmt"
	"time"

	gobgp "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/cilium/cilium/pkg/bgpv1/types"
)

// ToGoBGPPath converts the Agent Path type to the GoBGP Path type
func ToGoBGPPath(p *types.Path) (*gobgp.Path, error) {
	nlri, err := apiutil.MarshalNLRI(p.NLRI)
	if err != nil {
		return nil, fmt.Errorf("failed to convert NLRI: %w", err)
	}

	pattrs, err := apiutil.MarshalPathAttributes(p.PathAttributes)
	if err != nil {
		return nil, fmt.Errorf("failed to convert PathAttribute: %w", err)
	}

	// ageTimestamp is Path's creation time stamp.
	// It is calculated by subtraction of the AgeNanoseconds from the current timestamp.
	ageTimestamp := timestamppb.New(time.Now().Add(time.Duration(-1 * p.AgeNanoseconds)))

	family := &gobgp.Family{
		Afi:  gobgp.Family_Afi(p.NLRI.AFI()),
		Safi: gobgp.Family_Safi(p.NLRI.SAFI()),
	}

	return &gobgp.Path{
		Nlri:   nlri,
		Pattrs: pattrs,
		Age:    ageTimestamp,
		Best:   p.Best,
		Family: family,
		Uuid:   p.UUID,
	}, nil
}

// ToAgentPath converts the GoBGP Path type to the Agent Path type
func ToAgentPath(p *gobgp.Path) (*types.Path, error) {
	family := bgp.AfiSafiToRouteFamily(uint16(p.Family.Afi), uint8(p.Family.Safi))

	nlri, err := apiutil.UnmarshalNLRI(family, p.Nlri)
	if err != nil {
		return nil, fmt.Errorf("failed to convert Nlri: %w", err)
	}

	pattrs, err := apiutil.UnmarshalPathAttributes(p.Pattrs)
	if err != nil {
		return nil, fmt.Errorf("failed to convert Pattrs: %w", err)
	}

	// ageNano is time since the Path was created in nanoseconds.
	// It is calculated by difference in time from age timestamp till now.
	ageNano := int64(time.Since(p.Age.AsTime()))

	return &types.Path{
		NLRI:           nlri,
		PathAttributes: pattrs,
		AgeNanoseconds: ageNano,
		Best:           p.Best,
		UUID:           p.Uuid,
	}, nil
}

// ToAgentPaths converts slice of the GoBGP Path type to slice of the Agent Path type
func ToAgentPaths(paths []*gobgp.Path) ([]*types.Path, error) {
	errs := []error{}
	ps := []*types.Path{}

	for _, path := range paths {
		p, err := ToAgentPath(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		ps = append(ps, p)
	}

	if len(errs) != 0 {
		return nil, errors.Join(errs...)
	}

	return ps, nil
}
