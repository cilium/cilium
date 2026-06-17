// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"fmt"

	gobgp "github.com/osrg/gobgp/v4/api"

	"github.com/cilium/cilium/pkg/bgp/types"
)

// toGoBGPMonitoringPolicy maps a Cilium BMP monitoring policy to the GoBGP
// AddBmpRequest monitoring policy enum.
func toGoBGPMonitoringPolicy(p types.BMPMonitoringPolicy) gobgp.AddBmpRequest_MonitoringPolicy {
	switch p {
	case types.BMPMonitoringPolicyPre:
		return gobgp.AddBmpRequest_MONITORING_POLICY_PRE
	case types.BMPMonitoringPolicyPost:
		return gobgp.AddBmpRequest_MONITORING_POLICY_POST
	case types.BMPMonitoringPolicyBoth:
		return gobgp.AddBmpRequest_MONITORING_POLICY_BOTH
	case types.BMPMonitoringPolicyLocal:
		return gobgp.AddBmpRequest_MONITORING_POLICY_LOCAL
	case types.BMPMonitoringPolicyAll:
		return gobgp.AddBmpRequest_MONITORING_POLICY_ALL
	default:
		return gobgp.AddBmpRequest_MONITORING_POLICY_PRE
	}
}

// AddBMP configures a BMP monitoring station that this BGP instance streams its
// monitoring data to. It is idempotent at the reconciler level: changing an
// existing station's parameters requires a RemoveBMP followed by AddBMP.
func (g *GoBGPServer) AddBMP(ctx context.Context, s *types.BMPServer) error {
	if s == nil {
		return fmt.Errorf("nil BMP server")
	}
	req := &gobgp.AddBmpRequest{
		Address:           s.Address,
		Port:              s.Port,
		Policy:            toGoBGPMonitoringPolicy(s.MonitoringPolicy),
		StatisticsTimeout: s.StatisticsTimeout,
		SysName:           s.SysName,
		SysDescr:          s.SysDescr,
	}
	if err := g.server.AddBmp(ctx, req); err != nil {
		return fmt.Errorf("failed while adding BMP station %s:%d: %w", s.Address, s.Port, err)
	}
	return nil
}

// RemoveBMP removes a previously configured BMP monitoring station.
func (g *GoBGPServer) RemoveBMP(ctx context.Context, s *types.BMPServer) error {
	if s == nil {
		return fmt.Errorf("nil BMP server")
	}
	req := &gobgp.DeleteBmpRequest{
		Address: s.Address,
		Port:    s.Port,
	}
	if err := g.server.DeleteBmp(ctx, req); err != nil {
		return fmt.Errorf("failed while removing BMP station %s:%d: %w", s.Address, s.Port, err)
	}
	return nil
}
