// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"google.golang.org/grpc"

	"github.com/cilium/cilium/pkg/hive/cell"
)

type GRPCService struct {
	Service *grpc.ServiceDesc
	Impl    any
}

type GRPCServiceOut struct {
	cell.Out
	Service GRPCService `group:"grpc-services"`
}

func NewGRPCServiceOut(svc *grpc.ServiceDesc, impl any) GRPCServiceOut {
	return GRPCServiceOut{Service: GRPCService{svc, impl}}
}
