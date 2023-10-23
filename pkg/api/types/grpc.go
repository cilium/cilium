// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"github.com/cilium/cilium/pkg/hive/cell"
	"google.golang.org/grpc"
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
