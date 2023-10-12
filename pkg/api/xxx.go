package api

import "google.golang.org/grpc"

type GRPCService struct {
	Service *grpc.ServiceDesc
	Impl    any
}
