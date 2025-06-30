// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package reflect

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	rpb "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/cilium/cilium/hubble/cmd/common/config"
	"github.com/cilium/cilium/hubble/cmd/common/conn"
	"github.com/cilium/cilium/hubble/cmd/common/template"
)

// New returns the reflect command.
func New(vp *viper.Viper) *cobra.Command {
	reflectCmd := &cobra.Command{
		Use:   "reflect",
		Short: "Use gRPC reflection to explore Hubble's API",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()
			hubbleConn, err := conn.NewWithFlags(ctx, vp)
			if err != nil {
				return err
			}
			defer hubbleConn.Close()
			return runReflect(ctx, cmd, hubbleConn)
		},
		Hidden: true,
	}

	// add config.ServerFlags to the help template as these flags are used by
	// this command
	template.RegisterFlagSets(reflectCmd, config.ServerFlags)

	return reflectCmd
}

func runReflect(ctx context.Context, cmd *cobra.Command, conn *grpc.ClientConn) (err error) {
	client, err := rpb.NewServerReflectionClient(conn).ServerReflectionInfo(ctx)
	if err != nil {
		return err
	}
	req := rpb.ServerReflectionRequest{
		MessageRequest: &rpb.ServerReflectionRequest_ListServices{},
	}
	if err := client.Send(&req); err != nil {
		return err
	}
	res, err := client.Recv()
	if err != nil {
		return err
	}
	services, ok := res.GetMessageResponse().(*rpb.ServerReflectionResponse_ListServicesResponse)
	if !ok {
		return fmt.Errorf("unexpected response: %v", res)
	}
	// same proto file can be imported multiple times from different places. keep track of proto filenames
	// so that we don't print them multiple times.
	visited := make(map[string]struct{})
	encoder := json.NewEncoder(cmd.OutOrStdout())
	for _, svc := range services.ListServicesResponse.GetService() {
		if svc.GetName() == "grpc.reflection.v1alpha.ServerReflection" || svc.GetName() == "grpc.health.v1.Health" {
			continue
		}
		err = client.Send(&rpb.ServerReflectionRequest{
			MessageRequest: &rpb.ServerReflectionRequest_FileContainingSymbol{
				FileContainingSymbol: svc.GetName(),
			},
		})
		if err != nil {
			return err
		}
		res, err := client.Recv()
		if err != nil {
			return err
		}
		files, ok := res.GetMessageResponse().(*rpb.ServerReflectionResponse_FileDescriptorResponse)
		if !ok {
			return fmt.Errorf("unexpected response: %v", res)
		}
		if err := handleDescriptorResponse(visited, client, files, encoder); err != nil {
			return err
		}

	}
	return nil
}

func handleDescriptorResponse(
	visited map[string]struct{},
	client rpb.ServerReflection_ServerReflectionInfoClient,
	resp *rpb.ServerReflectionResponse_FileDescriptorResponse,
	encoder *json.Encoder,
) error {
	for _, r := range resp.FileDescriptorResponse.GetFileDescriptorProto() {
		desc := descriptorpb.FileDescriptorProto{}
		if err := proto.Unmarshal(r, &desc); err != nil {
			return err
		}
		if _, ok := visited[desc.GetName()]; !ok {
			visited[desc.GetName()] = struct{}{}
			if err := encoder.Encode(&desc); err != nil {
				return err
			}
		}
		for _, dep := range desc.GetDependency() {
			if err := resolveDependency(visited, client, dep, encoder); err != nil {
				return err
			}
		}
	}
	return nil
}

func resolveDependency(
	visited map[string]struct{},
	client rpb.ServerReflection_ServerReflectionInfoClient,
	filename string,
	encoder *json.Encoder,
) error {
	req := rpb.ServerReflectionRequest{
		MessageRequest: &rpb.ServerReflectionRequest_FileByFilename{FileByFilename: filename},
	}
	if err := client.Send(&req); err != nil {
		return err
	}
	res, err := client.Recv()
	if err != nil {
		return err
	}
	files, ok := res.GetMessageResponse().(*rpb.ServerReflectionResponse_FileDescriptorResponse)
	if !ok {
		return fmt.Errorf("unexpected response: %v", res.GetMessageResponse())
	}
	return handleDescriptorResponse(visited, client, files, encoder)
}
