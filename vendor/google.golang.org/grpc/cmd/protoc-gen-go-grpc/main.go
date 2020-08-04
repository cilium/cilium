/*
 *
 * Copyright 2020 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

// protoc-gen-go-grpc is a plugin for the Google protocol buffer compiler to
// generate Go code. Install it by building this program and making it
// accessible within your PATH with the name:
//	protoc-gen-go-grpc
//
// The 'go-grpc' suffix becomes part of the argument for the protocol compiler,
// such that it can be invoked as:
//	protoc --go-grpc_out=. path/to/file.proto
//
// This generates Go service definitions for the protocol buffer defined by
// file.proto.  With that input, the output will be written to:
//	path/to/file_grpc.pb.go
package main

import (
	"flag"

	"google.golang.org/protobuf/compiler/protogen"
	"google.golang.org/protobuf/types/pluginpb"
)

var requireUnimplemented *bool

func main() {
	var flags flag.FlagSet
	requireUnimplemented = flags.Bool("requireUnimplementedServers", true, "unset to match legacy behavior")

	protogen.Options{
		ParamFunc: flags.Set,
	}.Run(func(gen *protogen.Plugin) error {
		gen.SupportedFeatures = uint64(pluginpb.CodeGeneratorResponse_FEATURE_PROTO3_OPTIONAL)
		for _, f := range gen.Files {
			if !f.Generate {
				continue
			}
			generateFile(gen, f)
		}
		return nil
	})
}
