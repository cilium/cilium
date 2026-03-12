module github.com/cilium/cilium/examples/datapath-plugin

go 1.25.0

require (
	github.com/cilium/cilium v0.0.0-00010101000000-000000000000
	github.com/cilium/ebpf v0.20.1-0.20260108141042-f7e80f49188b
	google.golang.org/grpc v1.78.0
)

replace github.com/cilium/cilium => ../../

require (
	github.com/rogpeppe/go-internal v1.13.1 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260122232226-8e98ce8d340d // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

tool github.com/cilium/ebpf/cmd/bpf2go
