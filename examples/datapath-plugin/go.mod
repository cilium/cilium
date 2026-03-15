module github.com/cilium/cilium/examples/datapath-plugin

go 1.25.0

require (
	github.com/cilium/cilium v0.0.0-00010101000000-000000000000
	github.com/cilium/ebpf v0.20.1-0.20260218191617-ee67e7f43dd9
	google.golang.org/grpc v1.79.2
	google.golang.org/protobuf v1.36.11
)

replace github.com/cilium/cilium => ../../

require (
	github.com/rogpeppe/go-internal v1.13.1 // indirect
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260226221140-a57be14db171 // indirect
)

tool github.com/cilium/ebpf/cmd/bpf2go
