module github.com/cilium/cilium/examples/datapath-plugin

go 1.24.0

require (
	github.com/cilium/cilium v0.0.0-00010101000000-000000000000
	github.com/cilium/ebpf v0.19.1-0.20250729164112-d994daa25101
	github.com/vishvananda/netlink v1.3.1
	google.golang.org/grpc v1.74.2
)

replace github.com/cilium/cilium => ../../

require (
	github.com/rogpeppe/go-internal v1.13.1 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	golang.org/x/net v0.42.0 // indirect
	golang.org/x/sys v0.34.0 // indirect
	golang.org/x/text v0.27.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250728155136-f173205681a0 // indirect
	google.golang.org/protobuf v1.36.6 // indirect
)

tool github.com/cilium/ebpf/cmd/bpf2go
