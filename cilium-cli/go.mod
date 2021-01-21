module github.com/cilium/cilium-cli

go 1.15

replace (
	github.com/miekg/dns => github.com/cilium/dns v1.1.4-0.20190417235132-8e25ec9a0ff3
	github.com/optiopay/kafka => github.com/cilium/kafka v0.0.0-20180809090225-01ce283b732b

	// Using private fork of controller-tools. See commit msg for more context
	// as to why we are using a private fork.
	sigs.k8s.io/controller-tools => github.com/christarazi/controller-tools v0.3.1-0.20200911184030-7e668c1fb4c2

	// Fork until
	// https://github.com/kubernetes-sigs/structured-merge-diff/issues/172 is fixed.
	sigs.k8s.io/structured-merge-diff/v4 => github.com/christarazi/structured-merge-diff/v4 v4.0.2-0.20200917183246-1cc601931628
)

require (
	github.com/cilium/cilium v1.9.2
	github.com/cilium/hubble v0.7.1
	github.com/cloudflare/cfssl v1.5.0
	github.com/go-logr/logr v0.3.0 // indirect
	github.com/go-openapi/strfmt v0.19.11
	github.com/golang/protobuf v1.4.3
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/spf13/cobra v1.1.1
	golang.org/x/net v0.0.0-20201209123823-ac852fbbde11 // indirect
	google.golang.org/grpc v1.34.0
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c
	gopkg.in/yaml.v2 v2.4.0 // indirect
	k8s.io/api v0.19.6
	k8s.io/apimachinery v0.19.6
	k8s.io/client-go v0.19.6
)
