module github.com/cilium/cilium-cli

go 1.16

replace (
	github.com/miekg/dns => github.com/cilium/dns v1.1.4-0.20190417235132-8e25ec9a0ff3
	github.com/optiopay/kafka => github.com/cilium/kafka v0.0.0-20180809090225-01ce283b732b

	go.universe.tf/metallb => github.com/cilium/metallb v0.1.1-0.20210520171949-40d425d20241

	// Using private fork of controller-tools. See commit msg for more context
	// as to why we are using a private fork.
	sigs.k8s.io/controller-tools => github.com/christarazi/controller-tools v0.3.1-0.20200911184030-7e668c1fb4c2
)

require (
	github.com/cilium/cilium v1.10.2
	github.com/cilium/hubble v0.8.0
	github.com/cilium/workerpool v1.0.0
	github.com/cloudflare/cfssl v1.5.0
	github.com/go-openapi/strfmt v0.20.0
	github.com/hashicorp/go-multierror v1.1.1
	github.com/mholt/archiver/v3 v3.5.0
	github.com/pkg/browser v0.0.0-20210606212950-a7b7a6107d32
	github.com/spf13/cobra v1.2.1
	google.golang.org/grpc v1.38.1
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c
	k8s.io/api v0.21.1
	k8s.io/apimachinery v0.21.1
	k8s.io/cli-runtime v0.21.1
	k8s.io/client-go v0.21.1
	k8s.io/klog/v2 v2.8.0
)
