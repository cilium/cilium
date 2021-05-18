module github.com/cilium/cilium-cli

go 1.16

replace (
	// https://github.com/kubernetes-sigs/kustomize/issues/3262#issuecomment-841980352
	github.com/go-openapi/spec => github.com/go-openapi/spec v0.19.8
	github.com/miekg/dns => github.com/cilium/dns v1.1.4-0.20190417235132-8e25ec9a0ff3
	github.com/optiopay/kafka => github.com/cilium/kafka v0.0.0-20180809090225-01ce283b732b

	// Using cilium/netlink until XFRM patches merged upstream
	github.com/vishvananda/netlink => github.com/cilium/netlink v1.0.1-0.20210305225027-66e1713b4f2e
	gopkg.in/yaml.v2 => gopkg.in/yaml.v2 v2.2.8 // To avoid https://github.com/go-yaml/yaml/pull/571.
	k8s.io/client-go => github.com/cilium/client-go v0.0.0-20210218151335-3861ecd89595

	// Using private fork of controller-tools. See commit msg for more context
	// as to why we are using a private fork.
	sigs.k8s.io/controller-tools => github.com/christarazi/controller-tools v0.3.1-0.20200911184030-7e668c1fb4c2
	// Fork until
	// https://github.com/kubernetes-sigs/structured-merge-diff/issues/172 is fixed.
	sigs.k8s.io/structured-merge-diff/v4 => github.com/christarazi/structured-merge-diff/v4 v4.0.2-0.20200917183246-1cc601931628
)

require (
	github.com/cilium/cilium v1.9.7
	github.com/cilium/hubble v0.7.1
	github.com/cilium/workerpool v1.0.0
	github.com/cloudflare/cfssl v1.5.0
	github.com/go-openapi/strfmt v0.19.11
	github.com/golang/protobuf v1.4.3
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/gordonklaus/ineffassign v0.0.0-20200809085317-e36bfde3bb78
	github.com/hashicorp/go-multierror v1.1.1
	github.com/mholt/archiver/v3 v3.5.0
	github.com/spf13/cobra v1.1.1
	golang.org/x/lint v0.0.0-20200302205851-738671d3881b
	google.golang.org/grpc v1.34.0
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c
	honnef.co/go/tools v0.1.2
	k8s.io/api v0.19.10
	k8s.io/apimachinery v0.19.10
	k8s.io/cli-runtime v0.19.10
	k8s.io/client-go v0.19.10
	k8s.io/klog/v2 v2.2.0
)
