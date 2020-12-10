module github.com/cilium/cilium

go 1.15

// direct dependencies
require (
	github.com/Azure/azure-sdk-for-go v44.2.0+incompatible
	github.com/Azure/go-autorest/autorest v0.11.2
	github.com/Azure/go-autorest/autorest/adal v0.9.5
	github.com/Azure/go-autorest/autorest/azure/auth v0.5.0
	github.com/Azure/go-autorest/autorest/to v0.4.0
	github.com/Azure/go-autorest/autorest/validation v0.2.0 // indirect
	github.com/asaskevich/govalidator v0.0.0-20200428143746-21a406dcc535
	github.com/aws/aws-sdk-go-v2 v0.24.0
	github.com/blang/semver/v4 v4.0.0
	github.com/cilium/arping v1.0.1-0.20201126164629-5142c9527af5
	github.com/cilium/deepequal-gen v0.0.0-20200406125435-ad6a9003139e
	github.com/cilium/ebpf v0.3.0
	github.com/cilium/ipam v0.0.0-20201020084809-76717fcdb3a2
	github.com/cilium/proxy v0.0.0-20200728092031-595bb722a4ab
	github.com/containernetworking/cni v0.7.1
	github.com/containernetworking/plugins v0.8.2
	github.com/davecgh/go-spew v1.1.1
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v0.7.3-0.20190327010347-be7ac8be2ae0
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/libnetwork v0.0.0-20190128195551-d8d4c8cf03d7
	github.com/fsnotify/fsnotify v1.4.10-0.20200417215612-7f4cf4dd2b52
	github.com/go-bindata/go-bindata/v3 v3.1.3
	github.com/go-openapi/errors v0.19.6
	github.com/go-openapi/loads v0.19.5
	github.com/go-openapi/runtime v0.19.20
	github.com/go-openapi/spec v0.19.9
	github.com/go-openapi/strfmt v0.19.5
	github.com/go-openapi/swag v0.19.9
	github.com/go-openapi/validate v0.19.10
	github.com/gogo/protobuf v1.3.1
	github.com/golang/protobuf v1.4.3
	github.com/google/go-cmp v0.5.2
	github.com/google/gopacket v1.1.17
	github.com/google/gops v0.3.14
	github.com/google/renameio v0.1.0
	github.com/google/uuid v1.1.2
	github.com/gorilla/mux v1.7.0
	github.com/hashicorp/consul/api v1.2.0
	github.com/hashicorp/go-immutable-radix v1.1.0
	github.com/hashicorp/golang-lru v0.5.1
	// must be bound to this old version not to break libnetwork
	github.com/ishidawataru/sctp v0.0.0-20180213033435-07191f837fed // indirect
	github.com/jeremywohl/flatten v1.0.1
	github.com/kevinburke/ssh_config v0.0.0-20190725054713-01f96b0aa0cd
	github.com/kr/pretty v0.2.0
	github.com/mattn/go-shellwords v1.0.5
	github.com/miekg/dns v1.0.14
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/onsi/ginkgo v1.11.0
	github.com/onsi/gomega v1.8.1
	github.com/opencontainers/go-digest v1.0.0-rc1 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/optiopay/kafka v0.0.0-00010101000000-000000000000
	github.com/pmezard/go-difflib v1.0.0
	github.com/prometheus/client_golang v1.7.1
	github.com/prometheus/client_model v0.2.0
	github.com/russross/blackfriday/v2 v2.1.0
	github.com/sasha-s/go-deadlock v0.2.1-0.20190427202633-1595213edefa
	github.com/servak/go-fastping v0.0.0-20160802140958-5718d12e20a0
	github.com/shirou/gopsutil v2.20.4+incompatible
	github.com/sirupsen/logrus v1.6.0
	github.com/spf13/cobra v1.1.1
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.7.0
	github.com/stretchr/testify v1.6.1
	github.com/vishvananda/netlink v1.1.1-0.20200603190939-5a869a71f0cb
	github.com/vishvananda/netns v0.0.0-20191106174202-0a2b9b5464df
	go.etcd.io/etcd v0.5.0-alpha.5.0.20201125193152-8a03d2e9614b
	go.uber.org/goleak v1.0.0
	golang.org/x/crypto v0.0.0-20201002170205-7f63de1d35b0
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b
	golang.org/x/sync v0.0.0-20190911185100-cd5d95a43a6e
	golang.org/x/sys v0.0.0-20201207223542-d4d67f95c62d
	golang.org/x/time v0.0.0-20200630173020-3af7569d3a1e
	golang.org/x/tools v0.0.0-20200616195046-dc31b401abb5
	google.golang.org/genproto v0.0.0-20201110150050-8816d57aaa9a
	google.golang.org/grpc v1.29.1
	google.golang.org/protobuf v1.25.0
	gopkg.in/check.v1 v1.0.0-20200227125254-8fa46927fb4f
	gopkg.in/ini.v1 v1.62.0
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/api v0.20.0
	k8s.io/apiextensions-apiserver v0.20.0
	k8s.io/apimachinery v0.20.0
	k8s.io/client-go v0.20.0
	k8s.io/code-generator v0.20.0
	k8s.io/klog/v2 v2.4.0
	k8s.io/kube-openapi v0.0.0-20201113171705-d219536bb9fd
	// We specify the controller-tools version here to be the version of the
	// fork below, so that when we generate CRDs, the generated CRD contains
	// version number of the tool. We want the version number to match up with
	// the fork, even though this specific version doesn't exist in upstream
	// controller-tools.
	sigs.k8s.io/controller-tools v0.3.1-0.20200716001835-4a903ddb7005
	sigs.k8s.io/yaml v1.2.0
)

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
