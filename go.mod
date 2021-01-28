module github.com/cilium/cilium

go 1.15

// direct dependencies
require (
	github.com/Azure/azure-sdk-for-go v50.0.0+incompatible
	github.com/Azure/go-autorest/autorest v0.11.16
	github.com/Azure/go-autorest/autorest/adal v0.9.10
	github.com/Azure/go-autorest/autorest/azure/auth v0.5.5
	github.com/Azure/go-autorest/autorest/to v0.4.0
	github.com/Azure/go-autorest/autorest/validation v0.2.0 // indirect
	github.com/asaskevich/govalidator v0.0.0-20200907205600-7a23bdc65eef
	github.com/aws/aws-sdk-go-v2 v0.31.0
	github.com/aws/aws-sdk-go-v2/config v0.4.0
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v0.1.0
	github.com/aws/aws-sdk-go-v2/service/ec2 v0.31.0
	github.com/aws/smithy-go v0.5.0
	github.com/blang/semver/v4 v4.0.0
	github.com/cilium/customvet v0.0.0-20201209211516-9852765c1ac4
	github.com/cilium/deepequal-gen v0.0.0-20200406125435-ad6a9003139e
	github.com/cilium/ebpf v0.3.0
	github.com/cilium/ipam v0.0.0-20201106170308-4184bc4bf9d6
	github.com/cilium/proxy v0.0.0-20210121022617-de819bff23ee
	github.com/cncf/udpa/go v0.0.0-20201211205326-cc1b757b3edd // indirect
	github.com/containernetworking/cni v0.8.0
	github.com/containernetworking/plugins v0.9.0
	github.com/davecgh/go-spew v1.1.1
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v0.7.3-0.20190327010347-be7ac8be2ae0
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/libnetwork v0.0.0-20190128195551-d8d4c8cf03d7
	github.com/fsnotify/fsnotify v1.4.10-0.20200417215612-7f4cf4dd2b52
	github.com/go-bindata/go-bindata/v3 v3.1.3
	github.com/go-openapi/errors v0.19.9
	github.com/go-openapi/loads v0.20.0
	github.com/go-openapi/runtime v0.19.24
	github.com/go-openapi/spec v0.20.0
	github.com/go-openapi/strfmt v0.20.0
	github.com/go-openapi/swag v0.19.12
	github.com/go-openapi/validate v0.20.0
	github.com/gogo/protobuf v1.3.2
	github.com/golang/protobuf v1.4.3
	github.com/google/go-cmp v0.5.4
	github.com/google/gopacket v1.1.19
	github.com/google/gops v0.3.14
	github.com/google/renameio v1.0.0
	github.com/google/uuid v1.1.4
	github.com/gorilla/mux v1.8.0
	github.com/hashicorp/consul/api v1.3.0
	github.com/hashicorp/go-immutable-radix v1.3.0
	github.com/hashicorp/golang-lru v0.5.4
	// must be bound to this old version not to break libnetwork
	github.com/ishidawataru/sctp v0.0.0-20180213033435-07191f837fed // indirect
	github.com/jeremywohl/flatten v1.0.1
	github.com/kevinburke/ssh_config v0.0.0-20201106050909-4977a11b4351
	github.com/kr/pretty v0.2.1
	github.com/mattn/go-shellwords v1.0.10
	github.com/miekg/dns v1.0.14
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/onsi/ginkgo v1.12.1
	github.com/onsi/gomega v1.10.3
	github.com/opencontainers/go-digest v1.0.0-rc1 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/optiopay/kafka v0.0.0-00010101000000-000000000000
	github.com/pmezard/go-difflib v1.0.0
	github.com/prometheus/client_golang v1.9.0
	github.com/prometheus/client_model v0.2.1-0.20200623203004-60555c9708c7
	github.com/russross/blackfriday/v2 v2.1.0
	github.com/sasha-s/go-deadlock v0.2.1-0.20190427202633-1595213edefa
	github.com/servak/go-fastping v0.0.0-20160802140958-5718d12e20a0
	github.com/shirou/gopsutil v2.20.4+incompatible
	github.com/sirupsen/logrus v1.7.0
	github.com/spf13/cobra v1.1.1
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.6.1
	github.com/vishvananda/netlink v1.1.1-0.20201231054507-6ffafa9fc19b
	github.com/vishvananda/netns v0.0.0-20201230012202-c4f3ca719c73
	go.etcd.io/etcd v0.5.0-alpha.5.0.20201125193152-8a03d2e9614b
	go.uber.org/goleak v1.1.10
	golang.org/x/crypto v0.0.0-20201217014255-9d1352758620
	golang.org/x/net v0.0.0-20201224014010-6772e930b67b
	golang.org/x/sync v0.0.0-20201207232520-09787c993a3a
	golang.org/x/sys v0.0.0-20210110051926-789bb1bd4061
	golang.org/x/time v0.0.0-20200630173020-3af7569d3a1e
	golang.org/x/tools v0.0.0-20210108195828-e2f9c7f1fc8e
	google.golang.org/genproto v0.0.0-20210111234610-22ae2b108f89
	google.golang.org/grpc v1.29.1
	google.golang.org/protobuf v1.25.0
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c
	gopkg.in/ini.v1 v1.62.0
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/api v0.20.1
	k8s.io/apiextensions-apiserver v0.20.1
	k8s.io/apimachinery v0.20.1
	k8s.io/client-go v0.20.1
	k8s.io/code-generator v0.20.1
	k8s.io/klog/v2 v2.4.0
	k8s.io/kube-openapi v0.0.0-20201113171705-d219536bb9fd
	// We specify the controller-tools version here to be the version of the
	// fork below, so that when we generate CRDs, the generated CRD contains
	// version number of the tool. We want the version number to match up with
	// the fork, even though this specific version doesn't exist in upstream
	// controller-tools.
	sigs.k8s.io/controller-tools v0.3.1-0.20200716001835-4a903ddb7005
	// Must be bound to at least this commit until a new release is made with
	// https://github.com/kubernetes-sigs/structured-merge-diff/pull/173
	// included.
	sigs.k8s.io/structured-merge-diff/v4 v4.0.3-0.20201124161302-9f9c77085dec // indirect
	sigs.k8s.io/yaml v1.2.0
)

replace (
	github.com/miekg/dns => github.com/cilium/dns v1.1.4-0.20190417235132-8e25ec9a0ff3
	github.com/optiopay/kafka => github.com/cilium/kafka v0.0.0-20180809090225-01ce283b732b

	// Using private fork of controller-tools. See commit msg for more context
	// as to why we are using a private fork.
	sigs.k8s.io/controller-tools => github.com/christarazi/controller-tools v0.3.1-0.20200911184030-7e668c1fb4c2
)
