module github.com/cilium/cilium

go 1.14

// direct dependencies
require (
	github.com/Azure/azure-sdk-for-go v38.0.0+incompatible
	github.com/Azure/go-autorest/autorest/azure/auth v0.4.2
	github.com/Azure/go-autorest/autorest/to v0.3.0
	github.com/Azure/go-autorest/autorest/validation v0.2.0 // indirect
	github.com/asaskevich/govalidator v0.0.0-20200108200545-475eaeb16496
	github.com/aws/aws-sdk-go-v2 v0.18.0
	github.com/blang/semver v3.5.0+incompatible
	github.com/c9s/goprocinfo v0.0.0-20190309065803-0b2ad9ac246b
	github.com/cilium/deepequal-gen v0.0.0-20200406125435-ad6a9003139e
	github.com/cilium/ebpf v0.0.0-20200612163523-d7bee28bad96
	github.com/cilium/ipam v0.0.0-20201020084809-76717fcdb3a2
	github.com/cilium/proxy v0.0.0-20210511221533-82a70d56bf32
	github.com/containernetworking/cni v0.7.1
	github.com/containernetworking/plugins v0.8.2
	github.com/davecgh/go-spew v1.1.1
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v0.7.3-0.20190327010347-be7ac8be2ae0
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/libnetwork v0.0.0-20190128195551-d8d4c8cf03d7
	github.com/envoyproxy/protoc-gen-validate v0.4.2-0.20210105193028-872b28c45782
	github.com/fsnotify/fsnotify v1.4.10-0.20200417215612-7f4cf4dd2b52
	github.com/go-openapi/errors v0.19.3
	github.com/go-openapi/loads v0.19.5
	github.com/go-openapi/runtime v0.19.4
	github.com/go-openapi/spec v0.19.6
	github.com/go-openapi/strfmt v0.19.4
	github.com/go-openapi/swag v0.19.7
	github.com/go-openapi/validate v0.19.5
	github.com/gogo/protobuf v1.3.2
	github.com/golang/protobuf v1.4.3
	github.com/google/go-cmp v0.5.2
	github.com/google/gofuzz v1.1.0
	github.com/google/gopacket v1.1.17
	github.com/google/gops v0.3.14
	github.com/google/renameio v0.1.0
	github.com/gorilla/mux v1.7.0
	github.com/hashicorp/consul/api v1.2.0
	github.com/hashicorp/go-immutable-radix v1.1.0
	github.com/hashicorp/golang-lru v0.5.1
	// must be bound to this old version not to break libnetwork
	github.com/ishidawataru/sctp v0.0.0-20180213033435-07191f837fed // indirect
	github.com/kevinburke/ssh_config v0.0.0-20190725054713-01f96b0aa0cd
	github.com/kr/pretty v0.1.0
	github.com/mattn/go-shellwords v1.0.5
	github.com/miekg/dns v1.0.14
	github.com/mitchellh/protoc-gen-go-json v0.0.0-20200113165135-fd297ce346f1
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/onsi/ginkgo v1.11.0
	github.com/onsi/gomega v1.7.0
	github.com/opencontainers/go-digest v1.0.0-rc1 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/optiopay/kafka v0.0.0-00010101000000-000000000000
	github.com/pborman/uuid v1.2.0
	github.com/pkg/errors v0.9.1
	github.com/pmezard/go-difflib v1.0.0
	github.com/prometheus/client_golang v1.2.0
	github.com/prometheus/client_model v0.2.1-0.20200623203004-60555c9708c7
	github.com/russross/blackfriday v1.5.2
	github.com/sasha-s/go-deadlock v0.2.1-0.20190427202633-1595213edefa
	github.com/servak/go-fastping v0.0.0-20160802140958-5718d12e20a0
	github.com/shirou/gopsutil v2.20.4+incompatible
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/cobra v1.0.0
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.6.1
	github.com/stretchr/testify v1.6.1
	github.com/vishvananda/netlink v1.1.1-0.20210304225204-ec93726159ae
	github.com/vishvananda/netns v0.0.0-20201230012202-c4f3ca719c73
	go.etcd.io/etcd v0.5.0-alpha.5.0.20201125193152-8a03d2e9614b
	go.mongodb.org/mongo-driver v1.5.1 // indirect
	go.uber.org/goleak v1.0.0
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	golang.org/x/net v0.0.0-20201110031124-69a78807bb2b
	golang.org/x/sync v0.0.0-20201020160332-67f06af15bc9
	golang.org/x/sys v0.0.0-20201231184435-2d18734c6014
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0
	golang.org/x/tools v0.0.0-20210106214847-113979e3529a
	google.golang.org/genproto v0.0.0-20210126160654-44e461bb6506
	google.golang.org/grpc v1.29.1
	google.golang.org/protobuf v1.25.0
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/yaml.v2 v2.2.8
	k8s.io/api v0.18.19
	k8s.io/apiextensions-apiserver v0.18.19
	k8s.io/apimachinery v0.18.19
	k8s.io/client-go v0.18.19
	k8s.io/code-generator v0.18.19
	k8s.io/klog v1.0.0
	sigs.k8s.io/yaml v1.2.0
)

replace (
	github.com/miekg/dns => github.com/cilium/dns v1.1.4-0.20190417235132-8e25ec9a0ff3
	github.com/optiopay/kafka => github.com/cilium/kafka v0.0.0-20180809090225-01ce283b732b
	// Using cilium/netlink until XFRM patches merged upstream
	github.com/vishvananda/netlink => github.com/cilium/netlink v0.0.0-20210223023818-d826f2a4c934
	k8s.io/client-go => github.com/cilium/client-go v0.0.0-20210417023617-aeb4c6f1b557
)
