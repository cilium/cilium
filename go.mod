module github.com/cilium/cilium

go 1.17

// direct dependencies
require (
	github.com/Azure/azure-sdk-for-go v54.0.0+incompatible
	github.com/Azure/go-autorest/autorest v0.11.17
	github.com/Azure/go-autorest/autorest/adal v0.9.13
	github.com/Azure/go-autorest/autorest/azure/auth v0.5.7
	github.com/Azure/go-autorest/autorest/to v0.4.0
	github.com/Azure/go-autorest/autorest/validation v0.2.0 // indirect
	github.com/aliyun/alibaba-cloud-sdk-go v1.61.1214
	github.com/asaskevich/govalidator v0.0.0-20200907205600-7a23bdc65eef
	github.com/aws/aws-sdk-go-v2 v1.9.0
	github.com/aws/aws-sdk-go-v2/config v1.6.0
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.4.0
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.16.0
	github.com/aws/smithy-go v1.8.0
	github.com/blang/semver/v4 v4.0.0
	github.com/cilium/customvet v0.0.0-20201209211516-9852765c1ac4
	github.com/cilium/deepequal-gen v0.0.0-20200406125435-ad6a9003139e
	github.com/cilium/ebpf v0.5.1-0.20210421150058-a4ee356536f3
	github.com/cilium/ipam v0.0.0-20201106170308-4184bc4bf9d6
	github.com/cilium/proxy v0.0.0-20210511221533-82a70d56bf32
	github.com/cncf/udpa/go v0.0.0-20201211205326-cc1b757b3edd // indirect
	github.com/containernetworking/cni v0.8.1
	github.com/containernetworking/plugins v0.9.1
	github.com/davecgh/go-spew v1.1.1
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v0.7.3-0.20190327010347-be7ac8be2ae0
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/libnetwork v0.0.0-20190128195551-d8d4c8cf03d7
	github.com/fsnotify/fsnotify v1.4.10-0.20200417215612-7f4cf4dd2b52
	github.com/go-openapi/errors v0.20.1
	github.com/go-openapi/loads v0.20.2
	github.com/go-openapi/runtime v0.19.30
	github.com/go-openapi/spec v0.20.3
	github.com/go-openapi/strfmt v0.20.0
	github.com/go-openapi/swag v0.19.15
	github.com/go-openapi/validate v0.20.2
	github.com/gogo/protobuf v1.3.2
	github.com/golang/groupcache v0.0.0-20200121045136-8c9f03a8e57e
	github.com/golang/protobuf v1.5.2
	github.com/google/go-cmp v0.5.6
	github.com/google/gopacket v1.1.19
	github.com/google/gops v0.3.18
	github.com/google/renameio v1.0.1
	github.com/google/uuid v1.2.0
	github.com/gorilla/mux v1.8.0
	github.com/hashicorp/consul/api v1.9.1
	github.com/hashicorp/go-immutable-radix v1.3.0
	github.com/hashicorp/golang-lru v0.5.4
	// must be bound to this old version not to break libnetwork
	github.com/ishidawataru/sctp v0.0.0-20180213033435-07191f837fed // indirect
	github.com/jeremywohl/flatten v1.0.1
	github.com/kevinburke/ssh_config v0.0.0-20201106050909-4977a11b4351
	github.com/kr/pretty v0.3.0
	github.com/mattn/go-shellwords v1.0.12
	github.com/miekg/dns v1.1.26
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/onsi/ginkgo v1.12.1
	github.com/onsi/gomega v1.10.5
	github.com/opencontainers/go-digest v1.0.0-rc1 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/optiopay/kafka v0.0.0-20171218140449-a1e0071f1ce8
	github.com/pmezard/go-difflib v1.0.0
	github.com/prometheus/client_golang v1.11.0
	github.com/prometheus/client_model v0.2.1-0.20200623203004-60555c9708c7
	github.com/prometheus/procfs v0.6.0
	github.com/russross/blackfriday/v2 v2.1.0
	github.com/sasha-s/go-deadlock v0.2.1-0.20190427202633-1595213edefa
	github.com/servak/go-fastping v0.0.0-20160802140958-5718d12e20a0
	github.com/shirou/gopsutil/v3 v3.21.7
	github.com/sirupsen/logrus v1.7.0
	github.com/spf13/cobra v1.1.3
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.8.0
	github.com/stretchr/testify v1.7.0
	github.com/vishvananda/netlink v1.1.1-0.20210510164352-d17758a128bf
	github.com/vishvananda/netns v0.0.0-20201230012202-c4f3ca719c73
	go.etcd.io/etcd/api/v3 v3.5.0
	go.etcd.io/etcd/client/pkg/v3 v3.5.0
	go.etcd.io/etcd/client/v3 v3.5.0
	go.mongodb.org/mongo-driver v1.5.1 // indirect
	go.uber.org/goleak v1.1.10
	go.universe.tf/metallb v0.10.0
	golang.org/x/crypto v0.0.0-20210503195802-e9a32991a82e
	golang.org/x/net v0.0.0-20210504132125-bbd867fde50d
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/sys v0.0.0-20210823070655-63515b42dcdf
	golang.org/x/time v0.0.0-20210220033141-f8bda1e9f3ba
	golang.org/x/tools v0.1.2
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20210506160403-92e472f520a5
	google.golang.org/genproto v0.0.0-20210602131652-f16073e35f0c
	google.golang.org/grpc v1.39.0
	google.golang.org/protobuf v1.27.1
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c
	gopkg.in/ini.v1 v1.62.0
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/api v0.21.3
	k8s.io/apiextensions-apiserver v0.21.3
	k8s.io/apimachinery v0.21.3
	k8s.io/client-go v0.21.3
	k8s.io/code-generator v0.21.3
	k8s.io/klog/v2 v2.8.0
	k8s.io/kube-openapi v0.0.0-20210305001622-591a79e4bda7
	// We specify the controller-tools version here to be the version of the
	// fork below, so that when we generate CRDs, the generated CRD contains
	// version number of the tool. We want the version number to match up with
	// the fork, even though this specific version doesn't exist in upstream
	// controller-tools.
	sigs.k8s.io/controller-tools v0.3.1-0.20200716001835-4a903ddb7005
	sigs.k8s.io/yaml v1.2.0
)

require (
	github.com/Azure/go-autorest v14.2.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest/azure/cli v0.4.2 // indirect
	github.com/Azure/go-autorest/autorest/date v0.3.0 // indirect
	github.com/Azure/go-autorest/logger v0.2.1 // indirect
	github.com/Azure/go-autorest/tracing v0.6.0 // indirect
	github.com/Microsoft/go-winio v0.4.11 // indirect
	github.com/PuerkitoBio/purell v1.1.1 // indirect
	github.com/PuerkitoBio/urlesc v0.0.0-20170810143723-de5bf2ad4578 // indirect
	github.com/StackExchange/wmi v1.2.1 // indirect
	github.com/armon/go-metrics v0.0.0-20180917152333-f0300d1749da // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.3.2 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.2.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.3.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.3.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.6.1 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/census-instrumentation/opencensus-proto v0.3.0 // indirect
	github.com/cespare/xxhash/v2 v2.1.1 // indirect
	github.com/coreos/go-semver v0.3.0 // indirect
	github.com/coreos/go-systemd/v22 v22.3.2 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.0 // indirect
	github.com/dimchansky/utfbom v1.1.1 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/emicklei/go-restful v2.9.5+incompatible // indirect
	github.com/envoyproxy/protoc-gen-validate v0.4.2-0.20210105193028-872b28c45782 // indirect
	github.com/evanphx/json-patch v4.9.0+incompatible // indirect
	github.com/fatih/color v1.9.0 // indirect
	github.com/form3tech-oss/jwt-go v3.2.2+incompatible // indirect
	github.com/go-kit/kit v0.9.0 // indirect
	github.com/go-logfmt/logfmt v0.5.0 // indirect
	github.com/go-logr/logr v0.4.0 // indirect
	github.com/go-ole/go-ole v1.2.5 // indirect
	github.com/go-openapi/analysis v0.20.0 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.19.5 // indirect
	github.com/go-stack/stack v1.8.0 // indirect
	github.com/gobuffalo/flect v0.2.0 // indirect
	github.com/golang/snappy v0.0.1 // indirect
	github.com/google/gofuzz v1.1.0 // indirect
	github.com/googleapis/gnostic v0.4.1 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.1 // indirect
	github.com/hashicorp/go-hclog v0.12.0 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/hashicorp/serf v0.9.5 // indirect
	github.com/imdario/mergo v0.3.5 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/josharian/native v0.0.0-20200817173448-b6b71def0850 // indirect
	github.com/json-iterator/go v1.1.11 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/magiconair/properties v1.8.5 // indirect
	github.com/mailru/easyjson v0.7.6 // indirect
	github.com/mattn/go-colorable v0.1.6 // indirect
	github.com/mattn/go-isatty v0.0.12 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.2-0.20181231171920-c182affec369 // indirect
	github.com/mdlayher/arp v0.0.0-20191213142603-f72070a231fc // indirect
	github.com/mdlayher/ethernet v0.0.0-20190606142754-0394541c37b7 // indirect
	github.com/mdlayher/genetlink v1.0.0 // indirect
	github.com/mdlayher/ndp v0.0.0-20200602162440-17ab9e3e5567 // indirect
	github.com/mdlayher/netlink v1.4.0 // indirect
	github.com/mdlayher/raw v0.0.0-20191009151244-50f2db8cc065 // indirect
	github.com/mikioh/ipaddr v0.0.0-20190404000644-d465c8ab6721 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/mapstructure v1.4.1 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.1 // indirect
	github.com/nxadm/tail v1.4.4 // indirect
	github.com/opentracing/opentracing-go v1.2.0 // indirect
	github.com/pelletier/go-toml v1.9.3 // indirect
	github.com/petermattis/goid v0.0.0-20180202154549-b0b1615b78e5 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/common v0.26.0 // indirect
	github.com/rogpeppe/go-internal v1.6.1 // indirect
	github.com/spf13/afero v1.6.0 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/subosito/gotenv v1.2.0 // indirect
	github.com/tklauser/go-sysconf v0.3.7 // indirect
	github.com/tklauser/numcpus v0.2.3 // indirect
	gitlab.com/golang-commonmark/puny v0.0.0-20191124015043-9f83538fa04f // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	go.uber.org/zap v1.17.0 // indirect
	golang.org/x/lint v0.0.0-20210508222113-6edffad5e616 // indirect
	golang.org/x/mod v0.4.2 // indirect
	golang.org/x/oauth2 v0.0.0-20210402161424-2e8d93401602 // indirect
	golang.org/x/term v0.0.0-20210220032956-6a3ed077a48d // indirect
	golang.org/x/text v0.3.6 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	golang.zx2c4.com/wireguard v0.0.0-20210427022245-097af6e1351b // indirect
	google.golang.org/appengine v1.6.7 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
	k8s.io/gengo v0.0.0-20201214224949-b6c5ce23f027 // indirect
	k8s.io/klog v1.0.0 // indirect
	k8s.io/utils v0.0.0-20201110183641-67b214c5f920 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.1.2 // indirect
)

replace (
	github.com/miekg/dns => github.com/cilium/dns v1.1.4-0.20190417235132-8e25ec9a0ff3
	github.com/optiopay/kafka => github.com/cilium/kafka v0.0.0-20180809090225-01ce283b732b

	go.universe.tf/metallb => github.com/cilium/metallb v0.1.1-0.20210609003938-62cef75b3c9f

	// Using private fork of controller-tools. See commit msg for more context
	// as to why we are using a private fork.
	sigs.k8s.io/controller-tools => github.com/christarazi/controller-tools v0.3.1-0.20200911184030-7e668c1fb4c2
)
