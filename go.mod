// This is a generated file. Do not edit directly.
// Run contrib/go-mod/pin-dependency.sh to change pinned dependency versions.
// Run contrib/go-mod/update-vendor.sh to update go.mod files and the vendor directory.

module github.com/cilium/cilium

go 1.13

// direct dependencies
require (
	github.com/armon/go-metrics v0.0.0-20190430140413-ec5e00d3c878 // indirect
	github.com/asaskevich/govalidator v0.0.0-20190424111038-f61b66f89f4a
	github.com/aws/aws-sdk-go-v2 v0.18.0
	github.com/blang/semver v3.5.0+incompatible
	github.com/c9s/goprocinfo v0.0.0-20190309065803-0b2ad9ac246b
	github.com/census-instrumentation/opencensus-proto v0.2.1 // indirect
	github.com/cilium/arping v1.0.1-0.20190728065459-c5eaf8d7a710
	github.com/cilium/ebpf v0.0.0-20191113100448-d9fb101ca1fb
	github.com/cilium/proxy v0.0.0-20191113190709-4c7b379792e6
	github.com/containernetworking/cni v0.7.1
	github.com/containernetworking/plugins v0.8.2
	github.com/davecgh/go-spew v1.1.1
	github.com/docker/docker v0.7.3-0.20190327010347-be7ac8be2ae0
	github.com/docker/libnetwork v0.8.0-dev.2.0.20190624125649-f0e46a78ea34
	github.com/envoyproxy/protoc-gen-validate v0.1.0 // indirect
	github.com/fatih/color v1.7.0
	github.com/go-openapi/errors v0.19.2
	github.com/go-openapi/loads v0.19.4
	github.com/go-openapi/runtime v0.19.4
	github.com/go-openapi/spec v0.19.3
	github.com/go-openapi/strfmt v0.19.3
	github.com/go-openapi/swag v0.19.5
	github.com/go-openapi/validate v0.19.5
	github.com/golang/protobuf v1.3.2
	github.com/golang/snappy v0.0.1 // indirect
	github.com/google/go-cmp v0.3.1
	github.com/google/gopacket v1.1.17
	github.com/google/gops v0.3.6
	github.com/googleapis/gnostic v0.2.0 // indirect
	github.com/gorilla/mux v1.7.0
	github.com/hashicorp/consul/api v1.2.0
	github.com/hashicorp/go-immutable-radix v1.1.0
	github.com/hashicorp/go-msgpack v0.5.5 // indirect
	github.com/hashicorp/go-rootcerts v1.0.1 // indirect
	github.com/hashicorp/memberlist v0.1.5 // indirect
	github.com/hashicorp/serf v0.8.5 // indirect
	github.com/imdario/mergo v0.3.6 // indirect
	github.com/ishidawataru/sctp v0.0.0-20180213033435-07191f837fed // indirect
	github.com/jessevdk/go-flags v1.4.0
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0 // indirect
	github.com/kevinburke/ssh_config v0.0.0-20190725054713-01f96b0aa0cd
	github.com/kr/pretty v0.1.0
	github.com/mattn/go-shellwords v1.0.5
	github.com/miekg/dns v1.1.4
	github.com/onsi/ginkgo v1.10.1
	github.com/onsi/gomega v1.7.0
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7
	github.com/optiopay/kafka v0.0.0-20180809090225-01ce283b732b
	github.com/pborman/uuid v1.2.0
	github.com/petermattis/goid v0.0.0-20180202154549-b0b1615b78e5 // indirect
	github.com/pkg/errors v0.8.1
	github.com/pmezard/go-difflib v1.0.0
	github.com/prometheus/client_golang v1.2.0
	github.com/prometheus/client_model v0.0.0-20190812154241-14fe0d1b01d4
	github.com/russross/blackfriday v1.5.2
	github.com/sasha-s/go-deadlock v0.2.0
	github.com/servak/go-fastping v0.0.0-20160802140958-5718d12e20a0
	github.com/shirou/gopsutil v0.0.0-20181107111621-48177ef5f880
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/cobra v0.0.5
	github.com/spf13/pflag v1.0.5
	github.com/spf13/viper v1.6.1
	github.com/vishvananda/netlink v1.0.1-0.20191113183427-d71301a47b60
	go.etcd.io/etcd v0.5.0-alpha.5.0.20191023171146-3cf2f69b5738
	golang.org/x/crypto v0.0.0-20200220183623-bac4c82f6975
	golang.org/x/net v0.0.0-20191004110552-13f9640d40b9
	golang.org/x/sync v0.0.0-20190911185100-cd5d95a43a6e
	golang.org/x/sys v0.0.0-20191022100944-742c48ecaeb7
	golang.org/x/time v0.0.0-20190308202827-9d24e82272b4
	google.golang.org/genproto v0.0.0-20190502173448-54afdca5d873
	google.golang.org/grpc v1.23.1
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127
	gopkg.in/fsnotify.v1 v1.4.7
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/yaml.v2 v2.2.8
	k8s.io/api v0.17.4
	k8s.io/apiextensions-apiserver v0.0.0
	k8s.io/apimachinery v0.17.4
	k8s.io/client-go v8.0.0+incompatible
	k8s.io/code-generator v0.0.0
	k8s.io/klog v1.0.0
	k8s.io/kubernetes v1.17.4
	sigs.k8s.io/yaml v1.1.0
)

// direct + indirect dependencies

replace (
	bitbucket.org/bertimus9/systemstat => bitbucket.org/bertimus9/systemstat v0.0.0-20180207000608-0eeff89b0690
	cloud.google.com/go => cloud.google.com/go v0.38.0
	dmitri.shuralyov.com/gpu/mtl => dmitri.shuralyov.com/gpu/mtl v0.0.0-20190408044501-666a987793e9
	github.com/Azure/azure-sdk-for-go => github.com/Azure/azure-sdk-for-go v35.0.0+incompatible
	github.com/Azure/go-ansiterm => github.com/Azure/go-ansiterm v0.0.0-20170929234023-d6e3b3328b78
	github.com/Azure/go-autorest => github.com/Azure/go-autorest v10.15.3+incompatible
	github.com/Azure/go-autorest/autorest => github.com/Azure/go-autorest/autorest v0.9.0
	github.com/Azure/go-autorest/autorest/adal => github.com/Azure/go-autorest/autorest/adal v0.5.0
	github.com/Azure/go-autorest/autorest/date => github.com/Azure/go-autorest/autorest/date v0.1.0
	github.com/Azure/go-autorest/autorest/mocks => github.com/Azure/go-autorest/autorest/mocks v0.2.0
	github.com/Azure/go-autorest/autorest/to => github.com/Azure/go-autorest/autorest/to v0.2.0
	github.com/Azure/go-autorest/autorest/validation => github.com/Azure/go-autorest/autorest/validation v0.1.0
	github.com/Azure/go-autorest/logger => github.com/Azure/go-autorest/logger v0.1.0
	github.com/Azure/go-autorest/tracing => github.com/Azure/go-autorest/tracing v0.5.0
	github.com/BurntSushi/toml => github.com/BurntSushi/toml v0.3.1
	github.com/BurntSushi/xgb => github.com/BurntSushi/xgb v0.0.0-20160522181843-27f122750802
	github.com/DataDog/datadog-go => github.com/DataDog/datadog-go v2.2.0+incompatible
	github.com/GoogleCloudPlatform/k8s-cloud-provider => github.com/GoogleCloudPlatform/k8s-cloud-provider v0.0.0-20190822182118-27a4ced34534
	github.com/JeffAshton/win_pdh => github.com/JeffAshton/win_pdh v0.0.0-20161109143554-76bb4ee9f0ab
	github.com/Jeffail/gabs => github.com/Jeffail/gabs v1.1.0
	github.com/MakeNowJust/heredoc => github.com/MakeNowJust/heredoc v0.0.0-20170808103936-bb23615498cd
	github.com/Microsoft/go-winio => github.com/Microsoft/go-winio v0.4.11
	github.com/Microsoft/hcsshim => github.com/Microsoft/hcsshim v0.0.0-20190417211021-672e52e9209d
	github.com/NYTimes/gziphandler => github.com/NYTimes/gziphandler v0.0.0-20170623195520-56545f4a5d46
	github.com/Nvveen/Gotty => github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5
	github.com/OpenPeeDeeP/depguard => github.com/OpenPeeDeeP/depguard v1.0.1
	github.com/PuerkitoBio/purell => github.com/PuerkitoBio/purell v1.1.1
	github.com/PuerkitoBio/urlesc => github.com/PuerkitoBio/urlesc v0.0.0-20170810143723-de5bf2ad4578
	github.com/Rican7/retry => github.com/Rican7/retry v0.1.0
	github.com/SAP/go-hdb => github.com/SAP/go-hdb v0.12.0
	github.com/SermoDigital/jose => github.com/SermoDigital/jose v0.0.0-20180104203859-803625baeddc
	github.com/StackExchange/wmi => github.com/StackExchange/wmi v0.0.0-20180116203802-5d049714c4a6
	github.com/abdullin/seq => github.com/abdullin/seq v0.0.0-20160510034733-d5467c17e7af
	github.com/agnivade/levenshtein => github.com/agnivade/levenshtein v1.0.1
	github.com/alecthomas/template => github.com/alecthomas/template v0.0.0-20160405071501-a0175ee3bccc
	github.com/alecthomas/units => github.com/alecthomas/units v0.0.0-20151022065526-2efee857e7cf
	github.com/alexflint/go-filemutex => github.com/alexflint/go-filemutex v0.0.0-20171022225611-72bdc8eae2ae
	github.com/andreyvit/diff => github.com/andreyvit/diff v0.0.0-20170406064948-c7f18ee00883
	github.com/anmitsu/go-shlex => github.com/anmitsu/go-shlex v0.0.0-20161002113705-648efa622239
	github.com/armon/circbuf => github.com/armon/circbuf v0.0.0-20150827004946-bbbad097214e
	github.com/armon/consul-api => github.com/armon/consul-api v0.0.0-20180202201655-eb2c6b5be1b6
	github.com/armon/go-metrics => github.com/armon/go-metrics v0.0.0-20190430140413-ec5e00d3c878
	github.com/armon/go-radix => github.com/armon/go-radix v0.0.0-20180808171621-7fddfc383310
	github.com/asaskevich/govalidator => github.com/asaskevich/govalidator v0.0.0-20190424111038-f61b66f89f4a
	github.com/auth0/go-jwt-middleware => github.com/auth0/go-jwt-middleware v0.0.0-20170425171159-5493cabe49f7
	github.com/aws/aws-sdk-go => github.com/aws/aws-sdk-go v1.25.43
	github.com/aws/aws-sdk-go-v2 => github.com/aws/aws-sdk-go-v2 v0.18.0
	github.com/bazelbuild/bazel-gazelle => github.com/bazelbuild/bazel-gazelle v0.19.1-0.20191105222053-70208cbdc798
	github.com/bazelbuild/buildtools => github.com/bazelbuild/buildtools v0.0.0-20190917191645-69366ca98f89
	github.com/bazelbuild/rules_go => github.com/bazelbuild/rules_go v0.0.0-20190719190356-6dae44dc5cab
	github.com/beorn7/perks => github.com/beorn7/perks v1.0.0
	github.com/bgentry/speakeasy => github.com/bgentry/speakeasy v0.1.0
	github.com/bifurcation/mint => github.com/bifurcation/mint v0.0.0-20180715133206-93c51c6ce115
	github.com/bitly/go-hostpool => github.com/bitly/go-hostpool v0.0.0-20171023180738-a3a6125de932
	github.com/blang/semver => github.com/blang/semver v3.5.0+incompatible
	github.com/bmizerany/assert => github.com/bmizerany/assert v0.0.0-20160611221934-b7ed37b82869
	github.com/boltdb/bolt => github.com/boltdb/bolt v1.3.1
	github.com/bradfitz/go-smtpd => github.com/bradfitz/go-smtpd v0.0.0-20170404230938-deb6d6237625
	github.com/buger/jsonparser => github.com/buger/jsonparser v0.0.0-20180808090653-f4dd9f5a6b44
	github.com/c9s/goprocinfo => github.com/c9s/goprocinfo v0.0.0-20190309065803-0b2ad9ac246b
	github.com/caddyserver/caddy => github.com/caddyserver/caddy v1.0.3
	github.com/cenkalti/backoff => github.com/cenkalti/backoff v2.1.1+incompatible
	github.com/census-instrumentation/opencensus-proto => github.com/census-instrumentation/opencensus-proto v0.2.1
	github.com/cespare/prettybench => github.com/cespare/prettybench v0.0.0-20150116022406-03b8cfe5406c
	github.com/cespare/xxhash/v2 => github.com/cespare/xxhash/v2 v2.1.0
	github.com/chai2010/gettext-go => github.com/chai2010/gettext-go v0.0.0-20160711120539-c6fed771bfd5
	github.com/checkpoint-restore/go-criu => github.com/checkpoint-restore/go-criu v0.0.0-20190109184317-bdb7599cd87b
	github.com/cheekybits/genny => github.com/cheekybits/genny v0.0.0-20170328200008-9127e812e1e9
	github.com/cilium/arping => github.com/cilium/arping v1.0.1-0.20190728065459-c5eaf8d7a710
	github.com/cilium/ebpf => github.com/cilium/ebpf v0.0.0-20191113100448-d9fb101ca1fb
	github.com/cilium/proxy => github.com/cilium/proxy v0.0.0-20191113190709-4c7b379792e6
	github.com/circonus-labs/circonus-gometrics => github.com/circonus-labs/circonus-gometrics v2.3.1+incompatible
	github.com/circonus-labs/circonusllhist => github.com/circonus-labs/circonusllhist v0.1.3
	github.com/client9/misspell => github.com/client9/misspell v0.3.4
	github.com/cloudflare/cfssl => github.com/cloudflare/cfssl v0.0.0-20180726162950-56268a613adf
	github.com/clusterhq/flocker-go => github.com/clusterhq/flocker-go v0.0.0-20160920122132-2b8b7259d313
	github.com/cockroachdb/datadriven => github.com/cockroachdb/datadriven v0.0.0-20190809214429-80d97fb3cbaa
	github.com/codegangsta/negroni => github.com/codegangsta/negroni v1.0.0
	github.com/container-storage-interface/spec => github.com/container-storage-interface/spec v1.2.0
	github.com/containerd/cgroups => github.com/containerd/cgroups v0.0.0-20190717030353-c4b9ac5c7601
	github.com/containerd/console => github.com/containerd/console v0.0.0-20170925154832-84eeaae905fa
	github.com/containerd/containerd => github.com/containerd/containerd v1.0.2
	github.com/containerd/continuity => github.com/containerd/continuity v0.0.0-20181203112020-004b46473808
	github.com/containerd/cri => github.com/containerd/cri v1.11.1-0.20190729065224-f0a677e76f68
	github.com/containerd/fifo => github.com/containerd/fifo v0.0.0-20190816180239-bda0ff6ed73c
	github.com/containerd/ttrpc => github.com/containerd/ttrpc v0.0.0-20190828172938-92c8520ef9f8
	github.com/containerd/typeurl => github.com/containerd/typeurl v0.0.0-20190228175220-2a93cfde8c20
	github.com/containernetworking/cni => github.com/containernetworking/cni v0.7.1
	github.com/containernetworking/plugins => github.com/containernetworking/plugins v0.8.2
	github.com/coredns/coredns => github.com/coredns/coredns v1.1.2
	github.com/coredns/corefile-migration => github.com/coredns/corefile-migration v1.0.4
	github.com/coreos/bbolt => github.com/coreos/bbolt v1.3.2
	github.com/coreos/etcd => github.com/coreos/etcd v3.3.10+incompatible
	github.com/coreos/go-etcd => github.com/coreos/go-etcd v2.0.0+incompatible
	github.com/coreos/go-iptables => github.com/coreos/go-iptables v0.4.2
	github.com/coreos/go-oidc => github.com/coreos/go-oidc v2.1.0+incompatible
	github.com/coreos/go-semver => github.com/coreos/go-semver v0.3.0
	github.com/coreos/go-systemd => github.com/coreos/go-systemd v0.0.0-20190321100706-95778dfbb74e
	github.com/coreos/pkg => github.com/coreos/pkg v0.0.0-20180108230652-97fdf19511ea
	github.com/coreos/rkt => github.com/coreos/rkt v1.30.0
	github.com/cpuguy83/go-md2man => github.com/cpuguy83/go-md2man v1.0.10
	github.com/cpuguy83/go-md2man/v2 => github.com/cpuguy83/go-md2man/v2 v2.0.0
	github.com/creack/pty => github.com/creack/pty v1.1.7
	github.com/cyphar/filepath-securejoin => github.com/cyphar/filepath-securejoin v0.2.2
	github.com/d2g/dhcp4 => github.com/d2g/dhcp4 v0.0.0-20170904100407-a1d1b6c41b1c
	github.com/d2g/dhcp4client => github.com/d2g/dhcp4client v1.0.0
	github.com/d2g/dhcp4server => github.com/d2g/dhcp4server v0.0.0-20181031114812-7d4a0a7f59a5
	github.com/d2g/hardwareaddr => github.com/d2g/hardwareaddr v0.0.0-20190221164911-e7d9fbe030e4
	github.com/davecgh/go-spew => github.com/davecgh/go-spew v1.1.1
	github.com/daviddengcn/go-colortext => github.com/daviddengcn/go-colortext v0.0.0-20160507010035-511bcaf42ccd
	github.com/deckarep/golang-set => github.com/deckarep/golang-set v1.7.1
	github.com/denisenkom/go-mssqldb => github.com/denisenkom/go-mssqldb v0.0.0-20180620032804-94c9c97e8c9f
	github.com/denverdino/aliyungo => github.com/denverdino/aliyungo v0.0.0-20170926055100-d3308649c661
	github.com/dgrijalva/jwt-go => github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/digitalocean/godo => github.com/digitalocean/godo v1.10.0
	github.com/dnaeon/go-vcr => github.com/dnaeon/go-vcr v1.0.1
	github.com/docker/distribution => github.com/docker/distribution v2.7.1+incompatible
	github.com/docker/docker => github.com/docker/docker v0.7.3-0.20190327010347-be7ac8be2ae0
	github.com/docker/go-connections => github.com/docker/go-connections v0.3.0
	github.com/docker/go-units => github.com/docker/go-units v0.4.0
	github.com/docker/libkv => github.com/docker/libkv v0.2.1
	github.com/docker/libnetwork => github.com/docker/libnetwork v0.0.0-20190128195551-d8d4c8cf03d7
	github.com/docker/spdystream => github.com/docker/spdystream v0.0.0-20160310174837-449fdfce4d96
	github.com/docopt/docopt-go => github.com/docopt/docopt-go v0.0.0-20180111231733-ee0de3bc6815
	github.com/duosecurity/duo_api_golang => github.com/duosecurity/duo_api_golang v0.0.0-20190308151101-6c680f768e74
	github.com/dustin/go-humanize => github.com/dustin/go-humanize v1.0.0
	github.com/elazarl/go-bindata-assetfs => github.com/elazarl/go-bindata-assetfs v0.0.0-20160803192304-e1a2a7ec64b0
	github.com/elazarl/goproxy => github.com/elazarl/goproxy v0.0.0-20170405201442-c4fc26588b6e
	github.com/emicklei/go-restful => github.com/emicklei/go-restful v2.9.5+incompatible
	github.com/envoyproxy/go-control-plane => github.com/envoyproxy/go-control-plane v0.8.0
	github.com/envoyproxy/protoc-gen-validate => github.com/envoyproxy/protoc-gen-validate v0.1.0
	github.com/etcd-io/etcd => go.etcd.io/etcd v0.5.0-alpha.5.0.20190911215424-9ed5f76dc03b
	github.com/euank/go-kmsg-parser => github.com/euank/go-kmsg-parser v2.0.0+incompatible
	github.com/evanphx/json-patch => github.com/evanphx/json-patch v4.2.0+incompatible
	github.com/exponent-io/jsonpath => github.com/exponent-io/jsonpath v0.0.0-20151013193312-d6023ce2651d
	github.com/fatih/camelcase => github.com/fatih/camelcase v1.0.0
	github.com/fatih/color => github.com/fatih/color v1.7.0
	github.com/fatih/structs => github.com/fatih/structs v0.0.0-20180123065059-ebf56d35bba7
	github.com/flynn/go-shlex => github.com/flynn/go-shlex v0.0.0-20150515145356-3f9db97f8568
	github.com/fsnotify/fsnotify => github.com/fsnotify/fsnotify v1.4.7
	github.com/ghodss/yaml => github.com/ghodss/yaml v1.0.0
	github.com/gliderlabs/ssh => github.com/gliderlabs/ssh v0.1.1
	github.com/globalsign/mgo => github.com/globalsign/mgo v0.0.0-20181015135952-eeefdecb41b8
	github.com/go-acme/lego => github.com/go-acme/lego v2.5.0+incompatible
	github.com/go-bindata/go-bindata => github.com/go-bindata/go-bindata v3.1.1+incompatible
	github.com/go-critic/go-critic => github.com/go-critic/go-critic v0.3.5-0.20190526074819-1df300866540
	github.com/go-gl/glfw => github.com/go-gl/glfw v0.0.0-20190409004039-e6da0acd62b1
	github.com/go-kit/kit => github.com/go-kit/kit v0.8.0
	github.com/go-ldap/ldap => github.com/go-ldap/ldap v3.0.2+incompatible
	github.com/go-lintpack/lintpack => github.com/go-lintpack/lintpack v0.5.2
	github.com/go-logfmt/logfmt => github.com/go-logfmt/logfmt v0.3.0
	github.com/go-logr/logr => github.com/go-logr/logr v0.1.0
	github.com/go-ole/go-ole => github.com/go-ole/go-ole v1.2.1
	github.com/go-openapi/analysis => github.com/go-openapi/analysis v0.19.5
	github.com/go-openapi/errors => github.com/go-openapi/errors v0.19.2
	github.com/go-openapi/jsonpointer => github.com/go-openapi/jsonpointer v0.19.3
	github.com/go-openapi/jsonreference => github.com/go-openapi/jsonreference v0.19.3
	github.com/go-openapi/loads => github.com/go-openapi/loads v0.19.4
	github.com/go-openapi/runtime => github.com/go-openapi/runtime v0.19.4
	github.com/go-openapi/spec => github.com/go-openapi/spec v0.19.3
	github.com/go-openapi/strfmt => github.com/go-openapi/strfmt v0.19.3
	github.com/go-openapi/swag => github.com/go-openapi/swag v0.19.5
	github.com/go-openapi/validate => github.com/go-openapi/validate v0.19.5
	github.com/go-ozzo/ozzo-validation => github.com/go-ozzo/ozzo-validation v3.5.0+incompatible
	github.com/go-sql-driver/mysql => github.com/go-sql-driver/mysql v1.4.0
	github.com/go-stack/stack => github.com/go-stack/stack v1.8.0
	github.com/go-test/deep => github.com/go-test/deep v1.0.2
	github.com/go-toolsmith/astcast => github.com/go-toolsmith/astcast v1.0.0
	github.com/go-toolsmith/astcopy => github.com/go-toolsmith/astcopy v1.0.0
	github.com/go-toolsmith/astequal => github.com/go-toolsmith/astequal v1.0.0
	github.com/go-toolsmith/astfmt => github.com/go-toolsmith/astfmt v1.0.0
	github.com/go-toolsmith/astinfo => github.com/go-toolsmith/astinfo v0.0.0-20180906194353-9809ff7efb21
	github.com/go-toolsmith/astp => github.com/go-toolsmith/astp v1.0.0
	github.com/go-toolsmith/pkgload => github.com/go-toolsmith/pkgload v1.0.0
	github.com/go-toolsmith/strparse => github.com/go-toolsmith/strparse v1.0.0
	github.com/go-toolsmith/typep => github.com/go-toolsmith/typep v1.0.0
	github.com/gobwas/glob => github.com/gobwas/glob v0.2.3
	github.com/gocql/gocql => github.com/gocql/gocql v0.0.0-20180617115710-e06f8c1bcd78
	github.com/godbus/dbus => github.com/godbus/dbus v0.0.0-20181101234600-2ff6f7ffd60f
	github.com/gogo/googleapis => github.com/gogo/googleapis v1.1.0
	github.com/gogo/protobuf => github.com/gogo/protobuf v1.2.2-0.20190723190241-65acae22fc9d
	github.com/golang/glog => github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b
	github.com/golang/groupcache => github.com/golang/groupcache v0.0.0-20160516000752-02826c3e7903
	github.com/golang/mock => github.com/golang/mock v1.2.0
	github.com/golang/protobuf => github.com/golang/protobuf v1.3.2
	github.com/golang/snappy => github.com/golang/snappy v0.0.1
	github.com/golangci/check => github.com/golangci/check v0.0.0-20180506172741-cfe4005ccda2
	github.com/golangci/dupl => github.com/golangci/dupl v0.0.0-20180902072040-3e9179ac440a
	github.com/golangci/errcheck => github.com/golangci/errcheck v0.0.0-20181223084120-ef45e06d44b6
	github.com/golangci/go-misc => github.com/golangci/go-misc v0.0.0-20180628070357-927a3d87b613
	github.com/golangci/go-tools => github.com/golangci/go-tools v0.0.0-20190318055746-e32c54105b7c
	github.com/golangci/goconst => github.com/golangci/goconst v0.0.0-20180610141641-041c5f2b40f3
	github.com/golangci/gocyclo => github.com/golangci/gocyclo v0.0.0-20180528134321-2becd97e67ee
	github.com/golangci/gofmt => github.com/golangci/gofmt v0.0.0-20181222123516-0b8337e80d98
	github.com/golangci/golangci-lint => github.com/golangci/golangci-lint v1.18.0
	github.com/golangci/gosec => github.com/golangci/gosec v0.0.0-20190211064107-66fb7fc33547
	github.com/golangci/ineffassign => github.com/golangci/ineffassign v0.0.0-20190609212857-42439a7714cc
	github.com/golangci/lint-1 => github.com/golangci/lint-1 v0.0.0-20190420132249-ee948d087217
	github.com/golangci/maligned => github.com/golangci/maligned v0.0.0-20180506175553-b1d89398deca
	github.com/golangci/misspell => github.com/golangci/misspell v0.0.0-20180809174111-950f5d19e770
	github.com/golangci/prealloc => github.com/golangci/prealloc v0.0.0-20180630174525-215b22d4de21
	github.com/golangci/revgrep => github.com/golangci/revgrep v0.0.0-20180526074752-d9c87f5ffaf0
	github.com/golangci/unconvert => github.com/golangci/unconvert v0.0.0-20180507085042-28b1c447d1f4
	github.com/golangplus/bytes => github.com/golangplus/bytes v0.0.0-20160111154220-45c989fe5450
	github.com/golangplus/fmt => github.com/golangplus/fmt v0.0.0-20150411045040-2a5d6d7d2995
	github.com/golangplus/testing => github.com/golangplus/testing v0.0.0-20180327235837-af21d9c3145e
	github.com/google/btree => github.com/google/btree v1.0.0
	github.com/google/cadvisor => github.com/google/cadvisor v0.34.0
	github.com/google/certificate-transparency-go => github.com/google/certificate-transparency-go v1.0.21
	github.com/google/go-cmp => github.com/google/go-cmp v0.3.0
	github.com/google/go-github => github.com/google/go-github v17.0.0+incompatible
	github.com/google/go-querystring => github.com/google/go-querystring v1.0.0
	github.com/google/gofuzz => github.com/google/gofuzz v1.0.0
	github.com/google/gopacket => github.com/google/gopacket v1.1.17
	github.com/google/gops => github.com/google/gops v0.3.6
	github.com/google/martian => github.com/google/martian v2.1.0+incompatible
	github.com/google/pprof => github.com/google/pprof v0.0.0-20181206194817-3ea8567a2e57
	github.com/google/renameio => github.com/google/renameio v0.1.0
	github.com/google/uuid => github.com/google/uuid v1.1.1
	github.com/googleapis/gax-go/v2 => github.com/googleapis/gax-go/v2 v2.0.4
	github.com/googleapis/gnostic => github.com/googleapis/gnostic v0.0.0-20170729233727-0c5108395e2d
	github.com/gophercloud/gophercloud => github.com/gophercloud/gophercloud v0.1.0
	github.com/gopherjs/gopherjs => github.com/gopherjs/gopherjs v0.0.0-20181017120253-0766667cb4d1
	github.com/gorilla/context => github.com/gorilla/context v1.1.1
	github.com/gorilla/mux => github.com/gorilla/mux v1.7.0
	github.com/gorilla/websocket => github.com/gorilla/websocket v1.4.0
	github.com/gostaticanalysis/analysisutil => github.com/gostaticanalysis/analysisutil v0.0.3
	github.com/gotestyourself/gotestyourself => github.com/gotestyourself/gotestyourself v2.2.0+incompatible
	github.com/gregjones/httpcache => github.com/gregjones/httpcache v0.0.0-20180305231024-9cad4c3443a7
	github.com/grpc-ecosystem/go-grpc-middleware => github.com/grpc-ecosystem/go-grpc-middleware v1.0.1-0.20190118093823-f849b5445de4
	github.com/grpc-ecosystem/go-grpc-prometheus => github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/grpc-ecosystem/grpc-gateway => github.com/grpc-ecosystem/grpc-gateway v1.9.5
	github.com/hailocab/go-hostpool => github.com/hailocab/go-hostpool v0.0.0-20160125115350-e80d13ce29ed
	github.com/hashicorp/consul => github.com/hashicorp/consul v1.6.1
	github.com/hashicorp/consul/api => github.com/hashicorp/consul/api v1.2.0
	github.com/hashicorp/consul/sdk => github.com/hashicorp/consul/sdk v0.2.0
	github.com/hashicorp/errwrap => github.com/hashicorp/errwrap v1.0.0
	github.com/hashicorp/go-bexpr => github.com/hashicorp/go-bexpr v0.1.2
	github.com/hashicorp/go-checkpoint => github.com/hashicorp/go-checkpoint v0.0.0-20171009173528-1545e56e46de
	github.com/hashicorp/go-cleanhttp => github.com/hashicorp/go-cleanhttp v0.5.1
	github.com/hashicorp/go-discover => github.com/hashicorp/go-discover v0.0.0-20190403160810-22221edb15cd
	github.com/hashicorp/go-hclog => github.com/hashicorp/go-hclog v0.9.1
	github.com/hashicorp/go-immutable-radix => github.com/hashicorp/go-immutable-radix v1.1.0
	github.com/hashicorp/go-memdb => github.com/hashicorp/go-memdb v0.0.0-20180223233045-1289e7fffe71
	github.com/hashicorp/go-msgpack => github.com/hashicorp/go-msgpack v0.5.5
	github.com/hashicorp/go-multierror => github.com/hashicorp/go-multierror v1.0.0
	github.com/hashicorp/go-plugin => github.com/hashicorp/go-plugin v0.0.0-20180331002553-e8d22c780116
	github.com/hashicorp/go-raftchunking => github.com/hashicorp/go-raftchunking v0.6.1
	github.com/hashicorp/go-retryablehttp => github.com/hashicorp/go-retryablehttp v0.5.3
	github.com/hashicorp/go-rootcerts => github.com/hashicorp/go-rootcerts v1.0.1
	github.com/hashicorp/go-sockaddr => github.com/hashicorp/go-sockaddr v1.0.0
	github.com/hashicorp/go-syslog => github.com/hashicorp/go-syslog v1.0.0
	github.com/hashicorp/go-uuid => github.com/hashicorp/go-uuid v1.0.1
	github.com/hashicorp/go-version => github.com/hashicorp/go-version v0.0.0-20170202080759-03c5bf6be031
	github.com/hashicorp/go.net => github.com/hashicorp/go.net v0.0.1
	github.com/hashicorp/golang-lru => github.com/hashicorp/golang-lru v0.5.1
	github.com/hashicorp/hcl => github.com/hashicorp/hcl v1.0.0
	github.com/hashicorp/hil => github.com/hashicorp/hil v0.0.0-20160711231837-1e86c6b523c5
	github.com/hashicorp/logutils => github.com/hashicorp/logutils v1.0.0
	github.com/hashicorp/mdns => github.com/hashicorp/mdns v1.0.0
	github.com/hashicorp/memberlist => github.com/hashicorp/memberlist v0.1.5
	github.com/hashicorp/net-rpc-msgpackrpc => github.com/hashicorp/net-rpc-msgpackrpc v0.0.0-20151116020338-a14192a58a69
	github.com/hashicorp/raft => github.com/hashicorp/raft v1.1.1
	github.com/hashicorp/raft-boltdb => github.com/hashicorp/raft-boltdb v0.0.0-20171010151810-6e5ba93211ea
	github.com/hashicorp/serf => github.com/hashicorp/serf v0.8.5
	github.com/hashicorp/vault => github.com/hashicorp/vault v0.10.3
	github.com/hashicorp/vault-plugin-secrets-kv => github.com/hashicorp/vault-plugin-secrets-kv v0.0.0-20190318174639-195e0e9d07f1
	github.com/hashicorp/vic => github.com/hashicorp/vic v1.5.1-0.20190403131502-bbfe86ec9443
	github.com/hashicorp/yamux => github.com/hashicorp/yamux v0.0.0-20181012175058-2f1d1f20f75d
	github.com/heketi/heketi => github.com/heketi/heketi v9.0.1-0.20190917153846-c2e2a4ab7ab9+incompatible
	github.com/heketi/rest => github.com/heketi/rest v0.0.0-20180404230133-aa6a65207413
	github.com/heketi/tests => github.com/heketi/tests v0.0.0-20151005000721-f3775cbcefd6
	github.com/heketi/utils => github.com/heketi/utils v0.0.0-20170317161834-435bc5bdfa64
	github.com/hpcloud/tail => github.com/hpcloud/tail v1.0.0
	github.com/iancoleman/strcase => github.com/iancoleman/strcase v0.0.0-20190422225806-e506e3ef7365
	github.com/imdario/mergo => github.com/imdario/mergo v0.3.5
	github.com/inconshreveable/mousetrap => github.com/inconshreveable/mousetrap v1.0.0
	github.com/ishidawataru/sctp => github.com/ishidawataru/sctp v0.0.0-20180213033435-07191f837fed
	github.com/j-keck/arping => github.com/j-keck/arping v0.0.0-20160618110441-2cf9dc699c56
	github.com/jarcoal/httpmock => github.com/jarcoal/httpmock v0.0.0-20180424175123-9c70cfe4a1da
	github.com/jefferai/jsonx => github.com/jefferai/jsonx v0.0.0-20160721235117-9cc31c3135ee
	github.com/jellevandenhooff/dkim => github.com/jellevandenhooff/dkim v0.0.0-20150330215556-f50fe3d243e1
	github.com/jessevdk/go-flags => github.com/jessevdk/go-flags v1.4.0
	github.com/jimstudt/http-authentication => github.com/jimstudt/http-authentication v0.0.0-20140401203705-3eca13d6893a
	github.com/jmespath/go-jmespath => github.com/jmespath/go-jmespath v0.0.0-20180206201540-c2b33e8439af
	github.com/jonboulle/clockwork => github.com/jonboulle/clockwork v0.1.0
	github.com/joyent/triton-go => github.com/joyent/triton-go v0.0.0-20180628001255-830d2b111e62
	github.com/json-iterator/go => github.com/json-iterator/go v1.1.8
	github.com/jstemmer/go-junit-report => github.com/jstemmer/go-junit-report v0.0.0-20190106144839-af01ea7f8024
	github.com/jtolds/gls => github.com/jtolds/gls v4.20.0+incompatible
	github.com/juju/errors => github.com/juju/errors v0.0.0-20180806074554-22422dad46e1
	github.com/juju/loggo => github.com/juju/loggo v0.0.0-20190526231331-6e530bcce5d8
	github.com/juju/testing => github.com/juju/testing v0.0.0-20190613124551-e81189438503
	github.com/julienschmidt/httprouter => github.com/julienschmidt/httprouter v1.2.0
	github.com/kardianos/osext => github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0
	github.com/karrick/godirwalk => github.com/karrick/godirwalk v1.7.5
	github.com/kevinburke/ssh_config => github.com/kevinburke/ssh_config v0.0.0-20190725054713-01f96b0aa0cd
	github.com/keybase/go-crypto => github.com/keybase/go-crypto v0.0.0-20180614160407-5114a9a81e1b
	github.com/keybase/go-ps => github.com/keybase/go-ps v0.0.0-20161005175911-668c8856d999
	github.com/kisielk/errcheck => github.com/kisielk/errcheck v1.2.0
	github.com/kisielk/gotool => github.com/kisielk/gotool v1.0.0
	github.com/klauspost/compress => github.com/klauspost/compress v1.4.1
	github.com/klauspost/cpuid => github.com/klauspost/cpuid v1.2.0
	github.com/konsorten/go-windows-terminal-sequences => github.com/konsorten/go-windows-terminal-sequences v1.0.1
	github.com/kr/logfmt => github.com/kr/logfmt v0.0.0-20140226030751-b84e30acd515
	github.com/kr/pretty => github.com/kr/pretty v0.1.0
	github.com/kr/pty => github.com/kr/pty v1.1.5
	github.com/kr/text => github.com/kr/text v0.1.0
	github.com/kylelemons/godebug => github.com/kylelemons/godebug v0.0.0-20170820004349-d65d576e9348
	github.com/lib/pq => github.com/lib/pq v0.0.0-20180523175426-90697d60dd84
	github.com/libopenstorage/openstorage => github.com/libopenstorage/openstorage v1.0.0
	github.com/liggitt/tabwriter => github.com/liggitt/tabwriter v0.0.0-20181228230101-89fcab3d43de
	github.com/lithammer/dedent => github.com/lithammer/dedent v1.1.0
	github.com/logrusorgru/aurora => github.com/logrusorgru/aurora v0.0.0-20181002194514-a7b3b318ed4e
	github.com/lpabon/godbc => github.com/lpabon/godbc v0.1.1
	github.com/lucas-clemente/aes12 => github.com/lucas-clemente/aes12 v0.0.0-20171027163421-cd47fb39b79f
	github.com/lucas-clemente/quic-clients => github.com/lucas-clemente/quic-clients v0.1.0
	github.com/lucas-clemente/quic-go => github.com/lucas-clemente/quic-go v0.10.2
	github.com/lucas-clemente/quic-go-certificates => github.com/lucas-clemente/quic-go-certificates v0.0.0-20160823095156-d2f86524cced
	github.com/lyft/protoc-gen-star => github.com/lyft/protoc-gen-star v0.4.11
	github.com/magiconair/properties => github.com/magiconair/properties v1.8.1
	github.com/mailru/easyjson => github.com/mailru/easyjson v0.7.0
	github.com/marten-seemann/qtls => github.com/marten-seemann/qtls v0.2.3
	github.com/mattn/go-colorable => github.com/mattn/go-colorable v0.0.9
	github.com/mattn/go-isatty => github.com/mattn/go-isatty v0.0.9
	github.com/mattn/go-runewidth => github.com/mattn/go-runewidth v0.0.2
	github.com/mattn/go-shellwords => github.com/mattn/go-shellwords v1.0.5
	github.com/mattn/goveralls => github.com/mattn/goveralls v0.0.2
	github.com/matttproud/golang_protobuf_extensions => github.com/matttproud/golang_protobuf_extensions v1.0.1
	github.com/mesos/mesos-go => github.com/mesos/mesos-go v0.0.9
	github.com/mholt/certmagic => github.com/mholt/certmagic v0.6.2-0.20190624175158-6a42ef9fe8c2
	github.com/miekg/dns => github.com/cilium/dns v1.1.4-0.20190417235132-8e25ec9a0ff3
	github.com/mindprince/gonvml => github.com/mindprince/gonvml v0.0.0-20190828220739-9ebdce4bb989
	github.com/mistifyio/go-zfs => github.com/mistifyio/go-zfs v2.1.1+incompatible
	github.com/mitchellh/cli => github.com/mitchellh/cli v1.0.0
	github.com/mitchellh/copystructure => github.com/mitchellh/copystructure v1.0.0
	github.com/mitchellh/go-homedir => github.com/mitchellh/go-homedir v1.1.0
	github.com/mitchellh/go-ps => github.com/mitchellh/go-ps v0.0.0-20170309133038-4fdf99ab2936
	github.com/mitchellh/go-testing-interface => github.com/mitchellh/go-testing-interface v1.0.0
	github.com/mitchellh/go-wordwrap => github.com/mitchellh/go-wordwrap v1.0.0
	github.com/mitchellh/hashstructure => github.com/mitchellh/hashstructure v0.0.0-20170609045927-2bca23e0e452
	github.com/mitchellh/mapstructure => github.com/mitchellh/mapstructure v1.1.2
	github.com/mitchellh/reflectwalk => github.com/mitchellh/reflectwalk v1.0.1
	github.com/modern-go/concurrent => github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd
	github.com/modern-go/reflect2 => github.com/modern-go/reflect2 v1.0.1
	github.com/mohae/deepcopy => github.com/mohae/deepcopy v0.0.0-20170603005431-491d3605edfb
	github.com/morikuni/aec => github.com/morikuni/aec v0.0.0-20170113033406-39771216ff4c
	github.com/mozilla/tls-observatory => github.com/mozilla/tls-observatory v0.0.0-20180409132520-8791a200eb40
	github.com/mrunalp/fileutils => github.com/mrunalp/fileutils v0.0.0-20171103030105-7d4729fb3618
	github.com/munnerz/goautoneg => github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822
	github.com/mvdan/xurls => github.com/mvdan/xurls v1.1.0
	github.com/mwitkow/go-conntrack => github.com/mwitkow/go-conntrack v0.0.0-20161129095857-cc309e4a2223
	github.com/mxk/go-flowrate => github.com/mxk/go-flowrate v0.0.0-20140419014527-cca7078d478f
	github.com/naoina/go-stringutil => github.com/naoina/go-stringutil v0.1.0
	github.com/naoina/toml => github.com/naoina/toml v0.1.1
	github.com/nbutton23/zxcvbn-go => github.com/nbutton23/zxcvbn-go v0.0.0-20171102151520-eafdab6b0663
	github.com/nicolai86/scaleway-sdk => github.com/nicolai86/scaleway-sdk v1.10.2-0.20180628010248-798f60e20bb2
	github.com/oklog/run => github.com/oklog/run v0.0.0-20180308005104-6934b124db28
	github.com/olekukonko/tablewriter => github.com/olekukonko/tablewriter v0.0.0-20170122224234-a0225b3f23b5
	github.com/onsi/ginkgo => github.com/onsi/ginkgo v1.10.1
	github.com/onsi/gomega => github.com/onsi/gomega v1.7.0
	github.com/op/go-logging => github.com/op/go-logging v0.0.0-20160315200505-970db520ece7
	github.com/opencontainers/go-digest => github.com/opencontainers/go-digest v1.0.0-rc1
	github.com/opencontainers/image-spec => github.com/opencontainers/image-spec v1.0.1
	github.com/opencontainers/runc => github.com/opencontainers/runc v1.0.0-rc9
	github.com/opencontainers/runtime-spec => github.com/opencontainers/runtime-spec v1.0.0
	github.com/opencontainers/selinux => github.com/opencontainers/selinux v1.3.1-0.20190929122143-5215b1806f52
	github.com/optiopay/kafka => github.com/cilium/kafka v0.0.0-20180809090225-01ce283b732b
	github.com/ory/dockertest => github.com/ory/dockertest v3.3.4+incompatible
	github.com/packethost/packngo => github.com/packethost/packngo v0.1.1-0.20180711074735-b9cb5096f54c
	github.com/pascaldekloe/goe => github.com/pascaldekloe/goe v0.1.0
	github.com/patrickmn/go-cache => github.com/patrickmn/go-cache v0.0.0-20180527043350-9f6ff22cfff8
	github.com/pborman/uuid => github.com/pborman/uuid v1.2.0
	github.com/pelletier/go-toml => github.com/pelletier/go-toml v1.2.0
	github.com/peterbourgon/diskv => github.com/peterbourgon/diskv v2.0.1+incompatible
	github.com/petermattis/goid => github.com/petermattis/goid v0.0.0-20180202154549-b0b1615b78e5
	github.com/pkg/errors => github.com/pkg/errors v0.8.1
	github.com/pmezard/go-difflib => github.com/pmezard/go-difflib v1.0.0
	github.com/posener/complete => github.com/posener/complete v1.1.1
	github.com/pquerna/cachecontrol => github.com/pquerna/cachecontrol v0.0.0-20171018203845-0dec1b30a021
	github.com/pquerna/ffjson => github.com/pquerna/ffjson v0.0.0-20180717144149-af8b230fcd20
	github.com/prometheus/client_golang => github.com/prometheus/client_golang v1.2.0
	github.com/prometheus/client_model => github.com/prometheus/client_model v0.0.0-20190812154241-14fe0d1b01d4
	github.com/prometheus/common => github.com/prometheus/common v0.7.0
	github.com/prometheus/procfs => github.com/prometheus/procfs v0.0.5
	github.com/quasilyte/go-consistent => github.com/quasilyte/go-consistent v0.0.0-20190521200055-c6f3937de18c
	github.com/quobyte/api => github.com/quobyte/api v0.1.2
	github.com/remyoudompheng/bigfft => github.com/remyoudompheng/bigfft v0.0.0-20170806203942-52369c62f446
	github.com/renier/xmlrpc => github.com/renier/xmlrpc v0.0.0-20170708154548-ce4a1a486c03
	github.com/robfig/cron => github.com/robfig/cron v1.1.0
	github.com/rogpeppe/fastuuid => github.com/rogpeppe/fastuuid v0.0.0-20150106093220-6724a57986af
	github.com/rogpeppe/go-internal => github.com/rogpeppe/go-internal v1.3.0
	github.com/rubiojr/go-vhd => github.com/rubiojr/go-vhd v0.0.0-20160810183302-0bfd3b39853c
	github.com/russross/blackfriday => github.com/russross/blackfriday v1.5.2
	github.com/russross/blackfriday/v2 => github.com/russross/blackfriday/v2 v2.0.1
	github.com/ryanuber/columnize => github.com/ryanuber/columnize v0.0.0-20160712163229-9b3edd62028f
	github.com/ryanuber/go-glob => github.com/ryanuber/go-glob v0.0.0-20170128012129-256dc444b735
	github.com/safchain/ethtool => github.com/safchain/ethtool v0.0.0-20190326074333-42ed695e3de8
	github.com/samuel/go-zookeeper => github.com/samuel/go-zookeeper v0.0.0-20190923202752-2cc03de413da
	github.com/sasha-s/go-deadlock => github.com/sasha-s/go-deadlock v0.2.0
	github.com/satori/go.uuid => github.com/satori/go.uuid v1.2.0
	github.com/sean-/seed => github.com/sean-/seed v0.0.0-20170313163322-e2103e2c3529
	github.com/seccomp/libseccomp-golang => github.com/seccomp/libseccomp-golang v0.9.1
	github.com/sergi/go-diff => github.com/sergi/go-diff v1.0.0
	github.com/servak/go-fastping => github.com/servak/go-fastping v0.0.0-20160802140958-5718d12e20a0
	github.com/shirou/gopsutil => github.com/shirou/gopsutil v0.0.0-20180427012116-c95755e4bcd7
	github.com/shirou/w32 => github.com/shirou/w32 v0.0.0-20160930032740-bb4de0191aa4
	github.com/shurcooL/go => github.com/shurcooL/go v0.0.0-20180423040247-9e1955d9fb6e
	github.com/shurcooL/go-goon => github.com/shurcooL/go-goon v0.0.0-20170922171312-37c2f522c041
	github.com/shurcooL/sanitized_anchor_name => github.com/shurcooL/sanitized_anchor_name v1.0.0
	github.com/sirupsen/logrus => github.com/sirupsen/logrus v1.4.2
	github.com/smartystreets/assertions => github.com/smartystreets/assertions v0.0.0-20180927180507-b2de0cb4f26d
	github.com/smartystreets/goconvey => github.com/smartystreets/goconvey v0.0.0-20190330032615-68dc04aab96a
	github.com/softlayer/softlayer-go => github.com/softlayer/softlayer-go v0.0.0-20180806151055-260589d94c7d
	github.com/soheilhy/cmux => github.com/soheilhy/cmux v0.1.4
	github.com/sourcegraph/go-diff => github.com/sourcegraph/go-diff v0.5.1
	github.com/spf13/afero => github.com/spf13/afero v1.2.2
	github.com/spf13/cast => github.com/spf13/cast v1.3.0
	github.com/spf13/cobra => github.com/spf13/cobra v0.0.5
	github.com/spf13/jwalterweatherman => github.com/spf13/jwalterweatherman v1.1.0
	github.com/spf13/pflag => github.com/spf13/pflag v1.0.5
	github.com/spf13/viper => github.com/spf13/viper v1.6.1
	github.com/storageos/go-api => github.com/storageos/go-api v0.0.0-20180912212459-343b3eff91fc
	github.com/stretchr/objx => github.com/stretchr/objx v0.2.0
	github.com/stretchr/testify => github.com/stretchr/testify v1.4.0
	github.com/subosito/gotenv => github.com/subosito/gotenv v1.2.0
	github.com/syndtr/gocapability => github.com/syndtr/gocapability v0.0.0-20180916011248-d98352740cb2
	github.com/tarm/serial => github.com/tarm/serial v0.0.0-20180830185346-98f6abe2eb07
	github.com/tchap/go-patricia => github.com/tchap/go-patricia v2.3.0+incompatible
	github.com/tent/http-link-go => github.com/tent/http-link-go v0.0.0-20130702225549-ac974c61c2f9
	github.com/thecodeteam/goscaleio => github.com/thecodeteam/goscaleio v0.1.0
	github.com/tidwall/pretty => github.com/tidwall/pretty v1.0.0
	github.com/timakin/bodyclose => github.com/timakin/bodyclose v0.0.0-20190721030226-87058b9bfcec
	github.com/tmc/grpc-websocket-proxy => github.com/tmc/grpc-websocket-proxy v0.0.0-20170815181823-89b8d40f7ca8
	github.com/tv42/httpunix => github.com/tv42/httpunix v0.0.0-20150427012821-b75d8614f926
	github.com/ugorji/go => github.com/ugorji/go v1.1.4
	github.com/ugorji/go/codec => github.com/ugorji/go/codec v0.0.0-20181204163529-d75b2dcb6bc8
	github.com/ultraware/funlen => github.com/ultraware/funlen v0.0.2
	github.com/urfave/cli => github.com/urfave/cli v1.20.0
	github.com/urfave/negroni => github.com/urfave/negroni v1.0.0
	github.com/valyala/bytebufferpool => github.com/valyala/bytebufferpool v1.0.0
	github.com/valyala/fasthttp => github.com/valyala/fasthttp v1.2.0
	github.com/valyala/quicktemplate => github.com/valyala/quicktemplate v1.1.1
	github.com/valyala/tcplisten => github.com/valyala/tcplisten v0.0.0-20161114210144-ceec8f93295a
	github.com/vektah/gqlparser => github.com/vektah/gqlparser v1.1.2
	github.com/vishvananda/netlink => github.com/vishvananda/netlink v1.0.1-0.20191113183427-d71301a47b60
	github.com/vishvananda/netns => github.com/vishvananda/netns v0.0.0-20190625233234-7109fa855b0f
	github.com/vmware/govmomi => github.com/vmware/govmomi v0.20.3
	github.com/xiang90/probing => github.com/xiang90/probing v0.0.0-20190116061207-43a291ad63a2
	github.com/xlab/handysort => github.com/xlab/handysort v0.0.0-20150421192137-fb3537ed64a1
	github.com/xlab/treeprint => github.com/xlab/treeprint v0.0.0-20180616005107-d6fb6747feb6
	github.com/xordataexchange/crypt => github.com/xordataexchange/crypt v0.0.3-0.20170626215501-b2862e3d0a77
	go.etcd.io/bbolt => go.etcd.io/bbolt v1.3.3
	go.etcd.io/etcd => go.etcd.io/etcd v0.5.0-alpha.5.0.20191023171146-3cf2f69b5738
	go.mongodb.org/mongo-driver => go.mongodb.org/mongo-driver v1.1.2
	go.opencensus.io => go.opencensus.io v0.21.0
	go.uber.org/atomic => go.uber.org/atomic v1.3.2
	go.uber.org/multierr => go.uber.org/multierr v1.1.0
	go.uber.org/zap => go.uber.org/zap v1.10.0
	go4.org => go4.org v0.0.0-20180809161055-417644f6feb5
	golang.org/x/build => golang.org/x/build v0.0.0-20190927031335-2835ba2e683f
	golang.org/x/crypto => golang.org/x/crypto v0.0.0-20190820162420-60c769a6c586
	golang.org/x/exp => golang.org/x/exp v0.0.0-20190312203227-4b39c73a6495
	golang.org/x/image => golang.org/x/image v0.0.0-20190227222117-0694c2d4d067
	golang.org/x/lint => golang.org/x/lint v0.0.0-20190409202823-959b441ac422
	golang.org/x/mobile => golang.org/x/mobile v0.0.0-20190312151609-d3739f865fa6
	golang.org/x/mod => golang.org/x/mod v0.0.0-20190513183733-4bf6d317e70e
	golang.org/x/net => golang.org/x/net v0.0.0-20191004110552-13f9640d40b9
	golang.org/x/oauth2 => golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	golang.org/x/perf => golang.org/x/perf v0.0.0-20180704124530-6e6d33e29852
	golang.org/x/sync => golang.org/x/sync v0.0.0-20190911185100-cd5d95a43a6e
	golang.org/x/sys => golang.org/x/sys v0.0.0-20190813064441-fde4db37ae7a // pinned to release-branch.go1.13
	golang.org/x/text => golang.org/x/text v0.3.2
	golang.org/x/time => golang.org/x/time v0.0.0-20190308202827-9d24e82272b4
	golang.org/x/tools => golang.org/x/tools v0.0.0-20190821162956-65e3620a7ae7 // pinned to release-branch.go1.13
	golang.org/x/xerrors => golang.org/x/xerrors v0.0.0-20190717185122-a985d3407aa7
	gonum.org/v1/gonum => gonum.org/v1/gonum v0.0.0-20190331200053-3d26580ed485
	gonum.org/v1/netlib => gonum.org/v1/netlib v0.0.0-20190331212654-76723241ea4e
	google.golang.org/api => google.golang.org/api v0.6.1-0.20190607001116-5213b8090861
	google.golang.org/appengine => google.golang.org/appengine v1.5.0
	google.golang.org/genproto => google.golang.org/genproto v0.0.0-20190502173448-54afdca5d873
	google.golang.org/grpc => google.golang.org/grpc v1.23.1
	gopkg.in/airbrake/gobrake.v2 => gopkg.in/airbrake/gobrake.v2 v2.0.9
	gopkg.in/alecthomas/kingpin.v2 => gopkg.in/alecthomas/kingpin.v2 v2.2.6
	gopkg.in/asn1-ber.v1 => gopkg.in/asn1-ber.v1 v1.0.0-20181015200546-f715ec2f112d
	gopkg.in/check.v1 => gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127
	gopkg.in/cheggaaa/pb.v1 => gopkg.in/cheggaaa/pb.v1 v1.0.25
	gopkg.in/errgo.v2 => gopkg.in/errgo.v2 v2.1.0
	gopkg.in/fsnotify.v1 => gopkg.in/fsnotify.v1 v1.4.7
	gopkg.in/gcfg.v1 => gopkg.in/gcfg.v1 v1.2.0
	gopkg.in/gemnasium/logrus-airbrake-hook.v2 => gopkg.in/gemnasium/logrus-airbrake-hook.v2 v2.1.2
	gopkg.in/inf.v0 => gopkg.in/inf.v0 v0.9.1
	gopkg.in/ini.v1 => gopkg.in/ini.v1 v1.51.0
	gopkg.in/mcuadros/go-syslog.v2 => gopkg.in/mcuadros/go-syslog.v2 v2.2.1
	gopkg.in/mgo.v2 => gopkg.in/mgo.v2 v2.0.0-20180705113604-9856a29383ce
	gopkg.in/natefinch/lumberjack.v2 => gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gopkg.in/ory-am/dockertest.v3 => gopkg.in/ory-am/dockertest.v3 v3.3.4
	gopkg.in/resty.v1 => gopkg.in/resty.v1 v1.12.0
	gopkg.in/square/go-jose.v2 => gopkg.in/square/go-jose.v2 v2.2.2
	gopkg.in/tomb.v1 => gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7
	gopkg.in/warnings.v0 => gopkg.in/warnings.v0 v0.1.1
	gopkg.in/yaml.v2 => gopkg.in/yaml.v2 v2.2.4
	gotest.tools => gotest.tools v2.2.0+incompatible
	gotest.tools/gotestsum => gotest.tools/gotestsum v0.3.5
	grpc.go4.org => grpc.go4.org v0.0.0-20170609214715-11d0a25b4919
	honnef.co/go/tools => honnef.co/go/tools v0.0.1-2019.2.2
	istio.io/gogo-genproto => istio.io/gogo-genproto v0.0.0-20190124151557-6d926a6e6feb

	// v0.0.0-20200312205431-8d8aa3959853 -> k8s v1.17.4
	k8s.io/api => k8s.io/kubernetes/staging/src/k8s.io/api v0.0.0-20200312205431-8d8aa3959853
	k8s.io/apiextensions-apiserver => k8s.io/kubernetes/staging/src/k8s.io/apiextensions-apiserver v0.0.0-20200312205431-8d8aa3959853
	k8s.io/apimachinery => k8s.io/kubernetes/staging/src/k8s.io/apimachinery v0.0.0-20200312205431-8d8aa3959853
	k8s.io/apiserver => k8s.io/kubernetes/staging/src/k8s.io/apiserver v0.0.0-20200312205431-8d8aa3959853
	k8s.io/cli-runtime => k8s.io/kubernetes/staging/src/k8s.io/cli-runtime v0.0.0-20200312205431-8d8aa3959853
	k8s.io/client-go => github.com/cilium/client-go v0.0.0-20200323094943-b43e7e2f9a75
	k8s.io/cloud-provider => k8s.io/kubernetes/staging/src/k8s.io/cloud-provider v0.0.0-20200312205431-8d8aa3959853
	k8s.io/cluster-bootstrap => k8s.io/kubernetes/staging/src/k8s.io/cluster-bootstrap v0.0.0-20200312205431-8d8aa3959853
	k8s.io/code-generator => k8s.io/kubernetes/staging/src/k8s.io/code-generator v0.0.0-20200312205431-8d8aa3959853
	k8s.io/component-base => k8s.io/kubernetes/staging/src/k8s.io/component-base v0.0.0-20200312205431-8d8aa3959853
	k8s.io/cri-api => k8s.io/kubernetes/staging/src/k8s.io/cri-api v0.0.0-20200312205431-8d8aa3959853
	k8s.io/csi-translation-lib => k8s.io/kubernetes/staging/src/k8s.io/csi-translation-lib v0.0.0-20200312205431-8d8aa3959853
	k8s.io/gengo => k8s.io/gengo v0.0.0-20190822140433-26a664648505
	k8s.io/heapster => k8s.io/heapster v1.2.0-beta.1
	k8s.io/klog => k8s.io/klog v1.0.0
	k8s.io/kube-aggregator => k8s.io/kubernetes/staging/src/k8s.io/kube-aggregator v0.0.0-20200312205431-8d8aa3959853
	k8s.io/kube-controller-manager => k8s.io/kubernetes/staging/src/k8s.io/kube-controller-manager v0.0.0-20200312205431-8d8aa3959853
	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20191107075043-30be4d16710a
	k8s.io/kube-proxy => k8s.io/kubernetes/staging/src/k8s.io/kube-proxy v0.0.0-20200312205431-8d8aa3959853
	k8s.io/kube-scheduler => k8s.io/kubernetes/staging/src/k8s.io/kube-scheduler v0.0.0-20200312205431-8d8aa3959853
	k8s.io/kubectl => k8s.io/kubernetes/staging/src/k8s.io/kubectl v0.0.0-20200312205431-8d8aa3959853
	k8s.io/kubelet => k8s.io/kubernetes/staging/src/k8s.io/kubelet v0.0.0-20200312205431-8d8aa3959853
	k8s.io/kubernetes => k8s.io/kubernetes v1.17.4
	k8s.io/legacy-cloud-providers => k8s.io/kubernetes/staging/src/k8s.io/legacy-cloud-providers v0.0.0-20200312205431-8d8aa3959853
	k8s.io/metrics => k8s.io/kubernetes/staging/src/k8s.io/metrics v0.0.0-20200312205431-8d8aa3959853
	k8s.io/repo-infra => k8s.io/repo-infra v0.0.1-alpha.1
	k8s.io/sample-apiserver => k8s.io/kubernetes/staging/src/k8s.io/sample-apiserver v0.0.0-20200312205431-8d8aa3959853
	k8s.io/system-validators => k8s.io/system-validators v1.0.4
	k8s.io/utils => k8s.io/utils v0.0.0-20191114184206-e782cd3c129f
	modernc.org/cc => modernc.org/cc v1.0.0
	modernc.org/golex => modernc.org/golex v1.0.0
	modernc.org/mathutil => modernc.org/mathutil v1.0.0
	modernc.org/strutil => modernc.org/strutil v1.0.0
	modernc.org/xc => modernc.org/xc v1.0.0
	mvdan.cc/interfacer => mvdan.cc/interfacer v0.0.0-20180901003855-c20040233aed
	mvdan.cc/lint => mvdan.cc/lint v0.0.0-20170908181259-adc824a0674b
	mvdan.cc/unparam => mvdan.cc/unparam v0.0.0-20190209190245-fbb59629db34
	rsc.io/goversion => rsc.io/goversion v1.0.0
	sigs.k8s.io/kustomize => sigs.k8s.io/kustomize v2.0.3+incompatible
	sigs.k8s.io/structured-merge-diff => sigs.k8s.io/structured-merge-diff v1.0.1-0.20191108220359-b1b620dd3f06
	sigs.k8s.io/yaml => sigs.k8s.io/yaml v1.1.0
	sourcegraph.com/sqs/pbtypes => sourcegraph.com/sqs/pbtypes v0.0.0-20180604144634-d3ebe8f20ae4
	vbom.ml/util => vbom.ml/util v0.0.0-20160121211510-db5cfe13f5cc
)
