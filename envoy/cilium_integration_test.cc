#include <string>

#include "envoy/network/listen_socket.h"
#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"
#include "envoy/singleton/manager.h"

#include "common/common/assert.h"
#include "common/network/address_impl.h"
#include "common/network/utility.h"

#include "common/config/filesystem_subscription_impl.h"
#include "common/config/utility.h"
#include "common/filesystem/filesystem_impl.h"
#include "common/protobuf/protobuf.h"
#include "common/thread_local/thread_local_impl.h"
#include "extensions/filters/network/http_connection_manager/config.h"

#include "test/integration/http_integration.h"
#include "test/test_common/environment.h"
#include "test/test_common/network_utility.h"

#include "cilium_bpf_metadata.h"
#include "cilium_l7policy.h"
#include "cilium_network_policy.h"
#include "cilium_socket_option.h"
#include "cilium/cilium_bpf_metadata.pb.validate.h"
#include "cilium/cilium_l7policy.pb.validate.h"

namespace Envoy {

std::string host_map_config;
std::shared_ptr<const Cilium::PolicyHostMap> hostmap{nullptr};

Network::Address::InstanceConstSharedPtr original_dst_address;
std::shared_ptr<const Cilium::NetworkPolicyMap> npmap{nullptr};

std::string policy_config;

const std::string BASIC_POLICY = R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicy
  name: '173'
  policy: 3
  ingress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 1 ]
      http_rules:
        http_rules:
        - headers: [ { name: ':path', value: '/allowed', regex: false } ]
        - headers: [ { name: ':path', value: '.*public$', regex: true } ]
        - headers: [ { name: ':authority', value: 'allowedHOST', regex: false } ]
        - headers: [ { name: ':authority', value: '.*REGEX.*', regex: true } ]
        - headers: [ { name: ':method', value: 'PUT', regex: false }, { name: ':path', value: '/public/opinions', regex: false } ]
    - remote_policies: [ 2 ]
      http_rules:
        http_rules:
        - headers: [ { name: ':path', value: '/only-2-allowed', regex: false } ]
  egress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 1 ]
      http_rules:
        http_rules:
        - headers: [ { name: ':path', value: '/allowed', regex: false } ]
        - headers: [ { name: ':path', value: '.*public$', regex: true } ]
        - headers: [ { name: ':authority', value: 'allowedHOST', regex: false } ]
        - headers: [ { name: ':authority', value: '.*REGEX.*', regex: true } ]
        - headers: [ { name: ':method', value: 'PUT', regex: false }, { name: ':path', value: '/public/opinions', regex: false } ]
    - remote_policies: [ 2 ]
      http_rules:
        http_rules:
        - headers: [ { name: ':path', value: '/only-2-allowed', regex: false } ]
)EOF";
  
namespace Filter {
namespace BpfMetadata {

class TestConfig : public Config {
public:
  TestConfig(const ::cilium::BpfMetadata& config, Server::Configuration::ListenerFactoryContext& context)
    : Config(config, context) {}

  bool getMetadata(Network::ConnectionSocket &socket) override {
    // fake setting the local address. It remains the same as required by the test infra, but it will be marked as restored
    // as required by the original_dst cluster.
    socket.setLocalAddress(original_dst_address, true);
    if (is_ingress_) {
      socket.addOption(std::make_shared<Cilium::SocketOption>(maps_, 1, 173, true, 80, 10000));
    } else {
      socket.addOption(std::make_shared<Cilium::SocketOption>(maps_, 173, hosts_->resolve(socket.localAddress()->ip()), false, 80, 10001));
    }
    return true;
  }
};

typedef std::shared_ptr<TestConfig> TestConfigSharedPtr;

class TestInstance : public Instance {
public:
  TestInstance(TestConfigSharedPtr config) : Instance(config) {}
};

} // namespace BpfMetadata
} // namespace Filter

namespace Server {
namespace Configuration {

namespace {

std::shared_ptr<const Cilium::PolicyHostMap>
createHostMap(const std::string& config, Server::Configuration::ListenerFactoryContext& context) {
  return context.singletonManager().getTyped<const Cilium::PolicyHostMap>(
      "cilium_host_map_singleton", [&config, &context] {
	std::string path = TestEnvironment::writeStringToFileForTest("host_map.yaml", config);
	ENVOY_LOG_MISC(debug, "Loading Cilium Host Map from file \'{}\' instead of using gRPC",
		       path);

        Envoy::Config::Utility::checkFilesystemSubscriptionBackingPath(path);
        Envoy::Config::SubscriptionStats stats =
	  Envoy::Config::Utility::generateStats(context.scope());
        auto subscription =
	  std::make_unique<Envoy::Config::FilesystemSubscriptionImpl<cilium::NetworkPolicyHosts>>(
              context.dispatcher(), path, stats);
       
        auto map = std::make_shared<Cilium::PolicyHostMap>(std::move(subscription),
							   context.threadLocal());
        map->startSubscription();
        return map;
    });
}

} // namespace

/**
 * Config registration for the bpf metadata filter. @see
 * NamedNetworkFilterConfigFactory.
 */
class TestBpfMetadataConfigFactory : public NamedListenerFilterConfigFactory {
public:
  // NamedListenerFilterConfigFactory
  ListenerFilterFactoryCb
  createFilterFactoryFromProto(const Protobuf::Message& proto_config,
			       ListenerFactoryContext &context) override {
    // Create the file-based policy map before the filter is created, so that the singleton
    // is set before the gRPC subscription is attempted.
    hostmap = createHostMap(host_map_config, context);

    auto config = std::make_shared<Filter::BpfMetadata::TestConfig>(MessageUtil::downcastAndValidate<const ::cilium::BpfMetadata&>(proto_config), context);

    return [config](
               Network::ListenerFilterManager &filter_manager) mutable -> void {
      filter_manager.addAcceptFilter(
          std::make_unique<Filter::BpfMetadata::TestInstance>(config));
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<::cilium::BpfMetadata>();
  }

  std::string name() override { return "test_bpf_metadata"; }
};

/**
 * Static registration for the bpf metadata filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<TestBpfMetadataConfigFactory,
                                 NamedListenerFilterConfigFactory>
    registered_;

} // namespace Configuration
} // namespace Server

namespace Cilium {

std::shared_ptr<const Cilium::NetworkPolicyMap>
createPolicyMap(const std::string& config, Server::Configuration::FactoryContext& context) {
  return context.singletonManager().getTyped<const Cilium::NetworkPolicyMap>(
      "cilium_network_policy_singleton", [&config, &context] {
        // File subscription.
	std::string path = TestEnvironment::writeStringToFileForTest("network_policy.yaml", config);
	ENVOY_LOG_MISC(debug, "Loading Cilium Network Policy from file \'{}\' instead of using gRPC", path);
        Envoy::Config::Utility::checkFilesystemSubscriptionBackingPath(path);
        Envoy::Config::SubscriptionStats stats = Envoy::Config::Utility::generateStats(context.scope());
        auto subscription = std::make_unique<Envoy::Config::FilesystemSubscriptionImpl<cilium::NetworkPolicy>>(context.dispatcher(), path, stats);
       
        auto map = std::make_shared<Cilium::NetworkPolicyMap>(std::move(subscription), context.threadLocal());
	map->startSubscription();
	return map;
      });
}

class TestConfigFactory
    : public Server::Configuration::NamedHttpFilterConfigFactory {
public:
  Server::Configuration::HttpFilterFactoryCb
  createFilterFactory(const Json::Object&, const std::string &,
                      Server::Configuration::FactoryContext&) override {
    // json config not supported
    return [](Http::FilterChainFactoryCallbacks &) mutable -> void {};
  }

  Server::Configuration::HttpFilterFactoryCb
  createFilterFactoryFromProto(const Protobuf::Message& proto_config, const std::string&,
                               Server::Configuration::FactoryContext& context) override {
    // Create the file-based policy map before the filter is created, so that the singleton
    // is set before the gRPC subscription is attempted.
    npmap = createPolicyMap(policy_config, context);

    auto config = std::make_shared<Cilium::Config>(
        MessageUtil::downcastAndValidate<const ::cilium::L7Policy&>(proto_config), context);
    return [config](
               Http::FilterChainFactoryCallbacks &callbacks) mutable -> void {
      callbacks.addStreamFilter(std::make_shared<Cilium::AccessFilter>(config));
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<::cilium::L7Policy>();
  }

  std::string name() override { return "test_l7policy"; }
};

/**
 * Static registration for this filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<
    TestConfigFactory, Server::Configuration::NamedHttpFilterConfigFactory>
    register_;

} // namespace Cilium

// params: is_ingress ("true", "false")
const std::string cilium_proxy_config_fmt = R"EOF(
admin:
  access_log_path: /dev/null
  address:
    socket_address:
      address: 127.0.0.1
      port_value: 0
static_resources:
  clusters:
  - name: cluster1
    type: ORIGINAL_DST
    lb_policy: ORIGINAL_DST_LB
    connect_timeout:
      seconds: 1
    hosts:
    - socket_address:
        address: 127.0.0.1
        port_value: 0
  - name: xds-grpc-cilium
    connect_timeout:
      seconds: 5
    type: STATIC
    lb_policy: ROUND_ROBIN
    http2_protocol_options:
    hosts:
    - pipe:
        path: /var/run/cilium/xds.sock
  listeners:
    name: http
    address:
      socket_address:
        address: 127.0.0.1
        port_value: 0
    listener_filters:
      name: test_bpf_metadata
      config:
        is_ingress: {0}
    filter_chains:
      filters:
      - name: cilium.network
      - name: envoy.http_connection_manager
        config:
          stat_prefix: config_test
          codec_type: auto
          http_filters:
          - name: test_l7policy
            config:
              access_log_path: ""
              policy_name: "173"
          - name: envoy.router
          route_config:
            name: policy_enabled
            virtual_hosts:
              name: integration
              domains: "*"
              routes:
              - route:
                  cluster: cluster1
                match:
                  prefix: "/"
)EOF";

class CiliumIntegrationTestBase
  : public HttpIntegrationTest,
    public testing::TestWithParam<Network::Address::IpVersion> {

public:
  CiliumIntegrationTestBase(const std::string& config)
    : HttpIntegrationTest(Http::CodecClient::Type::HTTP1, GetParam(), config) {
    // Undo legacy compat rename done by HttpIntegrationTest constructor.
    // config_helper_.renameListener("cilium");
    for (Logger::Logger& logger : Logger::Registry::loggers()) {
      logger.setLevel(spdlog::level::trace);
    }
  }
  ~CiliumIntegrationTestBase() {
    npmap = nullptr;
    hostmap = nullptr;
  }  
  /**
   * Initializer for an individual integration test.
   */
  void initialize() override {
    HttpIntegrationTest::initialize();
    // Pass the fake upstream address to the cilium bpf filter that will set it as an "original destination address".
    if (GetParam() == Network::Address::IpVersion::v4) {
      original_dst_address = std::make_shared<Network::Address::Ipv4Instance>(Network::Test::getLoopbackAddressString(GetParam()), fake_upstreams_.back()->localAddress()->ip()->port());
    } else {
      original_dst_address = std::make_shared<Network::Address::Ipv6Instance>(Network::Test::getLoopbackAddressString(GetParam()), fake_upstreams_.back()->localAddress()->ip()->port());
    }
  }

  void Denied(Http::TestHeaderMapImpl headers) {
    policy_config = BASIC_POLICY;
    initialize();
    codec_client_ = makeHttpConnection(lookupPort("http"));
    codec_client_->makeHeaderOnlyRequest(headers, *response_);
    response_->waitForEndStream();

    EXPECT_STREQ("403", response_->headers().Status()->value().c_str());
  }

  void Accepted(Http::TestHeaderMapImpl headers) {
    policy_config = BASIC_POLICY;
    initialize();
    codec_client_ = makeHttpConnection(lookupPort("http"));
    sendRequestAndWaitForResponse(headers, 0, default_response_headers_, 0);

    EXPECT_STREQ("200", response_->headers().Status()->value().c_str());
  }

  void InvalidHostMap(const std::string& config, const char* exmsg) {
    std::string path = TestEnvironment::writeStringToFileForTest("host_map_fail.yaml", config);
    envoy::api::v2::DiscoveryResponse message;
    ThreadLocal::InstanceImpl tls;

    MessageUtil::loadFromFile(path, message);
    const auto typed_resources = Config::Utility::getTypedResources<cilium::NetworkPolicyHosts>(message);
    Envoy::Cilium::PolicyHostMap hmap(tls);

    EXPECT_THROW_WITH_MESSAGE(hmap.onConfigUpdate(typed_resources), EnvoyException, exmsg);
    tls.shutdownGlobalThreading();
  }
};

class CiliumIntegrationTest : public CiliumIntegrationTestBase {
public:
  CiliumIntegrationTest()
    : CiliumIntegrationTestBase(fmt::format(cilium_proxy_config_fmt, "true")) {}
};

INSTANTIATE_TEST_CASE_P(
    IpVersions, CiliumIntegrationTest,
    testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

TEST_P(CiliumIntegrationTest, HostMapValid) {
  std::string config = R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 173
  host_addresses: [ "192.168.0.1", "f00d::1" ]
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 1
  host_addresses: [ "127.0.0.1/32", "::1/128" ]
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "127.0.0.0/8", "beef::/63" ]
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 12
  host_addresses: [ "0.0.0.0/0", "::/0" ]
)EOF";

  std::string path = TestEnvironment::writeStringToFileForTest("host_map_success.yaml", config);
  envoy::api::v2::DiscoveryResponse message;
  ThreadLocal::InstanceImpl tls;

  MessageUtil::loadFromFile(path, message);
  const auto typed_resources = Config::Utility::getTypedResources<cilium::NetworkPolicyHosts>(message);
  auto hmap = std::make_shared<Envoy::Cilium::PolicyHostMap>(tls);

  VERBOSE_EXPECT_NO_THROW(hmap->onConfigUpdate(typed_resources));

  EXPECT_EQ(hmap->resolve(Network::Address::Ipv4Instance("192.168.0.1").ip()), 173);
  EXPECT_EQ(hmap->resolve(Network::Address::Ipv4Instance("192.168.0.0").ip()), 12);
  EXPECT_EQ(hmap->resolve(Network::Address::Ipv4Instance("192.168.0.2").ip()), 12);
  EXPECT_EQ(hmap->resolve(Network::Address::Ipv4Instance("127.0.0.1").ip()), 1);
  EXPECT_EQ(hmap->resolve(Network::Address::Ipv4Instance("127.0.0.2").ip()), 11);
  EXPECT_EQ(hmap->resolve(Network::Address::Ipv4Instance("126.0.0.2").ip()), 12);
  EXPECT_EQ(hmap->resolve(Network::Address::Ipv4Instance("128.0.0.0").ip()), 12);
  EXPECT_EQ(hmap->resolve(Network::Address::Ipv6Instance("::1").ip()), 1);
  EXPECT_EQ(hmap->resolve(Network::Address::Ipv6Instance("::").ip()), 12);
  EXPECT_EQ(hmap->resolve(Network::Address::Ipv6Instance("f00d::1").ip()), 173);
  EXPECT_EQ(hmap->resolve(Network::Address::Ipv6Instance("f00d::").ip()), 12);
  EXPECT_EQ(hmap->resolve(Network::Address::Ipv6Instance("beef::1.2.3.4").ip()), 11);
  EXPECT_EQ(hmap->resolve(Network::Address::Ipv6Instance("beef:0:0:1::").ip()), 11);
  EXPECT_EQ(hmap->resolve(Network::Address::Ipv6Instance("beef:0:0:1::42").ip()), 11);
  EXPECT_EQ(hmap->resolve(Network::Address::Ipv6Instance("beef:0:0:2::").ip()), 12);

  tls.shutdownGlobalThreading();
}

TEST_P(CiliumIntegrationTest, HostMapInvalidNonCIDRBits) {
  if (GetParam() == Network::Address::IpVersion::v4) {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "127.0.0.1/32", "127.0.0.1/31" ]
)EOF",
		   "NetworkPolicyHosts: Non-prefix bits set in '127.0.0.1/31'");
  } else {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "::1/128", "::1/63" ]
)EOF",
		   "NetworkPolicyHosts: Non-prefix bits set in '::1/63'");
  }
}

TEST_P(CiliumIntegrationTest, HostMapInvalidPrefixLengths) {
  if (GetParam() == Network::Address::IpVersion::v4) {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "127.0.0.1", "127.0.0.0/8", "127.0.0.1/33" ]
)EOF",
		   "NetworkPolicyHosts: Invalid prefix length in '127.0.0.1/33'");
  } else {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "::1/128", "f00f::/65", "::3/129" ]
)EOF",
		   "NetworkPolicyHosts: Invalid prefix length in '::3/129'");
  }
}

TEST_P(CiliumIntegrationTest, HostMapInvalidPrefixLengths2) {
  if (GetParam() == Network::Address::IpVersion::v4) {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "127.0.0.1", "127.0.0.0/8", "127.0.0.1/32a" ]
)EOF",
		   "NetworkPolicyHosts: Invalid prefix length in '127.0.0.1/32a'");
  } else {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "::1/128", "f00f::/65", "::3/" ]
)EOF",
		   "NetworkPolicyHosts: Invalid prefix length in '::3/'");
  }
}

TEST_P(CiliumIntegrationTest, HostMapInvalidPrefixLengths3) {
  if (GetParam() == Network::Address::IpVersion::v4) {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "127.0.0.1", "127.0.0.0/8", "127.0.0.1/ 32" ]
)EOF",
		   "NetworkPolicyHosts: Invalid prefix length in '127.0.0.1/ 32'");
  } else {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "::1/128", "f00f::/65", "::3/128 " ]
)EOF",
		   "NetworkPolicyHosts: Invalid prefix length in '::3/128 '");
  }
}

TEST_P(CiliumIntegrationTest, HostMapDuplicateEntry) {
  if (GetParam() == Network::Address::IpVersion::v4) {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "127.0.0.0/16", "127.0.0.1/32", "127.0.0.1" ]
)EOF",
		   "NetworkPolicyHosts: Duplicate host entry '127.0.0.1' for policy 11, already mapped to 11");
  } else {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "::1/128", "f00f::/65", "::1" ]
)EOF",
		   "NetworkPolicyHosts: Duplicate host entry '::1' for policy 11, already mapped to 11");
  }
}

TEST_P(CiliumIntegrationTest, HostMapDuplicateEntry2) {
  if (GetParam() == Network::Address::IpVersion::v4) {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "127.0.0.0/16", "127.0.0.1/32" ]
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 12
  host_addresses: [ "127.0.0.0/8", "127.0.0.1" ]
)EOF",
		   "NetworkPolicyHosts: Duplicate host entry '127.0.0.1' for policy 12, already mapped to 11");
  } else {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "::1/128", "f00f::/65" ]
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 12
  host_addresses: [ "f00f::/16", "::1" ]
)EOF",
		   "NetworkPolicyHosts: Duplicate host entry '::1' for policy 12, already mapped to 11");
  }
}

TEST_P(CiliumIntegrationTest, HostMapInvalidAddress) {
  if (GetParam() == Network::Address::IpVersion::v4) {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "127.0.0.0/16", "127.0.0.1/32", "255.256.0.0" ]
)EOF",
		   "NetworkPolicyHosts: Invalid host entry '255.256.0.0' for policy 11");
  } else {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "::1/128", "f00f::/65", "fOOd::1" ]
)EOF",
		   "NetworkPolicyHosts: Invalid host entry 'fOOd::1' for policy 11");
  }
}

TEST_P(CiliumIntegrationTest, HostMapInvalidAddress2) {
  if (GetParam() == Network::Address::IpVersion::v4) {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "127.0.0.0/16", "127.0.0.1/32", "255.255.0.0 " ]
)EOF",
		   "NetworkPolicyHosts: Invalid host entry '255.255.0.0 ' for policy 11");
  } else {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "::1/128", "f00f::/65", "f00d:: 1" ]
)EOF",
		   "NetworkPolicyHosts: Invalid host entry 'f00d:: 1' for policy 11");
  }
}

TEST_P(CiliumIntegrationTest, HostMapInvalidDefaults) {
  if (GetParam() == Network::Address::IpVersion::v4) {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "0.0.0.0/0", "128.0.0.0/0" ]
)EOF",
		   "NetworkPolicyHosts: Non-prefix bits set in '128.0.0.0/0'");
  } else {
    InvalidHostMap(R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 11
  host_addresses: [ "::/0", "8000::/0" ]
)EOF",
		   "NetworkPolicyHosts: Non-prefix bits set in '8000::/0'");
  }
}

TEST_P(CiliumIntegrationTest, DeniedPathPrefix) {
  Denied({{":method", "GET"}, {":path", "/prefix"}, {":authority", "host"}});
}

TEST_P(CiliumIntegrationTest, AllowedPathPrefix) {
  Accepted({{":method", "GET"}, {":path", "/allowed"}, {":authority", "host"}});
}

TEST_P(CiliumIntegrationTest, AllowedPathRegex) {
  Accepted({{":method", "GET"}, {":path", "/maybe/public"}, {":authority", "host"}});
}

TEST_P(CiliumIntegrationTest, DeniedPath) {
  Denied({{":method", "GET"}, {":path", "/maybe/private"}, {":authority", "host"}});
}

TEST_P(CiliumIntegrationTest, AllowedHostString) {
  Accepted({{":method", "GET"}, {":path", "/maybe/private"}, {":authority", "allowedHOST"}});
}

TEST_P(CiliumIntegrationTest, AllowedHostRegex) {
  Accepted({{":method", "GET"}, {":path", "/maybe/private"}, {":authority", "hostREGEXname"}});
}

TEST_P(CiliumIntegrationTest, DeniedMethod) {
  Denied({{":method", "POST"}, {":path", "/maybe/private"}, {":authority", "host"}});
}

TEST_P(CiliumIntegrationTest, AcceptedMethod) {
  Accepted({{":method", "PUT"}, {":path", "/public/opinions"}, {":authority", "host"}});
}

TEST_P(CiliumIntegrationTest, L3DeniedPath) {
  Denied({{":method", "GET"}, {":path", "/only-2-allowed"}, {":authority", "host"}});
}

TEST_P(CiliumIntegrationTest, DuplicatePort) {
  // This policy has a duplicate port number, and will be rejected.
  policy_config = BASIC_POLICY + R"EOF(  - port: 80
    rules:
    - remote_policies: [ 2 ]
      http_rules:
        http_rules:
        - headers: [ { name: ':path', value: '/only-2-allowed', regex: false } ]
)EOF";

  // This would normally be allowed, but since the policy fails, everything will be rejected.
  Http::TestHeaderMapImpl headers =
    {{":method", "GET"}, {":path", "/allowed"}, {":authority", "host"}};
  initialize();
  codec_client_ = makeHttpConnection(lookupPort("http"));
  codec_client_->makeHeaderOnlyRequest(headers, *response_);
  response_->waitForEndStream();

  EXPECT_STREQ("403", response_->headers().Status()->value().c_str());
}

class CiliumIntegrationEgressTest : public CiliumIntegrationTestBase {
public:
  CiliumIntegrationEgressTest()
    : CiliumIntegrationTestBase(fmt::format(cilium_proxy_config_fmt, "false")) {
    host_map_config = R"EOF(version_info: "0"
resources:
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 173
  host_addresses: [ "192.168.0.1", "f00d::1" ]
- "@type": type.googleapis.com/cilium.NetworkPolicyHosts
  policy: 1
  host_addresses: [ "127.0.0.0/8", "::/104" ]
)EOF";

  }
};

INSTANTIATE_TEST_CASE_P(
    IpVersions, CiliumIntegrationEgressTest,
    testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

TEST_P(CiliumIntegrationEgressTest, DeniedPathPrefix) {
  Denied({{":method", "GET"}, {":path", "/prefix"}, {":authority", "host"}});
}

TEST_P(CiliumIntegrationEgressTest, AllowedPathPrefix) {
  Accepted({{":method", "GET"}, {":path", "/allowed"}, {":authority", "host"}});
}

TEST_P(CiliumIntegrationEgressTest, AllowedPathRegex) {
  Accepted({{":method", "GET"}, {":path", "/maybe/public"}, {":authority", "host"}});
}

TEST_P(CiliumIntegrationEgressTest, DeniedPath) {
  Denied({{":method", "GET"}, {":path", "/maybe/private"}, {":authority", "host"}});
}

TEST_P(CiliumIntegrationEgressTest, AllowedHostString) {
  Accepted({{":method", "GET"}, {":path", "/maybe/private"}, {":authority", "allowedHOST"}});
}

TEST_P(CiliumIntegrationEgressTest, AllowedHostRegex) {
  Accepted({{":method", "GET"}, {":path", "/maybe/private"}, {":authority", "hostREGEXname"}});
}

TEST_P(CiliumIntegrationEgressTest, DeniedMethod) {
  Denied({{":method", "POST"}, {":path", "/maybe/private"}, {":authority", "host"}});
}

TEST_P(CiliumIntegrationEgressTest, AcceptedMethod) {
  Accepted({{":method", "PUT"}, {":path", "/public/opinions"}, {":authority", "host"}});
}

TEST_P(CiliumIntegrationEgressTest, L3DeniedPath) {
  Denied({{":method", "GET"}, {":path", "/only-2-allowed"}, {":authority", "host"}});
}


} // namespace Envoy
