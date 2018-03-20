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
#include "server/config/network/http_connection_manager.h"

#include "test/integration/http_integration.h"

#include "cilium_bpf_metadata.h"
#include "cilium_l7policy.h"
#include "cilium_network_policy.h"
#include "cilium_socket_option.h"
#include "cilium/cilium_bpf_metadata.pb.validate.h"
#include "cilium/cilium_l7policy.pb.validate.h"

namespace Envoy {

Network::Address::InstanceConstSharedPtr original_dst_address;
std::string policy_path;
std::shared_ptr<const Cilium::NetworkPolicyMap> npmap;
  
namespace Filter {
namespace BpfMetadata {

class TestConfig : public Config {
public:
  TestConfig(const ::cilium::BpfMetadata& config, Stats::Scope& scope)
    : Config(config, scope),
      socket_mark_(std::make_shared<Cilium::SocketOption>(42, 1, true, 80)) {}

  Network::Socket::OptionsSharedPtr socket_mark_;
};

typedef std::shared_ptr<TestConfig> TestConfigSharedPtr;

class TestInstance : public Instance {
public:
  TestInstance(TestConfigSharedPtr config)
    : Instance(config), test_config_(config.get()) {}

  bool getBpfMetadata(Network::ConnectionSocket &socket) override {
    // fake setting the local address. It remains the same as required by the test infra, but it will be marked as restored
    // as required by the original_dst cluster.
    socket.setLocalAddress(original_dst_address, true);
    socket.setOptions(test_config_->socket_mark_);
    return true;
  }

  TestConfig *test_config_;
};

} // namespace BpfMetadata
} // namespace Filter

namespace Server {
namespace Configuration {

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
    Filter::BpfMetadata::TestConfigSharedPtr config(
        new Filter::BpfMetadata::TestConfig(MessageUtil::downcastAndValidate<const ::cilium::BpfMetadata&>(proto_config), context.scope()));

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
createPolicyMap(const std::string& path, Server::Configuration::FactoryContext& context) {
  return context.singletonManager().getTyped<const Cilium::NetworkPolicyMap>(
      "cilium_network_policy_singleton", [&path, &context] {
        // File subscription.
	ENVOY_LOG_MISC(debug, "Loading Cilium Network Policy from file \'{}\' instead of using gRPC", path);
        Envoy::Config::Utility::checkFilesystemSubscriptionBackingPath(path);
        Envoy::Config::SubscriptionStats stats = Envoy::Config::Utility::generateStats(context.scope());
        auto subscription = std::make_unique<Envoy::Config::FilesystemSubscriptionImpl<cilium::NetworkPolicy>>(context.dispatcher(), path, stats);
       
        return std::make_shared<Cilium::NetworkPolicyMap>(std::move(subscription), context.threadLocal());
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
    npmap = createPolicyMap(policy_path, context);

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
  
const std::string cilium_proxy_config = R"EOF(
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
  - name: xds_cluster
    connect_timeout: { seconds: 5 }
    type: STATIC
    lb_policy: ROUND_ROBIN
    http2_protocol_options: {}
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
        is_ingress: true
    filter_chains:
      filters:
        name: envoy.http_connection_manager
        config:
          stat_prefix: config_test
          codec_type: auto
          http_filters:
          - name: test_l7policy
            config:
              access_log_path: ""
              listener_id: foo42
              policy_name: "173"
              api_config_source:
                api_type: GRPC
                cluster_names: xds_cluster
          - name: envoy.router
          route_config:
            name: policy_enabled
            virtual_hosts:
              name: integration
              domains: "*"
              routes:
              - route: { cluster: cluster1 }
                match: { prefix: "/" }
)EOF";

class CiliumIntegrationTest
    : public HttpIntegrationTest,
      public testing::TestWithParam<Network::Address::IpVersion> {

public:
  CiliumIntegrationTest()
    : HttpIntegrationTest(Http::CodecClient::Type::HTTP1, GetParam(), cilium_proxy_config) {
    // Undo legacy compat rename done by HttpIntegrationTest constructor.
    // config_helper_.renameListener("cilium");
    for (const Logger::Logger& logger : Logger::Registry::loggers()) {
      logger.setLevel(static_cast<spdlog::level::level_enum>(0));
    }
  }
  ~CiliumIntegrationTest() {
    npmap = nullptr;
  }  
  /**
   * Initializer for an individual integration test.
   */
  void initialize() override {
    HttpIntegrationTest::initialize();
    // Pass the fake upstream address to the cilium bpf filter that will set it as an "original destination address".
    original_dst_address = fake_upstreams_.back()->localAddress();
  }

  void Denied(Http::TestHeaderMapImpl headers) {
    policy_path = "./cilium_network_policy_test.yaml";
    initialize();
    codec_client_ = makeHttpConnection(lookupPort("http"));
    codec_client_->makeHeaderOnlyRequest(headers, *response_);
    response_->waitForEndStream();

    EXPECT_STREQ("403", response_->headers().Status()->value().c_str());
  }

  void Accepted(Http::TestHeaderMapImpl headers) {
    policy_path = "./cilium_network_policy_test.yaml";
    initialize();
    codec_client_ = makeHttpConnection(lookupPort("http"));
    sendRequestAndWaitForResponse(headers, 0, default_response_headers_, 0);

    EXPECT_STREQ("200", response_->headers().Status()->value().c_str());
  }
};

INSTANTIATE_TEST_CASE_P(
    IpVersions, CiliumIntegrationTest,
    testing::ValuesIn(TestEnvironment::getIpVersionsForTest()));

TEST_P(CiliumIntegrationTest, DeniedPathPrefix) {
  Denied({{":method", "GET"}, {":path", "/prefix"}, {":authority", "host"}});
}

TEST_P(CiliumIntegrationTest, AllowedPathPrefix) {
  Accepted({{":method", "GET"}, {":path", "/allowed"}, {":authority", "host"}});
}

TEST_P(CiliumIntegrationTest, AllowedPathRegex) {
  Accepted(
      {{":method", "GET"}, {":path", "/maybe/public"}, {":authority", "host"}});
}

TEST_P(CiliumIntegrationTest, DeniedPath) {
  Denied({{":method", "GET"},
          {":path", "/maybe/private"},
          {":authority", "host"}});
}

TEST_P(CiliumIntegrationTest, AllowedHostString) {
  Accepted({{":method", "GET"},
            {":path", "/maybe/private"},
            {":authority", "allowedHOST"}});
}

TEST_P(CiliumIntegrationTest, AllowedHostRegex) {
  Accepted({{":method", "GET"},
            {":path", "/maybe/private"},
            {":authority", "hostREGEXname"}});
}

TEST_P(CiliumIntegrationTest, DeniedMethod) {
  Denied({{":method", "POST"},
          {":path", "/maybe/private"},
          {":authority", "host"}});
}

TEST_P(CiliumIntegrationTest, AcceptedMethod) {
  Accepted({{":method", "PUT"},
            {":path", "/public/opinions"},
            {":authority", "host"}});
}

TEST_P(CiliumIntegrationTest, L3DeniedPath) {
  Denied({{":method", "GET"},
          {":path", "/only-2-allowed"},
          {":authority", "host"}});
}

TEST_P(CiliumIntegrationTest, DuplicatePort) {
  // This policy has a duplicate port number, and will be rejected.
  policy_path = "./cilium_network_policy_test_dup_port.yaml";

  // This would normally be allowed, but since the policy fails, everything will be rejected.
  Http::TestHeaderMapImpl headers =
    {{":method", "GET"}, {":path", "/allowed"}, {":authority", "host"}};
  initialize();
  codec_client_ = makeHttpConnection(lookupPort("http"));
  codec_client_->makeHeaderOnlyRequest(headers, *response_);
  response_->waitForEndStream();

  EXPECT_STREQ("403", response_->headers().Status()->value().c_str());
}

} // namespace Envoy
