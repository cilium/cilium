#include "accesslog.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
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

class AccessLogServer : Logger::Loggable<Logger::Id::router> {
public:
  AccessLogServer(const std::string path) : path_(path), fd2_(-1) {
    ENVOY_LOG(critical, "Creating access log server: {}", path_);
    ::unlink(path_.c_str());
    fd_ = ::socket(AF_UNIX, SOCK_SEQPACKET, 0);
    if (fd_ == -1) {
      ENVOY_LOG(error, "Can't create socket: {}", strerror(errno));
      return;
    }

    ENVOY_LOG(critical, "Binding to {}", path_);
    struct sockaddr_un addr = {.sun_family = AF_UNIX, .sun_path = {}};
    strncpy(addr.sun_path, path_.c_str(), sizeof(addr.sun_path) - 1);
    if (::bind(fd_, reinterpret_cast<struct sockaddr *>(&addr),
	       sizeof(addr)) == -1) {
      ENVOY_LOG(warn, "Bind to {} failed: {}", path_, strerror(errno));
      Close();
      return;
    }

    ENVOY_LOG(critical, "Listening on {}", path_);
    if (::listen(fd_, 5) == -1) {
      ENVOY_LOG(warn, "Listen on {} failed: {}", path_, strerror(errno));
      Close();
      return;
    }

    ENVOY_LOG(critical, "Starting access log server thread fd: {}", fd_);

    thread_.reset(new Thread::Thread([this]() -> void { threadRoutine(); }));
  }

  ~AccessLogServer() {
    if (fd_ >= 0) {
      Close();
      ENVOY_LOG(warn, "Waiting on access log to close: {}", strerror(errno));
      thread_->join();
      thread_.reset();
    }
  }
private:
  void Close() {
    ::shutdown(fd_, SHUT_RD);
    ::shutdown(fd2_, SHUT_RD);
    errno = 0;
    ::close(fd_);
    fd_ = -1;
    ::unlink(path_.c_str());
  }

  void threadRoutine() {
    while (fd_ >= 0) {
      ENVOY_LOG(critical, "Access Log thread started on fd: {}", fd_);
      // Accept a new connection
      struct sockaddr_un addr;
      socklen_t addr_len;
      ENVOY_LOG(warn, "Access log blocking accept on fd: {}", fd_);
      fd2_ = ::accept(fd_, reinterpret_cast<sockaddr*>(&addr), &addr_len);
      if (fd2_ < 0) {
	ENVOY_LOG(critical, "Access log accept failed: {}", strerror(errno));
      } else {
	char buf[8192];
	while (true) {
	  ENVOY_LOG(warn, "Access log blocking recv on fd: {}", fd2_);
	  ssize_t received = ::recv(fd2_, buf, sizeof(buf), 0);
	  if (received < 0) {
	    ENVOY_LOG(warn, "Access log recv failed: {}", strerror(errno));
	    break;
	  } else if (received == 0) {
	    ENVOY_LOG(warn, "Access log recv got no data!");
	    break;
	  } else {
	    std::string data(buf, received);
	    ::cilium::LogEntry entry;
	    if (!entry.ParseFromString(data)) {
	      ENVOY_LOG(warn, "Access log parse failed!");
	    } else {
	      if (entry.method().length() > 0) {
		ENVOY_LOG(warn, "Access log deprecated format detected");
		// Deprecated format detected, map to the new one
		auto http = entry.mutable_http();
		http->set_http_protocol(entry.http_protocol());
		entry.clear_http_protocol();
		http->set_scheme(entry.scheme());
		entry.clear_scheme();
		http->set_host(entry.host());
		entry.clear_host();
		http->set_path(entry.path());
		entry.clear_path();
		http->set_method(entry.method());
		entry.clear_method();
		for (const auto& dep_hdr: entry.headers()) {
		  auto hdr = http->add_headers();
		  hdr->set_key(dep_hdr.key());
		  hdr->set_value(dep_hdr.value());
		}
		entry.clear_headers();
		http->set_status(entry.status());
		entry.clear_status();
	      }
	      ENVOY_LOG(info, "Access log entry: {}", entry.DebugString());
	    }
	  }
	}
	::close(fd2_);
	fd2_ = -1;
      }
    };
  }

  const std::string path_;
  std::atomic<int> fd_;
  std::atomic<int> fd2_;
  Thread::ThreadPtr thread_;
};

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
        - headers: [ { name: ':path', exact_match: '/allowed' } ]
        - headers: [ { name: ':path', regex_match: '.*public$' } ]
        - headers: [ { name: ':authority', exact_match: 'allowedHOST' } ]
        - headers: [ { name: ':authority', regex_match: '.*REGEX.*' } ]
        - headers: [ { name: ':method', exact_match: 'PUT' }, { name: ':path', exact_match: '/public/opinions' } ]
    - remote_policies: [ 2 ]
      http_rules:
        http_rules:
        - headers: [ { name: ':path', exact_match: '/only-2-allowed' } ]
  egress_per_port_policies:
  - port: 80
    rules:
    - remote_policies: [ 1 ]
      http_rules:
        http_rules:
        - headers: [ { name: ':path', exact_match: '/allowed' } ]
        - headers: [ { name: ':path', regex_match: '.*public$' } ]
        - headers: [ { name: ':authority', exact_match: 'allowedHOST' } ]
        - headers: [ { name: ':authority', regex_match: '.*REGEX.*' } ]
        - headers: [ { name: ':method', exact_match: 'PUT' }, { name: ':path', exact_match: '/public/opinions' } ]
    - remote_policies: [ 2 ]
      http_rules:
        http_rules:
        - headers: [ { name: ':path', exact_match: '/only-2-allowed' } ]
)EOF";

namespace Filter {
namespace BpfMetadata {

class TestConfig : public Config {
public:
  TestConfig(const ::cilium::BpfMetadata& config, Server::Configuration::ListenerFactoryContext& context)
    : Config(config, context) {}
  ~TestConfig() {
    hostmap.reset();
  }

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

class TestInstance : public Instance {
public:
  TestInstance(const ConfigSharedPtr& config) : Instance(config) {}
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
  Network::ListenerFilterFactoryCb
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
  Http::FilterFactoryCb
  createFilterFactory(const Json::Object&, const std::string &,
                      Server::Configuration::FactoryContext&) override {
    // json config not supported
    return [](Http::FilterChainFactoryCallbacks &) mutable -> void {};
  }

  Http::FilterFactoryCb
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
        config:
          proxylib: "proxylib/libcilium.so"
          l7_proto: "test.passer"
      - name: envoy.http_connection_manager
        config:
          stat_prefix: config_test
          codec_type: auto
          http_filters:
          - name: test_l7policy
            config:
              access_log_path: "{{ test_udsdir }}/access_log.sock"
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
                  max_grpc_timeout:
                    seconds: 0
                    nanos: 0
                match:
                  prefix: "/"
)EOF";

class CiliumHttpIntegrationTest
  : public HttpIntegrationTest,
    public testing::TestWithParam<Network::Address::IpVersion> {

public:
  CiliumHttpIntegrationTest(const std::string& config)
    : HttpIntegrationTest(Http::CodecClient::Type::HTTP1, GetParam(), config),
      accessLogServer_(TestEnvironment::unixDomainSocketPath("access_log.sock")) {
    // Undo legacy compat rename done by HttpIntegrationTest constructor.
    // config_helper_.renameListener("cilium");
    for (Logger::Logger& logger : Logger::Registry::loggers()) {
      logger.setLevel(spdlog::level::trace);
    }
  }
  ~CiliumHttpIntegrationTest() {
    npmap.reset();
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

  void Denied(Http::TestHeaderMapImpl&& headers) {
    policy_config = BASIC_POLICY;
    initialize();
    codec_client_ = makeHttpConnection(lookupPort("http"));
    auto response = codec_client_->makeHeaderOnlyRequest(headers);
    response->waitForEndStream();

    EXPECT_STREQ("403", response->headers().Status()->value().c_str());
  }

  void Accepted(Http::TestHeaderMapImpl&& headers) {
    policy_config = BASIC_POLICY;
    initialize();
    codec_client_ = makeHttpConnection(lookupPort("http"));
    auto response = sendRequestAndWaitForResponse(headers, 0, default_response_headers_, 0);

    EXPECT_STREQ("200", response->headers().Status()->value().c_str());
  }

  void InvalidHostMap(const std::string& config, const char* exmsg) {
    std::string path = TestEnvironment::writeStringToFileForTest("host_map_fail.yaml", config);
    envoy::api::v2::DiscoveryResponse message;
    ThreadLocal::InstanceImpl tls;

    MessageUtil::loadFromFile(path, message);
    const auto typed_resources = Config::Utility::getTypedResources<cilium::NetworkPolicyHosts>(message);
    Envoy::Cilium::PolicyHostMap hmap(tls);

    EXPECT_THROW_WITH_MESSAGE(hmap.onConfigUpdate(typed_resources, "1"), EnvoyException, exmsg);
    tls.shutdownGlobalThreading();
  }

  AccessLogServer accessLogServer_;
};

class CiliumIntegrationTest : public CiliumHttpIntegrationTest {
public:
  CiliumIntegrationTest()
    : CiliumHttpIntegrationTest(fmt::format(TestEnvironment::substitute(cilium_proxy_config_fmt, GetParam()), "true")) {}
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

  VERBOSE_EXPECT_NO_THROW(hmap->onConfigUpdate(typed_resources, "2"));

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

TEST_P(CiliumIntegrationTest, AllowedPathPrefixStrippedHeader) {
  Accepted({{":method", "GET"}, {":path", "/allowed"}, {":authority", "host"},
            {"x-envoy-original-dst-host", "1.1.1.1:9999"}});
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
  auto response = codec_client_->makeHeaderOnlyRequest(headers);
  response->waitForEndStream();

  EXPECT_STREQ("403", response->headers().Status()->value().c_str());
}

class CiliumIntegrationEgressTest : public CiliumHttpIntegrationTest {
public:
  CiliumIntegrationEgressTest()
    : CiliumHttpIntegrationTest(fmt::format(TestEnvironment::substitute(cilium_proxy_config_fmt, GetParam()), "false")) {
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

//
// Cilium filters with TCP proxy
//

// params: is_ingress ("true", "false")
const std::string cilium_tcp_proxy_config_fmt = R"EOF(
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
    name: listener_0
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
        config:
          proxylib: "proxylib/libcilium.so"
          l7_proto: "test.passer"
      - name: envoy.tcp_proxy
        config:
          stat_prefix: tcp_stats
          cluster: cluster1
)EOF";

class CiliumTcpIntegrationTest : public BaseIntegrationTest,
                                 public testing::TestWithParam<Network::Address::IpVersion> {
public:
  CiliumTcpIntegrationTest(const std::string& config)
    : BaseIntegrationTest(GetParam(), config),
      accessLogServer_(TestEnvironment::unixDomainSocketPath("access_log.sock")) {
    enable_half_close_ = true;
  }

  void initialize() override {
    config_helper_.renameListener("tcp_proxy");
    BaseIntegrationTest::initialize();
    // Pass the fake upstream address to the cilium bpf filter that will set it as an "original destination address".
    if (GetParam() == Network::Address::IpVersion::v4) {
      original_dst_address = std::make_shared<Network::Address::Ipv4Instance>(Network::Test::getLoopbackAddressString(GetParam()), fake_upstreams_.back()->localAddress()->ip()->port());
    } else {
      original_dst_address = std::make_shared<Network::Address::Ipv6Instance>(Network::Test::getLoopbackAddressString(GetParam()), fake_upstreams_.back()->localAddress()->ip()->port());
    }
  }

  void TearDown() override {
    test_server_.reset();
    fake_upstreams_.clear();
    npmap.reset();
  }

  AccessLogServer accessLogServer_;
};

class CiliumTcpProxyIntegrationTest : public CiliumTcpIntegrationTest {
public:
  CiliumTcpProxyIntegrationTest() : CiliumTcpIntegrationTest(fmt::format(TestEnvironment::substitute(cilium_tcp_proxy_config_fmt, GetParam()), "true")) {}
};

INSTANTIATE_TEST_CASE_P(IpVersions, CiliumTcpProxyIntegrationTest,
                        testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                        TestUtility::ipTestParamsToString);

// Test upstream writing before downstream downstream does.
TEST_P(CiliumTcpProxyIntegrationTest, CiliumTcpProxyUpstreamWritesFirst) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(fake_upstream_connection->write("hello"));
  tcp_client->waitForData("hello");

  tcp_client->write("hello");
  ASSERT_TRUE(fake_upstream_connection->waitForData(5));

  ASSERT_TRUE(fake_upstream_connection->write("", true));
  tcp_client->waitForHalfClose();
  tcp_client->write("", true);
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

// Test proxying data in both directions, and that all data is flushed properly
// when there is an upstream disconnect.
TEST_P(CiliumTcpProxyIntegrationTest, CiliumTcpProxyUpstreamDisconnect) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  tcp_client->write("hello");
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(fake_upstream_connection->waitForData(5));
  ASSERT_TRUE(fake_upstream_connection->write("world"));
  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
  tcp_client->waitForHalfClose();
  tcp_client->close();

  EXPECT_EQ("world", tcp_client->data());
}

// Test proxying data in both directions, and that all data is flushed properly
// when the client disconnects.
TEST_P(CiliumTcpProxyIntegrationTest, CiliumTcpProxyDownstreamDisconnect) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  tcp_client->write("hello");
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(fake_upstream_connection->waitForData(5));
  ASSERT_TRUE(fake_upstream_connection->write("world"));
  tcp_client->waitForData("world");
  tcp_client->write("hello", true);
  ASSERT_TRUE(fake_upstream_connection->waitForData(10));
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->write("", true));
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect(true));
  tcp_client->waitForDisconnect();
}

TEST_P(CiliumTcpProxyIntegrationTest, CiliumTcpProxyLargeWrite) {
  config_helper_.setBufferLimits(1024, 1024);
  initialize();

  std::string data(1024 * 16, 'a');
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  tcp_client->write(data);
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(fake_upstream_connection->waitForData(data.size()));
  ASSERT_TRUE(fake_upstream_connection->write(data));
  tcp_client->waitForData(data);
  tcp_client->close();
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());

  uint32_t upstream_pauses =
      test_server_->counter("cluster.cluster1.upstream_flow_control_paused_reading_total")
          ->value();
  uint32_t upstream_resumes =
      test_server_->counter("cluster.cluster1.upstream_flow_control_resumed_reading_total")
          ->value();
  EXPECT_EQ(upstream_pauses, upstream_resumes);

  uint32_t downstream_pauses =
      test_server_->counter("tcp.tcp_stats.downstream_flow_control_paused_reading_total")->value();
  uint32_t downstream_resumes =
      test_server_->counter("tcp.tcp_stats.downstream_flow_control_resumed_reading_total")->value();
  EXPECT_EQ(downstream_pauses, downstream_resumes);
}

// Test that a downstream flush works correctly (all data is flushed)
TEST_P(CiliumTcpProxyIntegrationTest, CiliumTcpProxyDownstreamFlush) {
  // Use a very large size to make sure it is larger than the kernel socket read buffer.
  const uint32_t size = 50 * 1024 * 1024;
  config_helper_.setBufferLimits(size / 4, size / 4);
  initialize();

  std::string data(size, 'a');
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  tcp_client->readDisable(true);
  tcp_client->write("", true);

  // This ensures that readDisable(true) has been run on it's thread
  // before tcp_client starts writing.
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());

  ASSERT_TRUE(fake_upstream_connection->write(data, true));

  test_server_->waitForCounterGe("cluster.cluster1.upstream_flow_control_paused_reading_total", 1);
  EXPECT_EQ(test_server_->counter("cluster.cluster1.upstream_flow_control_resumed_reading_total")
                ->value(),
            0);
  tcp_client->readDisable(false);
  tcp_client->waitForData(data);
  tcp_client->waitForHalfClose();
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());

  uint32_t upstream_pauses =
      test_server_->counter("cluster.cluster1.upstream_flow_control_paused_reading_total")
          ->value();
  uint32_t upstream_resumes =
      test_server_->counter("cluster.cluster1.upstream_flow_control_resumed_reading_total")
          ->value();
  EXPECT_GE(upstream_pauses, upstream_resumes);
  EXPECT_GT(upstream_resumes, 0);
}

// Test that an upstream flush works correctly (all data is flushed)
TEST_P(CiliumTcpProxyIntegrationTest, CiliumTcpProxyUpstreamFlush) {
  // Use a very large size to make sure it is larger than the kernel socket read buffer.
  const uint32_t size = 50 * 1024 * 1024;
  config_helper_.setBufferLimits(size, size);
  initialize();

  std::string data(size, 'a');
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(fake_upstream_connection->readDisable(true));
  ASSERT_TRUE(fake_upstream_connection->write("", true));

  // This ensures that fake_upstream_connection->readDisable has been run on it's thread
  // before tcp_client starts writing.
  tcp_client->waitForHalfClose();

  tcp_client->write(data, true);

  test_server_->waitForGaugeEq("tcp.tcp_stats.upstream_flush_active", 1);
  ASSERT_TRUE(fake_upstream_connection->readDisable(false));
  ASSERT_TRUE(fake_upstream_connection->waitForData(data.size()));
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
  tcp_client->waitForHalfClose();

  EXPECT_EQ(test_server_->counter("tcp.tcp_stats.upstream_flush_total")->value(), 1);
  EXPECT_EQ(test_server_->gauge("tcp.tcp_stats.upstream_flush_active")->value(), 0);
}

// Test that Envoy doesn't crash or assert when shutting down with an upstream flush active
TEST_P(CiliumTcpProxyIntegrationTest, CiliumTcpProxyUpstreamFlushEnvoyExit) {
  // Use a very large size to make sure it is larger than the kernel socket read buffer.
  const uint32_t size = 50 * 1024 * 1024;
  config_helper_.setBufferLimits(size, size);
  initialize();

  std::string data(size, 'a');
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(fake_upstream_connection->readDisable(true));
  ASSERT_TRUE(fake_upstream_connection->write("", true));

  // This ensures that fake_upstream_connection->readDisable has been run on it's thread
  // before tcp_client starts writing.
  tcp_client->waitForHalfClose();

  tcp_client->write(data, true);

  test_server_->waitForGaugeEq("tcp.tcp_stats.upstream_flush_active", 1);
  test_server_.reset();
  ASSERT_TRUE(fake_upstream_connection->close());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());

  // Success criteria is that no ASSERTs fire and there are no leaks.
}

//
// Cilium Go test parser "linetester" with TCP proxy
//

// params: is_ingress ("true", "false")
const std::string cilium_linetester_config_fmt = R"EOF(
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
    name: listener_0
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
        config:
          proxylib: "proxylib/libcilium.so"
          l7_proto: "test.lineparser"
      - name: envoy.tcp_proxy
        config:
          stat_prefix: tcp_stats
          cluster: cluster1
)EOF";

class CiliumGoLinetesterIntegrationTest : public CiliumTcpIntegrationTest {
public:
  CiliumGoLinetesterIntegrationTest() : CiliumTcpIntegrationTest(fmt::format(TestEnvironment::substitute(cilium_linetester_config_fmt, GetParam()), "true")) {}
};

INSTANTIATE_TEST_CASE_P(IpVersions, CiliumGoLinetesterIntegrationTest,
                        testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                        TestUtility::ipTestParamsToString);

static FakeRawConnection::ValidatorFunction noMatch(const char* data_to_not_match) {
  return [data_to_not_match](const std::string& data) -> bool {
    auto found = data.find(data_to_not_match);
    return found == std::string::npos;
  };
}

TEST_P(CiliumGoLinetesterIntegrationTest, CiliumGoLineParserUpstreamWritesFirst) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(fake_upstream_connection->write("DROP reply direction\n"));
  ASSERT_TRUE(fake_upstream_connection->write("PASS reply direction\n"));
  tcp_client->waitForData("PASS reply direction\n");

  tcp_client->write("PASS original direction\n");
  ASSERT_TRUE(fake_upstream_connection->waitForData(FakeRawConnection::waitForInexactMatch("PASS")));

  ASSERT_TRUE(fake_upstream_connection->write("", true));
  tcp_client->waitForHalfClose();
  tcp_client->write("", true);
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

TEST_P(CiliumGoLinetesterIntegrationTest, CiliumGoLineParserPartialLines) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(fake_upstream_connection->write("DROP reply "));
  std::this_thread::sleep_for(std::chrono::milliseconds(10));
  ASSERT_TRUE(fake_upstream_connection->write("direction\nPASS"));
  std::this_thread::sleep_for(std::chrono::milliseconds(10));
  ASSERT_TRUE(fake_upstream_connection->write(" reply direction\n"));
  tcp_client->waitForData("PASS reply direction\n");

  tcp_client->write("PASS original direction\n");
  ASSERT_TRUE(fake_upstream_connection->waitForData(FakeRawConnection::waitForInexactMatch("PASS original direction\n")));

  ASSERT_TRUE(fake_upstream_connection->write("", true));
  tcp_client->waitForHalfClose();
  tcp_client->write("", true);
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

TEST_P(CiliumGoLinetesterIntegrationTest, CiliumGoLineParserInject) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  tcp_client->write("INJECT reply direction\n");
  tcp_client->write("PASS original direction\n");
  ASSERT_TRUE(fake_upstream_connection->write("PASS reply direction\n"));

  // These can in principle arrive in either order
  tcp_client->waitForData("PASS reply direction\n", false);
  tcp_client->waitForData("INJECT reply direction\n", false);

  ASSERT_TRUE(fake_upstream_connection->waitForData(FakeRawConnection::waitForInexactMatch("PASS original direction\n")));

  ASSERT_TRUE(fake_upstream_connection->write("", true));
  tcp_client->waitForHalfClose();
  tcp_client->write("", true);
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

TEST_P(CiliumGoLinetesterIntegrationTest, CiliumGoLineParserInjectPartial) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(fake_upstream_connection->write("PASS reply"));
  tcp_client->write("INJECT reply direction\n");
  tcp_client->write("PASS original direction\n");

  ASSERT_TRUE(fake_upstream_connection->write(" direction\n"));

  // These can in principle arrive in either order
  tcp_client->waitForData("PASS reply direction\n", false);
  tcp_client->waitForData("INJECT reply direction\n", false);

  ASSERT_TRUE(fake_upstream_connection->waitForData(FakeRawConnection::waitForInexactMatch("PASS original direction\n")));

  ASSERT_TRUE(fake_upstream_connection->write("", true));
  tcp_client->waitForHalfClose();
  tcp_client->write("", true);
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

TEST_P(CiliumGoLinetesterIntegrationTest, CiliumGoLineParserInjectPartialMultiple) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(fake_upstream_connection->write("PASS reply"));
  tcp_client->write("INJECT reply direction\n");
  tcp_client->write("DROP original direction\n");
  tcp_client->write("INSERT original direction\n");

  ASSERT_TRUE(fake_upstream_connection->write(" direction\n"));

  // These can in principle arrive in either order
  std::this_thread::sleep_for(std::chrono::milliseconds(10));
  tcp_client->waitForData("PASS reply direction\n", false);
  std::this_thread::sleep_for(std::chrono::milliseconds(10));
  tcp_client->waitForData("INJECT reply direction\n", false);

  ASSERT_TRUE(fake_upstream_connection->waitForData(FakeRawConnection::waitForInexactMatch("INSERT original direction\n")));
  ASSERT_TRUE(fake_upstream_connection->waitForData(noMatch("DROP")));

  ASSERT_TRUE(fake_upstream_connection->write("DROP reply direction\n"));
  ASSERT_TRUE(fake_upstream_connection->write("PASS2 reply direction\n"));
  tcp_client->waitForData("PASS2 reply direction\n", false);
  
  ASSERT_TRUE(fake_upstream_connection->write("", true));
  tcp_client->waitForHalfClose();
  tcp_client->write("", true);
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

//
// Cilium Go test parser "blocktester" with TCP proxy
//

// params: is_ingress ("true", "false")
const std::string cilium_blocktester_config_fmt = R"EOF(
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
    name: listener_0
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
        config:
          proxylib: "proxylib/libcilium.so"
          proxylib_params:
            access-log-path: "{{ test_udsdir }}/access_log.sock"
          l7_proto: "test.blockparser"
          policy_name: "FooBar"
      - name: envoy.tcp_proxy
        config:
          stat_prefix: tcp_stats
          cluster: cluster1
)EOF";

class CiliumGoBlocktesterIntegrationTest : public CiliumTcpIntegrationTest {
public:
  CiliumGoBlocktesterIntegrationTest() : CiliumTcpIntegrationTest(fmt::format(TestEnvironment::substitute(cilium_blocktester_config_fmt, GetParam()), "true")) {}
};

INSTANTIATE_TEST_CASE_P(IpVersions, CiliumGoBlocktesterIntegrationTest,
                        testing::ValuesIn(TestEnvironment::getIpVersionsForTest()),
                        TestUtility::ipTestParamsToString);

TEST_P(CiliumGoBlocktesterIntegrationTest, CiliumGoBlockParserUpstreamWritesFirst) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(fake_upstream_connection->write("24:DROP reply direction\n"));
  ASSERT_TRUE(fake_upstream_connection->write("24:PASS reply direction\n"));
  tcp_client->waitForData("24:PASS reply direction\n");

  tcp_client->write("27:PASS original direction\n");
  ASSERT_TRUE(fake_upstream_connection->waitForData(FakeRawConnection::waitForInexactMatch("PASS")));

  ASSERT_TRUE(fake_upstream_connection->write("", true));
  tcp_client->waitForHalfClose();
  tcp_client->write("", true);
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

TEST_P(CiliumGoBlocktesterIntegrationTest, CiliumGoBlockParserPartialBlocks) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(fake_upstream_connection->write("24:DROP reply "));
  ASSERT_TRUE(fake_upstream_connection->write("direction\n24:PASS"));
  ASSERT_TRUE(fake_upstream_connection->write(" reply direction\n"));
  tcp_client->waitForData("24:PASS reply direction\n");

  tcp_client->write("27:PASS original direction\n");
  ASSERT_TRUE(fake_upstream_connection->waitForData(FakeRawConnection::waitForInexactMatch("27:PASS original direction\n")));

  ASSERT_TRUE(fake_upstream_connection->write("", true));
  tcp_client->waitForHalfClose();
  tcp_client->write("", true);
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

TEST_P(CiliumGoBlocktesterIntegrationTest, CiliumGoBlockParserInject) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  tcp_client->write("26:INJECT reply direction\n");
  tcp_client->write("27:PASS original direction\n");
  ASSERT_TRUE(fake_upstream_connection->write("24:PASS reply direction\n"));

  // These can in principle arrive in either order
  std::this_thread::sleep_for(std::chrono::milliseconds(10));
  tcp_client->waitForData("24:PASS reply direction\n", false);
  std::this_thread::sleep_for(std::chrono::milliseconds(10));
  tcp_client->waitForData("26:INJECT reply direction\n", false);

  ASSERT_TRUE(fake_upstream_connection->waitForData(FakeRawConnection::waitForInexactMatch("27:PASS original direction\n")));

  ASSERT_TRUE(fake_upstream_connection->write("", true));
  tcp_client->waitForHalfClose();
  tcp_client->write("", true);
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

TEST_P(CiliumGoBlocktesterIntegrationTest, CiliumGoBlockParserInjectPartial) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(fake_upstream_connection->write("24:PASS reply"));
  tcp_client->write("26:INJECT reply direction\n");
  tcp_client->write("27:PASS original direction\n");

  ASSERT_TRUE(fake_upstream_connection->write(" direction\n"));

  // These can in principle arrive in either order
  tcp_client->waitForData("24:PASS reply direction\n", false);
  tcp_client->waitForData("26:INJECT reply direction\n", false);

  ASSERT_TRUE(fake_upstream_connection->waitForData(FakeRawConnection::waitForInexactMatch("27:PASS original direction\n")));

  ASSERT_TRUE(fake_upstream_connection->write("", true));
  tcp_client->waitForHalfClose();
  tcp_client->write("", true);
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

TEST_P(CiliumGoBlocktesterIntegrationTest, CiliumGoBlockParserInjectPartialMultiple) {
  initialize();
  IntegrationTcpClientPtr tcp_client = makeTcpConnection(lookupPort("tcp_proxy"));
  FakeRawConnectionPtr fake_upstream_connection;
  ASSERT_TRUE(fake_upstreams_[0]->waitForRawConnection(fake_upstream_connection));

  ASSERT_TRUE(fake_upstream_connection->write("24:PASS reply"));
  tcp_client->write("26:INJECT reply direction\n");
  tcp_client->write("27:DROP original direction\n");
  tcp_client->write("29:INSERT original direction\n");

  std::this_thread::sleep_for(std::chrono::milliseconds(1000));
  ASSERT_TRUE(fake_upstream_connection->write(" dire"));

  std::this_thread::sleep_for(std::chrono::milliseconds(1000));
  ASSERT_TRUE(fake_upstream_connection->write("ction\n"));

  // These can in principle arrive in either order
  tcp_client->waitForData("24:PASS reply direction\n", false);
  tcp_client->waitForData("26:INJECT reply direction\n", false);

  ASSERT_TRUE(fake_upstream_connection->waitForData(FakeRawConnection::waitForInexactMatch("29:INSERT original direction\n")));
  ASSERT_TRUE(fake_upstream_connection->waitForData(noMatch("DROP")));

  ASSERT_TRUE(fake_upstream_connection->write("24:DROP reply direction\n"));
  ASSERT_TRUE(fake_upstream_connection->write("25:PASS2 reply direction\n"));
  tcp_client->waitForData("25:PASS2 reply direction\n", false);

  ASSERT_TRUE(fake_upstream_connection->write("", true));
  tcp_client->waitForHalfClose();
  tcp_client->write("", true);
  ASSERT_TRUE(fake_upstream_connection->waitForHalfClose());
  ASSERT_TRUE(fake_upstream_connection->waitForDisconnect());
}

} // namespace Envoy
