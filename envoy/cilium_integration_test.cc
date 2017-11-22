#include <string>

#include "envoy/network/listen_socket.h"
#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

#include "common/common/assert.h"
#include "common/network/address_impl.h"
#include "common/network/utility.h"

#include "test/integration/integration.h"
#include "test/integration/utility.h"

#include "bpf_metadata.h"

namespace Envoy {

namespace Filter {
namespace BpfMetadata {

class TestConfig : public Config {
public:
  TestConfig(const Json::Object &config, Stats::Scope &scope)
      : Config(config, scope) {
    original_dst_address_ = Network::Utility::parseInternetAddressAndPort(
        config.getString("original_dst_address"));
    socket_mark_ = config.getInteger("socket_mark", 0);
  }

  Network::Address::InstanceConstSharedPtr original_dst_address_;
  uint32_t socket_mark_;
};

typedef std::shared_ptr<TestConfig> TestConfigSharedPtr;

class TestInstance : public Instance {
public:
  TestInstance(TestConfigSharedPtr json)
      : Instance(json), test_config_(json.get()) {}

  bool getBpfMetadata(Network::AcceptSocket &socket) override {
    socket.resetLocalAddress(test_config_->original_dst_address_);
    socket.setSocketMark(test_config_->socket_mark_);
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
  createFilterFactory(const Json::Object &json,
                      ListenerFactoryContext &context) override {
    Filter::BpfMetadata::TestConfigSharedPtr config(
        new Filter::BpfMetadata::TestConfig(json, context.scope()));

    return [config](
               Network::ListenerFilterManager &filter_manager) mutable -> void {
      filter_manager.addAcceptFilter(
          std::make_shared<Filter::BpfMetadata::TestInstance>(config));
    };
  }

  std::string name() override { return "test_bpf_metadata"; }
  ListenerFilterType type() override { return ListenerFilterType::Accept; }
};

/**
 * Static registration for the bpf metadata filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<TestBpfMetadataConfigFactory,
                                 NamedListenerFilterConfigFactory>
    registered_;

} // namespace Configuration
} // namespace Server

class CiliumIntegrationTest
    : public BaseIntegrationTest,
      public testing::TestWithParam<Network::Address::IpVersion> {
public:
  CiliumIntegrationTest() : BaseIntegrationTest(GetParam()) {}
  /**
   * Initializer for an individual integration test.
   */
  void SetUp() override {
    fake_upstreams_.emplace_back(
        new FakeUpstream(0, FakeHttpConnection::Type::HTTP1, version_));
    registerPort("upstream_0",
                 fake_upstreams_.back()->localAddress()->ip()->port());
    createTestServer("cilium_proxy_test.json", {"cilium"});
  }

  /**
   * Destructor for an individual integration test.
   */
  void TearDown() override {
    fake_upstreams_.clear();
    test_server_.reset();
  }

  void Denied(Http::TestHeaderMapImpl headers) {
    IntegrationCodecClientPtr codec_client;
    IntegrationStreamDecoderPtr response(
        new IntegrationStreamDecoder(*dispatcher_));

    codec_client = makeHttpConnection(lookupPort("cilium"),
                                      Http::CodecClient::Type::HTTP1);
    codec_client->makeHeaderOnlyRequest(headers, *response);
    response->waitForEndStream();

    EXPECT_STREQ("403", response->headers().Status()->value().c_str());
    codec_client->close();
  }

  void Accepted(Http::TestHeaderMapImpl headers) {
    IntegrationCodecClientPtr codec_client;
    FakeHttpConnectionPtr fake_upstream_connection;
    IntegrationStreamDecoderPtr response(
        new IntegrationStreamDecoder(*dispatcher_));
    FakeStreamPtr request_stream;

    codec_client = makeHttpConnection(lookupPort("cilium"),
                                      Http::CodecClient::Type::HTTP1);
    codec_client->makeHeaderOnlyRequest(headers, *response);
    fake_upstream_connection =
        fake_upstreams_[0]->waitForHttpConnection(*dispatcher_);
    request_stream = fake_upstream_connection->waitForNewStream();
    request_stream->waitForEndStream(*dispatcher_);
    request_stream->encodeHeaders(Http::TestHeaderMapImpl{{":status", "200"}},
                                  true);
    response->waitForEndStream();

    EXPECT_STREQ("200", response->headers().Status()->value().c_str());
    codec_client->close();
    fake_upstream_connection->close();
    fake_upstream_connection->waitForDisconnect();
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

} // namespace Envoy
