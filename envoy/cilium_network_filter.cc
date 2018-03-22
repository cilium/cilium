#include "cilium_network_filter.h"

#include "common/common/assert.h"
#include "common/common/fmt.h"
#include "envoy/network/listen_socket.h"
#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

#include "cilium_socket_option.h"

namespace Envoy {
namespace Server {
namespace Configuration {

/**
 * Config registration for the bpf metadata filter. @see
 * NamedNetworkFilterConfigFactory.
 */
class CiliumNetworkConfigFactory : public NamedNetworkFilterConfigFactory {
public:
  // NamedNetworkFilterConfigFactory
  Configuration::NetworkFilterFactoryCb
  createFilterFactoryFromProto(const Protobuf::Message&, FactoryContext&) override {
    return [](Network::FilterManager &filter_manager) mutable -> void {
      filter_manager.addReadFilter(std::make_shared<Filter::CiliumL3::Instance>());
    };
  }

  Configuration::NetworkFilterFactoryCb
  createFilterFactory(const Json::Object&, FactoryContext&) override {
    return [](Network::FilterManager &filter_manager) mutable -> void {
      filter_manager.addReadFilter(std::make_shared<Filter::CiliumL3::Instance>());
    };
  }
  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return ProtobufTypes::MessagePtr{new Envoy::ProtobufWkt::Empty()};
  }

  std::string name() override { return "cilium.network"; }
};

/**
 * Static registration for the bpf metadata filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<CiliumNetworkConfigFactory, NamedNetworkFilterConfigFactory>
    registered_;

} // namespace Configuration
} // namespace Server

namespace Filter {
namespace CiliumL3 {

Network::FilterStatus Instance::onNewConnection() {
  ENVOY_LOG(warn, "Cilium Network: onNewConnection");
  auto& conn = callbacks_->connection();
  const auto& options_ = conn.socketOptions();
  if (options_) {
    const auto options = dynamic_cast<Cilium::SocketOption*>(options_.get());
    if (options) {
      if (options->maps_) {
	// Insert connection callback to delete the proxymap entry once the connection is closed.
	ASSERT(!maps_);
	maps_ = options->maps_;
	proxy_port_ = options->proxy_port_;
	conn.addConnectionCallbacks(*this);
	ENVOY_CONN_LOG(debug, "Cilium Network: Added connection callbacks", conn);
      } else {
	ENVOY_CONN_LOG(warn, "Cilium Network: No proxymap", conn);
      }
    } else {
      ENVOY_CONN_LOG(warn, "Cilium Network: Socket Options dynamic cast failed", conn);
    }
  } else {
    ENVOY_CONN_LOG(warn, "Cilium Network: No socket options", conn);
  }

  return Network::FilterStatus::Continue;
}

void Instance::onEvent(Network::ConnectionEvent event) {
  if (event == Network::ConnectionEvent::RemoteClose ||
      event == Network::ConnectionEvent::LocalClose) {
    auto& conn = callbacks_->connection();
    bool ok = maps_->removeBpfMetadata(conn, proxy_port_);
    ENVOY_CONN_LOG(warn, "Cilium Network: Connection Closed, proxymap cleanup {}", conn,
	           ok ? "succeeded" : "failed");
  }
}

} // namespace CiliumL3
} // namespace Filter
} // namespace Envoy
