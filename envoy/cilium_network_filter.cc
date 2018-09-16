#include "cilium_network_filter.h"
#include "cilium/cilium_network_filter.pb.validate.h"

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
  Network::FilterFactoryCb
  createFilterFactoryFromProto(const Protobuf::Message& proto_config,
			       FactoryContext& context) override {
    auto config = std::make_shared<Filter::CiliumL3::Config>(MessageUtil::downcastAndValidate<const ::cilium::NetworkFilter&>(proto_config), context);
    return [config](Network::FilterManager &filter_manager) mutable -> void {
      filter_manager.addReadFilter(std::make_shared<Filter::CiliumL3::Instance>(config));
    };
  }

  Network::FilterFactoryCb
  createFilterFactory(const Json::Object& json_config, FactoryContext& context) override {
    auto config = std::make_shared<Filter::CiliumL3::Config>(json_config, context);
    return [config](Network::FilterManager &filter_manager) mutable -> void {
      filter_manager.addReadFilter(std::make_shared<Filter::CiliumL3::Instance>(config));
    };
  }
  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<::cilium::NetworkFilter>();
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

Config::Config(const ::cilium::NetworkFilter&, Server::Configuration::FactoryContext&) {
}

Config::Config(const Json::Object&, Server::Configuration::FactoryContext&) {
}

Network::FilterStatus Instance::onNewConnection() {
  ENVOY_LOG(debug, "Cilium Network: onNewConnection");
  auto& conn = callbacks_->connection();
  const auto& options_ = conn.socketOptions();
  if (options_) {
    const Cilium::SocketOption* option = nullptr;
    for (const auto& option_: *options_) {
      option = dynamic_cast<const Cilium::SocketOption*>(option_.get());
      if (option) {
	if (option->maps_) {
	  // Insert connection callback to delete the proxymap entry once the connection is closed.
	  maps_ = option->maps_;
	  proxy_port_ = option->proxy_port_;
	  if (proxy_port_ != 0) {
	    conn.addConnectionCallbacks(*this);
	    ENVOY_CONN_LOG(debug, "Cilium Network: Added connection callbacks to delete proxymap entry later", conn);
	  }
	  break;
	} else {
	  ENVOY_CONN_LOG(debug, "Cilium Network: No proxymap", conn);
	}
      }
    }
    if (!option) {
      ENVOY_CONN_LOG(warn, "Cilium Network: Cilium Socket Option not found", conn);
    }
  } else {
    ENVOY_CONN_LOG(warn, "Cilium Network: No socket options", conn);
  }

  return Network::FilterStatus::Continue;
}

Network::FilterStatus Instance::onData(Buffer::Instance&, bool) {
  return Network::FilterStatus::Continue;
}

void Instance::onEvent(Network::ConnectionEvent event) {
  if (event == Network::ConnectionEvent::RemoteClose ||
      event == Network::ConnectionEvent::LocalClose) {
    auto& conn = callbacks_->connection();
    if (maps_) {
      bool ok = maps_->removeBpfMetadata(conn, proxy_port_);
      ENVOY_CONN_LOG(debug, "Cilium Network: Connection Closed, proxymap cleanup {}", conn,
		     ok ? "succeeded" : "failed");
    }
  }
}

} // namespace CiliumL3
} // namespace Filter
} // namespace Envoy
