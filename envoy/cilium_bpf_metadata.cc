#include "cilium_bpf_metadata.h"
#include "cilium/cilium_bpf_metadata.pb.validate.h"

#include <string>

#include "common/common/assert.h"
#include "common/common/fmt.h"
#include "envoy/network/listen_socket.h"
#include "envoy/registry/registry.h"
#include "envoy/singleton/manager.h"

#include "cilium_socket_option.h"

namespace Envoy {
namespace Server {
namespace Configuration {

/**
 * Config registration for the bpf metadata filter. @see
 * NamedNetworkFilterConfigFactory.
 */
class BpfMetadataConfigFactory : public NamedListenerFilterConfigFactory {
public:
  // NamedListenerFilterConfigFactory
  Configuration::ListenerFilterFactoryCb
  createFilterFactoryFromProto(const Protobuf::Message& proto_config,
			       Configuration::ListenerFactoryContext& context) override {
    auto config = std::make_shared<Filter::BpfMetadata::Config>(MessageUtil::downcastAndValidate<const ::cilium::BpfMetadata&>(proto_config), context);
    // Set the socket mark option for the listen socket.
    // Can use identity 0 on the listen socket option, as the bpf datapath is only interested
    // in whether the proxy is ingress, egress, or if there is no proxy at all.
    context.addListenSocketOption(std::make_unique<Cilium::SocketMarkOption>(0, config->is_ingress_));

    return [config](Network::ListenerFilterManager &filter_manager) mutable -> void {
      filter_manager.addAcceptFilter(std::make_unique<Filter::BpfMetadata::Instance>(config));
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<::cilium::BpfMetadata>();
  }

  std::string name() override { return "cilium.bpf_metadata"; }
};

/**
 * Static registration for the bpf metadata filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<BpfMetadataConfigFactory,
                                 NamedListenerFilterConfigFactory>
    registered_;

} // namespace Configuration
} // namespace Server

namespace Filter {
namespace BpfMetadata {

// Singleton registration via macro defined in envoy/singleton/manager.h
SINGLETON_MANAGER_REGISTRATION(cilium_bpf_proxymap);
SINGLETON_MANAGER_REGISTRATION(cilium_host_map);

namespace {

std::shared_ptr<const Cilium::PolicyHostMap>
createHostMap(Server::Configuration::ListenerFactoryContext& context) {
  return context.singletonManager().getTyped<const Cilium::PolicyHostMap>(
    SINGLETON_MANAGER_REGISTERED_NAME(cilium_host_map), [&context] {
      return std::make_shared<Cilium::PolicyHostMap>(
        context.localInfo().node(), context.clusterManager(),
	context.dispatcher(), context.scope(), context.threadLocal());
    });
}

} // namespace

Config::Config(const ::cilium::BpfMetadata &config, Server::Configuration::ListenerFactoryContext& context)
    : is_ingress_(config.is_ingress()) {
  // Note: all instances use the bpf root of the first filter with non-empty bpf_root instantiated!
  std::string bpf_root = config.bpf_root();
  if (bpf_root.length() > 0) {
    maps_ = context.singletonManager().getTyped<Cilium::ProxyMap>(
        SINGLETON_MANAGER_REGISTERED_NAME(cilium_bpf_proxymap), [&bpf_root] {
	  return std::make_shared<Cilium::ProxyMap>(bpf_root);
	});
    if (bpf_root != maps_->bpfRoot()) {
      throw EnvoyException(fmt::format("cilium.bpf_metadata: Invalid bpf_root: {}", bpf_root));
    }
  }
  hosts_ = createHostMap(context);
}

bool Config::getMetadata(Network::ConnectionSocket& socket) {
  uint32_t source_identity, destination_identity = 2 /* WORLD */;
  uint16_t orig_dport, proxy_port;
  bool ok = false;

  if (maps_) {
    ok = maps_->getBpfMetadata(socket, &source_identity, &orig_dport, &proxy_port);
  } else if (hosts_ && socket.remoteAddress()->ip() && socket.localAddress()->ip()) {
    // Resolve the source security ID
    source_identity = hosts_->resolve(socket.remoteAddress()->ip()->addressAsString());
    orig_dport = socket.localAddress()->ip()->port();
    proxy_port = 0; // no proxy_port when no bpf.
    ok = true;
  }
  if (ok) {
    // Resolve the destination security ID
    if (hosts_ && socket.localAddress()->ip()) {
      destination_identity = hosts_->resolve(socket.localAddress()->ip()->addressAsString());
    }
    socket.addOption(std::make_unique<Cilium::SocketOption>(maps_, source_identity, destination_identity, is_ingress_, orig_dport, proxy_port));
  }
  return ok;
}

Network::FilterStatus Instance::onAccept(Network::ListenerFilterCallbacks &cb) {
  Network::ConnectionSocket &socket = cb.socket();
  if (!config_->getMetadata(socket)) {
    ENVOY_LOG(debug,
              "cilium.bpf_metadata ({}): NO metadata for the connection",
              config_->is_ingress_ ? "ingress" : "egress");
  } else {
    ENVOY_LOG(trace,
              "cilium.bpf_metadata ({}): GOT metadata for new connection",
              config_->is_ingress_ ? "ingress" : "egress");
  }
  return Network::FilterStatus::Continue;
}

} // namespace BpfMetadata
} // namespace Filter
} // namespace Envoy
