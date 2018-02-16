#include "cilium_bpf_metadata.h"
#include "cilium/cilium_bpf_metadata.pb.validate.h"

#include <string>

#include "envoy/network/listen_socket.h"
#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

#include "common/common/assert.h"

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
    Filter::BpfMetadata::ConfigSharedPtr config(
	new Filter::BpfMetadata::Config(MessageUtil::downcastAndValidate<const ::cilium::BpfMetadata&>(proto_config),
					context.scope()));
    // Set the socket mark option for the listen socket.
    // TODO: Share
    context.setListenSocketOptions(std::make_shared<Cilium::SocketMarkOption>(config->getMark(config->identity_)));

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

Config::Config(const ::cilium::BpfMetadata &config, Stats::Scope &scope)
    : bpf_root_(config.bpf_root().length() ? config.bpf_root() : "/sys/fs/bpf"),
      stats_{ALL_BPF_METADATA_STATS(POOL_COUNTER(scope))},
      is_ingress_(config.is_ingress()),
      identity_(config.identity()), maps_(bpf_root_, *this) {}

bool Instance::getBpfMetadata(Network::ConnectionSocket &socket) {
  return config_->maps_.getBpfMetadata(socket);
}

Network::FilterStatus Instance::onAccept(Network::ListenerFilterCallbacks &cb) {
  Network::ConnectionSocket &socket = cb.socket();
  if (!getBpfMetadata(socket)) {
    ENVOY_LOG(warn,
              "cilium.bpf_metadata ({}): no bpf metadata for the connection.",
              config_->is_ingress_ ? "ingress" : "egress");
  } else {
    ENVOY_LOG(debug,
              "cilium.bpf_metadata ({}): GOT bpf metadata for new connection "
              "(mark: {:x})",
              config_->is_ingress_ ? "ingress" : "egress", socket.options()->hashKey());
  }
  return Network::FilterStatus::Continue;
}

} // namespace BpfMetadata
} // namespace Filter
} // namespace Envoy
