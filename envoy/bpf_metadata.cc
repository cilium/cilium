#include "bpf_metadata.h"

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
  ListenerFilterFactoryCb
  createFilterFactory(const Json::Object &json,
                      ListenerFactoryContext &context) override {
    Filter::BpfMetadata::ConfigSharedPtr config(
        new Filter::BpfMetadata::Config(json, context.scope()));
    // Set the socket mark for the listen socket.
    context.setListenSocketMark(config->getMark(config->identity_));

    return [config](
               Network::ListenerFilterManager &filter_manager) mutable -> void {
      filter_manager.addAcceptFilter(
          std::make_shared<Filter::BpfMetadata::Instance>(config));
    };
  }

  std::string name() override { return "bpf_metadata"; }
  // Deprecate?
  ListenerFilterType type() override { return ListenerFilterType::Accept; }
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

std::string Config::get_bpf_root(const Json::Object &config) {
  return config.getString("bpf_root", "/sys/fs/bpf");
}

Config::Config(const Json::Object &config, Stats::Scope &scope)
    : bpf_root_(config.getString("bpf_root", "/sys/fs/bpf")),
      stats_{ALL_BPF_METADATA_STATS(POOL_COUNTER(scope))},
      is_ingress_(config.getBoolean("is_ingress", false)),
      identity_(config.getInteger("identity", 0)), maps_(bpf_root_, *this) {}

bool Instance::getBpfMetadata(Network::AcceptSocket &socket) {
  return config_->maps_.getBpfMetadata(socket);
}

Network::FilterStatus Instance::onAccept(Network::ListenerFilterCallbacks &cb) {
  Network::AcceptSocket &socket = cb.socket();
  if (!getBpfMetadata(socket)) {
    ENVOY_LOG(info, "bpf_metadata ({}): no bpf metadata for the connection.",
              config_->is_ingress_ ? "ingress" : "egress");
  } else {
    ENVOY_LOG(
        info,
        "bpf_metadata ({}): GOT bpf metadata for new connection (mark: {:x})",
        config_->is_ingress_ ? "ingress" : "egress", socket.socketMark());
  }
  return Network::FilterStatus::Continue;
}

} // namespace BpfMetadata
} // namespace Filter
} // namespace Envoy
