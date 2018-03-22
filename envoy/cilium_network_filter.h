#pragma once

#include "envoy/network/connection.h"
#include "envoy/network/filter.h"
#include "common/common/logger.h"

#include "proxymap.h"

namespace Envoy {
namespace Filter {
namespace CiliumL3 {

/**
 * Implementation of a Cilium network filter.
 */
class Instance : public Network::ReadFilter, public Network::ConnectionCallbacks,
                 Logger::Loggable<Logger::Id::filter> {
public:
  // Network::ReadFilter
  Network::FilterStatus onData(Buffer::Instance&, bool) override {
    return Network::FilterStatus::Continue;
  }
  Network::FilterStatus onNewConnection() override;
  void initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) override {
    callbacks_ = &callbacks;
  }

  // Network::ConnectionCallbacks
  void onEvent(Network::ConnectionEvent event) override;
  void onAboveWriteBufferHighWatermark() override {}
  void onBelowWriteBufferLowWatermark() override {}

private:
  Network::ReadFilterCallbacks* callbacks_ = nullptr;
  Cilium::ProxyMapSharedPtr maps_{};
  uint16_t proxy_port_ = 0;
};

} // namespace CiliumL3
} // namespace Filter
} // namespace Envoy
