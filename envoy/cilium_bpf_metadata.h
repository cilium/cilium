#pragma once

#include "envoy/json/json_object.h"
#include "envoy/network/filter.h"
#include "envoy/stats/stats_macros.h"

#include "common/common/logger.h"

#include "cilium/cilium_bpf_metadata.pb.h"
#include "proxymap.h"

namespace Envoy {
namespace Filter {
namespace BpfMetadata {

/**
 * All stats for the bpf metadata. @see stats_macros.h
 */
// clang-format off
#define ALL_BPF_METADATA_STATS(COUNTER)					\
  COUNTER(bpf_open_error)						\
  COUNTER(bpf_lookup_error)
// clang-format on

/**
 * Definition of all stats for the bpf metadata. @see stats_macros.h
 */
struct BpfStats {
  ALL_BPF_METADATA_STATS(GENERATE_COUNTER_STRUCT)
};

/**
 * Global configuration for Bpf Metadata listener filter. This
 * represents all global state shared among the working thread
 * instances of the filter.
 */
class Config : Logger::Loggable<Logger::Id::config> {
public:
  Config(const ::cilium::BpfMetadata &config, Stats::Scope &scope);

  uint32_t getMark(uint32_t identity) {
    // Magic marker values must match with Cilium.
    return ((is_ingress_) ? 0xFEA : 0xFEB) | (identity << 16);
  }

private:
  std::string bpf_root_;

public:
  BpfStats stats_;
  bool is_ingress_;
  uint32_t identity_;
  Cilium::ProxyMap maps_;
};

typedef std::shared_ptr<Config> ConfigSharedPtr;

/**
 * Implementation of a bpf metadata listener filter.
 */
class Instance : public Network::ListenerFilter,
                 Logger::Loggable<Logger::Id::filter> {
public:
  Instance(ConfigSharedPtr config) : config_(config) {}

  // Network::ListenerFilter
  Network::FilterStatus onAccept(Network::ListenerFilterCallbacks &cb) override;

  virtual bool getBpfMetadata(Network::ConnectionSocket &socket);

private:
  ConfigSharedPtr config_;
};

} // namespace BpfMetadata
} // namespace Filter
} // namespace Envoy
