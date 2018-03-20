#pragma once

#include <string>

#include "envoy/stats/stats_macros.h"

#include "common/common/logger.h"

#include "server/config/network/http_connection_manager.h"

#include "accesslog.h"
#include "cilium/cilium_l7policy.pb.h"

#include "cilium_network_policy.h"

namespace Envoy {
namespace Cilium {

/**
 * All Cilium L7 filter stats. @see stats_macros.h
 */
// clang-format off
#define ALL_CILIUM_STATS(COUNTER)                                                                  \
  COUNTER(access_denied)                                                                           \
// clang-format on

/**
 * Struct definition for all Cilium L7 filter stats. @see stats_macros.h
 */
struct FilterStats {
  ALL_CILIUM_STATS(GENERATE_COUNTER_STRUCT)
};

/**
 * Per listener configuration for Cilium HTTP filter. This
 * is accessed by multiple working thread instances of the filter.
 */
class Config : public Logger::Loggable<Logger::Id::filter> {
public:
  Config(const envoy::api::v2::core::ApiConfigSource& api_config_source,
	 const std::string& policy_name, const std::string& listener_id,
	 const std::string& access_log_path, Server::Configuration::FactoryContext& context);
  Config(const Json::Object &config, Server::Configuration::FactoryContext& context);
  Config(const ::cilium::L7Policy &config, Server::Configuration::FactoryContext& context);
  ~Config();

  void Log(AccessLog::Entry &, ::cilium::EntryType);

  FilterStats stats_;
  std::string listener_id_;
  std::string policy_name_;
  std::shared_ptr<const Cilium::NetworkPolicyMap> npmap_;

private:
  AccessLog *access_log_;
};

typedef std::shared_ptr<Config> ConfigSharedPtr;

// Each request gets their own instance of this filter, and
// they can run parallel from multiple worker threads, all accessing
// the shared configuration.
class AccessFilter : public Http::StreamFilter,
                     Logger::Loggable<Logger::Id::filter> {
public:
  AccessFilter(ConfigSharedPtr& config) : config_(config), denied_(false) {}

  // Http::StreamFilterBase
  void onDestroy() override;

  // Http::StreamDecoderFilter
  Http::FilterHeadersStatus decodeHeaders(Http::HeaderMap& headers, bool) override;
  Http::FilterDataStatus decodeData(Buffer::Instance&, bool) override {
    return Http::FilterDataStatus::Continue;
  }
  Http::FilterTrailersStatus decodeTrailers(Http::HeaderMap&) override {
    return Http::FilterTrailersStatus::Continue;
  }
  void setDecoderFilterCallbacks(Http::StreamDecoderFilterCallbacks& callbacks) override {
    callbacks_ = &callbacks;
  }

  // Http::StreamEncoderFilter
  Http::FilterHeadersStatus encode100ContinueHeaders(Http::HeaderMap&) override {
    return Http::FilterHeadersStatus::Continue;
  }
  Http::FilterHeadersStatus encodeHeaders(Http::HeaderMap& headers, bool end_stream) override;
  Http::FilterDataStatus encodeData(Buffer::Instance&, bool) override {
    return Http::FilterDataStatus::Continue;
  }
  Http::FilterTrailersStatus encodeTrailers(Http::HeaderMap&) override {
    return Http::FilterTrailersStatus::Continue;
  }
  void setEncoderFilterCallbacks(Http::StreamEncoderFilterCallbacks&) override {}

private:
  ConfigSharedPtr config_;
  Http::StreamDecoderFilterCallbacks* callbacks_;

  bool denied_;
  AccessLog::Entry log_entry_;
};

} // Cilium
} // Envoy
