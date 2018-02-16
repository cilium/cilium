#include "cilium_l7policy.h"
#include "cilium/cilium_l7policy.pb.validate.h"

#include <string>

#include "envoy/registry/registry.h"

#include "common/common/enum_to_int.h"

#include "server/config/network/http_connection_manager.h"

namespace Envoy {
namespace Cilium {

class ConfigFactory
    : public Server::Configuration::NamedHttpFilterConfigFactory {
public:
  Server::Configuration::HttpFilterFactoryCb
  createFilterFactory(const Json::Object &json, const std::string &,
                      Server::Configuration::FactoryContext &context) override {
    Cilium::ConfigSharedPtr config(new Cilium::Config(json, context.scope()));
    return [config](
               Http::FilterChainFactoryCallbacks &callbacks) mutable -> void {
      callbacks.addStreamFilter(std::make_shared<Cilium::AccessFilter>(config));
    };
  }

  Server::Configuration::HttpFilterFactoryCb
  createFilterFactoryFromProto(const Protobuf::Message& proto_config, const std::string&,
                               Server::Configuration::FactoryContext &context) override {
    Cilium::ConfigSharedPtr config(new Cilium::Config(MessageUtil::downcastAndValidate<const ::cilium::L7Policy&>(proto_config),
						      context.scope()));
    return [config](
               Http::FilterChainFactoryCallbacks &callbacks) mutable -> void {
      callbacks.addStreamFilter(std::make_shared<Cilium::AccessFilter>(config));
    };
  }

  ProtobufTypes::MessagePtr createEmptyConfigProto() override {
    return std::make_unique<::cilium::L7Policy>();
  }

  std::string name() override { return "cilium.l7policy"; }
};

/**
 * Static registration for this sample filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<
    ConfigFactory, Server::Configuration::NamedHttpFilterConfigFactory>
    register_;

Config::Config(const std::string& access_log_path, const std::string& listener_id,
               Stats::Scope &scope)
    : stats_{ALL_CILIUM_STATS(POOL_COUNTER_PREFIX(scope, "cilium"))},
      listener_id_(listener_id), access_log_(nullptr) {
  if (access_log_path.length()) {
    access_log_ = AccessLog::Open(access_log_path);
    if (!access_log_) {
      ENVOY_LOG(warn, "Cilium filter can not open access log socket {}", access_log_path);
    }
  }
}

Config::Config(const Json::Object &config, Stats::Scope &scope)
    : Config(config.getString("listener_id"), config.getString("access_log_path"), scope) {}

Config::Config(const ::cilium::L7Policy &config, Stats::Scope &scope)
    : Config(config.listener_id(), config.access_log_path(), scope) {}

Config::~Config() {
  if (access_log_) {
    access_log_->Close();
  }
}

void Config::Log(AccessLog::Entry &entry, ::cilium::EntryType type) {
  if (access_log_) {
    access_log_->Log(entry, type);
  }
}

void AccessFilter::onDestroy() {}

Http::FilterHeadersStatus AccessFilter::decodeHeaders(Http::HeaderMap &headers,
                                                      bool) {
  // Cilium configures security policy on route entries, whitelisting
  // allowed traffic. Return 403 if no route is found.
  auto route = callbacks_->route();

  // Fill in the log entry
  log_entry_.InitFromRequest(config_->listener_id_, callbacks_->connection(),
                             headers, callbacks_->requestInfo(),
                             route ? route->routeEntry() : nullptr);
  if (!route) {
    denied_ = true;
    config_->stats_.access_denied_.inc();

    // Return a 403 response
    Http::HeaderMapPtr response_headers{new Http::HeaderMapImpl{
        {Http::Headers::get().Status,
         std::to_string(enumToInt(Http::Code::Forbidden))}}};
    Buffer::OwnedImpl response_data{"Access denied\r\n"};

    callbacks_->encodeHeaders(std::move(response_headers), false);
    callbacks_->encodeData(response_data, true);
    return Http::FilterHeadersStatus::StopIteration;
  }

  config_->Log(log_entry_, ::cilium::EntryType::Request);
  return Http::FilterHeadersStatus::Continue;
}

Http::FilterHeadersStatus AccessFilter::encodeHeaders(Http::HeaderMap &headers,
                                                      bool) {
  log_entry_.UpdateFromResponse(headers, callbacks_->requestInfo());
  config_->Log(log_entry_, denied_ ? ::cilium::EntryType::Denied
                                   : ::cilium::EntryType::Response);
  return Http::FilterHeadersStatus::Continue;
}

} // namespace Cilium
} // namespace Envoy
