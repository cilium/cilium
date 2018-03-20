#include "cilium_l7policy.h"
#include "cilium/cilium_l7policy.pb.validate.h"

#include <string>

#include "envoy/registry/registry.h"

#include "common/common/enum_to_int.h"
#include "common/config/utility.h"

#include "server/config/network/http_connection_manager.h"

#include "envoy/singleton/manager.h"

#include "cilium_network_policy.h"
#include "cilium_socket_option.h"

namespace Envoy {
namespace Cilium {

// Singleton registration via macro defined in envoy/singleton/manager.h
SINGLETON_MANAGER_REGISTRATION(cilium_network_policy);

class ConfigFactory
    : public Server::Configuration::NamedHttpFilterConfigFactory {
public:
  Server::Configuration::HttpFilterFactoryCb
  createFilterFactory(const Json::Object& json, const std::string &,
                      Server::Configuration::FactoryContext& context) override {
    auto config = std::make_shared<Cilium::Config>(json, context);
    return [config](
               Http::FilterChainFactoryCallbacks& callbacks) mutable -> void {
      callbacks.addStreamFilter(std::make_shared<Cilium::AccessFilter>(config));
    };
  }

  Server::Configuration::HttpFilterFactoryCb
  createFilterFactoryFromProto(const Protobuf::Message& proto_config, const std::string&,
                               Server::Configuration::FactoryContext& context) override {
    auto config = std::make_shared<Cilium::Config>(
        MessageUtil::downcastAndValidate<const ::cilium::L7Policy&>(proto_config), context);
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
 * Static registration for this filter. @see RegisterFactory.
 */
static Registry::RegisterFactory<
    ConfigFactory, Server::Configuration::NamedHttpFilterConfigFactory>
    register_;

namespace {

envoy::api::v2::core::ApiConfigSource
ApiConfigSource(const Json::Object &config) {
  envoy::api::v2::core::ApiConfigSource api_config_source;
  
  ASSERT(config.getString("api_type", Envoy::Config::ApiType::get().Grpc) == Envoy::Config::ApiType::get().Grpc);
  api_config_source.set_api_type(envoy::api::v2::core::ApiConfigSource::GRPC);
  api_config_source.add_cluster_names(config.getObject("cluster")->getString("name"));

  return api_config_source;
}

std::shared_ptr<const Cilium::NetworkPolicyMap>
createPolicyMap(const envoy::api::v2::core::ApiConfigSource& api_config_source,
		Server::Configuration::FactoryContext& context) {
  return context.singletonManager().getTyped<const Cilium::NetworkPolicyMap>(
    SINGLETON_MANAGER_REGISTERED_NAME(cilium_network_policy), [&api_config_source, &context] {
      return std::make_shared<Cilium::NetworkPolicyMap>(
	api_config_source, context.localInfo(), context.clusterManager(),
	context.dispatcher(), context.scope(), context.threadLocal());
    });
}

} // namespace

Config::Config(const envoy::api::v2::core::ApiConfigSource& api_config_source,
	       const std::string& policy_name, const std::string& listener_id,
	       const std::string& access_log_path, Server::Configuration::FactoryContext& context)
    : stats_{ALL_CILIUM_STATS(POOL_COUNTER_PREFIX(context.scope(), "cilium"))},
      listener_id_(listener_id),  policy_name_(policy_name), access_log_(nullptr) {
  if (access_log_path.length()) {
    access_log_ = AccessLog::Open(access_log_path);
    if (!access_log_) {
      ENVOY_LOG(warn, "Cilium filter can not open access log socket {}", access_log_path);
    }
  }

  // Get the shared policy provider, or create it if not already created.
  // Note that the API config source is assumed to be the same for all filter instances!
  npmap_ = createPolicyMap(api_config_source, context);
}

Config::Config(const Json::Object &config, Server::Configuration::FactoryContext& context)
    : Config(ApiConfigSource(*config.getObject("api_config_source")), config.getString("policy_name"), config.getString("listener_id"), config.getString("access_log_path"), context) {}

Config::Config(const ::cilium::L7Policy &config, Server::Configuration::FactoryContext& context)
    : Config(config.api_config_source(), config.policy_name(), config.listener_id(), config.access_log_path(), context) {}

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

Http::FilterHeadersStatus AccessFilter::decodeHeaders(Http::HeaderMap& headers, bool) {
  const auto& conn = callbacks_->connection();
  bool allowed = false;
  if (config_->npmap_ && conn) {
    const auto& options_ = conn->socketOptions();
    if (options_) {
      const auto options = dynamic_cast<Cilium::SocketOption*>(options_.get());
      if (options) {
	if (options->ingress_) {
	  allowed = config_->npmap_->Allowed(config_->policy_name_, true, options->port_,
					     options->source_identity_, headers);
	} else {
	  allowed = config_->npmap_->Allowed(config_->policy_name_, false, options->port_,
					     0 /* no remote ID yet */, headers);
	}
	ENVOY_LOG(debug, "Cilium L7: {} policy lookup for endpoint {}: {}",
		  options->ingress_ ? "Ingress" : "Egress", config_->policy_name_,
		  allowed ? "ALLOW" : "DENY");
      } else {
	ENVOY_LOG(warn, "Cilium L7: Socket Options dynamic cast failed");
      }
    } else {
      ENVOY_LOG(warn, "Cilium L7: No socket options");
    }
  } else {
    ENVOY_LOG(warn, "Cilium L7: No policy map or no connection");
  }

  // Fill in the log entry
  log_entry_.InitFromRequest(config_->listener_id_, callbacks_->connection(),
                             headers, callbacks_->requestInfo());
  if (!allowed) {
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
