#pragma once

#include "envoy/local_info/local_info.h"
#include "envoy/upstream/cluster_manager.h"
#include "envoy/event/dispatcher.h"

#include "common/common/logger.h"
#include "common/http/header_utility.h"
#include "envoy/config/subscription.h"
#include "envoy/singleton/instance.h"
#include "envoy/thread_local/thread_local.h"
#include "envoy/http/header_map.h"

#include "cilium/npds.pb.h"

namespace Envoy {
namespace Cilium {

class NetworkPolicyMap : public Singleton::Instance,
                         Config::SubscriptionCallbacks<cilium::NetworkPolicy>,
                         public std::enable_shared_from_this<NetworkPolicyMap>,
                         public Logger::Loggable<Logger::Id::config> {
public:
  NetworkPolicyMap(ThreadLocal::SlotAllocator& tls);
  NetworkPolicyMap(const envoy::api::v2::core::Node& node, Upstream::ClusterManager& cm,
		   Event::Dispatcher& dispatcher, Stats::Scope &scope,
		   ThreadLocal::SlotAllocator& tls);
  NetworkPolicyMap(std::unique_ptr<Envoy::Config::Subscription<cilium::NetworkPolicy>>&& subscription,
		   ThreadLocal::SlotAllocator& tls);
  ~NetworkPolicyMap() {
    ENVOY_LOG(debug, "Cilium L7 NetworkPolicyMap({}): NetworkPolicyMap is deleted NOW!", name_);
  }

  // subscription_->start() calls onConfigUpdate(), which uses
  // shared_from_this(), which cannot be called before a shared
  // pointer is formed by the caller of the constructor, hence this
  // can't be called from the constructor!
  void startSubscription() { subscription_->start({}, *this); }
  
  class PolicyInstance {
  public:
    PolicyInstance(uint64_t hash, const cilium::NetworkPolicy& proto)
        : hash_(hash), policy_proto_(proto), ingress_(policy_proto_.ingress_per_port_policies()),
          egress_(policy_proto_.egress_per_port_policies()) {}

    uint64_t hash_;
    const cilium::NetworkPolicy policy_proto_;

  protected:
    class HttpNetworkPolicyRule : public Logger::Loggable<Logger::Id::config> {
    public:
      HttpNetworkPolicyRule(const cilium::HttpNetworkPolicyRule& rule) {
	ENVOY_LOG(trace, "Cilium L7 HttpNetworkPolicyRule():");
	for (const auto& header: rule.headers()) {
	  headers_.emplace_back(header);
	  const auto& header_data = headers_.back();
	  ENVOY_LOG(trace, "Cilium L7 HttpNetworkPolicyRule(): HeaderData {}={}",
		    header_data.name_.get(),
		    header_data.header_match_type_ == Http::HeaderUtility::HeaderMatchType::Range
		    ? fmt::format("[{}-{})", header_data.range_.start(), header_data.range_.end())
		    : header_data.header_match_type_ == Http::HeaderUtility::HeaderMatchType::Value
		    ? header_data.value_
		    : header_data.header_match_type_ == Http::HeaderUtility::HeaderMatchType::Regex
		    ? "<REGEX>" : "<UNKNOWN>");
	}
      }

      bool Matches(const Envoy::Http::HeaderMap& headers) const {
	// Empty set matches any headers.
	return Envoy::Http::HeaderUtility::matchHeaders(headers, headers_);
      }

      std::vector<Envoy::Http::HeaderUtility::HeaderData> headers_; // Allowed if empty.
    };
    
    class PortNetworkPolicyRule : public Logger::Loggable<Logger::Id::config> {
    public:
      PortNetworkPolicyRule(const cilium::PortNetworkPolicyRule& rules) {
	for (const auto& remote: rules.remote_policies()) {
	  ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRule(): Allowing remote {}", remote);
	  allowed_remotes_.emplace(remote);
	}
	if (rules.has_http_rules()) {
	  for (const auto& http_rule: rules.http_rules().http_rules()) {
	    http_rules_.emplace_back(http_rule);
	  }
	}
      }

      bool Matches(uint64_t remote_id, const Envoy::Http::HeaderMap& headers) const {
	// Remote ID must match if we have any.
	if (allowed_remotes_.size() > 0) {
	  auto search = allowed_remotes_.find(remote_id);
	  if (search == allowed_remotes_.end()) {
	    return false;
	  }
	}
	if (http_rules_.size() > 0) {
	  for (const auto& rule: http_rules_) {
	    if (rule.Matches(headers)) {
	      return true;
	    }
	  }
	  return false;
	}
	// Empty set matches any payload
	return true;
      }

      std::unordered_set<uint64_t> allowed_remotes_; // Everyone allowed if empty.
      std::vector<HttpNetworkPolicyRule> http_rules_; // Allowed if empty, but remote is checked first.
    };

    class PortNetworkPolicyRules : public Logger::Loggable<Logger::Id::config> {
    public:
      PortNetworkPolicyRules(const google::protobuf::RepeatedPtrField<cilium::PortNetworkPolicyRule>& rules) : have_http_rules_(false) {
	if (rules.size() == 0) {
	    ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicyRules(): No rules, will allow everything.");
	}
	for (const auto& it: rules) {
	  if (it.has_http_rules()) {
	    have_http_rules_ = true;
	  }
	  rules_.emplace_back(PortNetworkPolicyRule(it));
	}
      }

      bool Matches(uint64_t remote_id, const Envoy::Http::HeaderMap& headers) const {
	if (!have_http_rules_) {
	  // If there are no L7 rules, host proxy will not create a proxy redirect at all,
	  // whereby the decicion made by the bpf datapath is final. Emulate the same behavior
	  // in the sidecar by allowing such traffic.
	  // TODO: This will need to be revised when non-bpf datapaths are to be supported.
	  return true;
	}
	// Empty set matches any payload from anyone
	if (rules_.size() == 0) {
	  return true;
	}
	for (const auto& rule: rules_) {
	  if (rule.Matches(remote_id, headers)) {
	    return true;
	  }
	}
	return false;
      }

      std::vector<PortNetworkPolicyRule> rules_; // Allowed if empty.
      bool have_http_rules_;
    };
    
    class PortNetworkPolicy : public Logger::Loggable<Logger::Id::config> {
    public:
      PortNetworkPolicy(const google::protobuf::RepeatedPtrField<cilium::PortNetworkPolicy>& rules) {
	for (const auto& it: rules) {
	  // Only TCP supported for HTTP
	  if (it.protocol() == envoy::api::v2::core::SocketAddress::TCP) {
	    // Port may be zero, which matches any port.
	    ENVOY_LOG(trace, "Cilium L7 PortNetworkPolicy(): installing TCP policy for port {}", it.port());
	    if (!rules_.emplace(it.port(), PortNetworkPolicyRules(it.rules())).second) {
	      throw EnvoyException("PortNetworkPolicy: Duplicate port number");
	    }
	  } else {
	    ENVOY_LOG(debug, "Cilium L7 PortNetworkPolicy(): NOT installing non-TCP policy");
	  }
	}
      }

      bool Matches(uint32_t port, uint64_t remote_id, const Envoy::Http::HeaderMap& headers) const {
	bool found_port_rule = false;
	auto it = rules_.find(port);
	if (it != rules_.end()) {
	  if (it->second.Matches(remote_id, headers)) {
	    return true;
	  }
	  found_port_rule = true;
	}
	// Check for any rules that wildcard the port
	it = rules_.find(0);
	if (it != rules_.end()) {
	  if (it->second.Matches(remote_id, headers)) {
	    return true;
	  }
	  found_port_rule = true;
	}

	// No policy for the port was found. Cilium always creates a policy for redirects it
	// creates, so the host proxy never gets here. Sidecar gets all the traffic, which we need
	// to pass through since the bpf datapath already allowed it.
        // TODO: Change back to false only when non-bpf datapath is supported?
	return found_port_rule ? false : true;
      }

      std::unordered_map<uint32_t, PortNetworkPolicyRules> rules_;
    };

  public:
    bool Allowed(bool ingress, uint32_t port, uint64_t remote_id,
		 const Envoy::Http::HeaderMap& headers) const {
      return ingress
	? ingress_.Matches(port, remote_id, headers)
	: egress_.Matches(port, remote_id, headers);
    }

  private:
    const PortNetworkPolicy ingress_;
    const PortNetworkPolicy egress_;
  };

  struct ThreadLocalPolicyMap : public ThreadLocal::ThreadLocalObject {
    std::map<std::string, std::shared_ptr<const PolicyInstance>> policies_;
  };

  const std::shared_ptr<const PolicyInstance>& GetPolicyInstance(const std::string& endpoint_policy_name) const {
    const ThreadLocalPolicyMap& map = tls_->getTyped<ThreadLocalPolicyMap>();
    auto it = map.policies_.find(endpoint_policy_name);
    if (it == map.policies_.end()) {
      return null_instance_;
    }
    return it->second;
  }

  bool Allowed(const std::string& endpoint_policy_name, bool ingress, uint32_t port, uint64_t remote_id,
	       const Envoy::Http::HeaderMap& headers) const {
    ENVOY_LOG(trace, "Cilium L7 NetworkPolicyMap::Allowed(): {} policy lookup for endpoint {}, port {}, remote_id: {}", ingress ? "Ingress" : "Egress", endpoint_policy_name, port, remote_id);
    if (tls_->get().get() == nullptr) {
      ENVOY_LOG(warn, "Cilium L7 NetworkPolicyMap::Allowed(): NULL TLS object!");
      return false;
    }
    const auto& npmap = tls_->getTyped<ThreadLocalPolicyMap>().policies_;
    auto it = npmap.find(endpoint_policy_name);
    if (it == npmap.end()) {
      ENVOY_LOG(trace, "Cilium L7 NetworkPolicyMap::Allowed(): No policy found for endpoint {}", endpoint_policy_name);
      return false;
    }
    return it->second->Allowed(ingress, port, remote_id, headers);
  }

  // Config::SubscriptionCallbacks
  void onConfigUpdate(const ResourceVector& resources, const std::string& version_info) override;
  void onConfigUpdateFailed(const EnvoyException* e) override;
  std::string resourceName(const ProtobufWkt::Any& resource) override {
    return MessageUtil::anyConvert<cilium::NetworkPolicy>(resource).name();
  }

private:
  ThreadLocal::SlotPtr tls_;
  Stats::ScopePtr scope_;
  std::unique_ptr<Envoy::Config::Subscription<cilium::NetworkPolicy>> subscription_;
  const std::shared_ptr<const PolicyInstance> null_instance_{nullptr};
  static uint64_t instance_id_;
  std::string name_;
};

} // namespace Cilium
} // namespace Envoy
