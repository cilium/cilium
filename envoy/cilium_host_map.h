#pragma once

#include "envoy/local_info/local_info.h"
#include "envoy/upstream/cluster_manager.h"
#include "envoy/event/dispatcher.h"

#include "common/common/logger.h"
#include "envoy/config/subscription.h"
#include "envoy/singleton/instance.h"
#include "envoy/thread_local/thread_local.h"

#include "cilium/nphds.pb.h"

namespace Envoy {
namespace Cilium {

class PolicyHostMap : public Singleton::Instance,
                      Config::SubscriptionCallbacks<cilium::NetworkPolicyHosts>,
                      public std::enable_shared_from_this<PolicyHostMap>,
                      public Logger::Loggable<Logger::Id::config> {
public:
  PolicyHostMap(const envoy::api::v2::core::Node& node,
		Upstream::ClusterManager& cm, Event::Dispatcher& dispatcher,
		Stats::Scope &scope, ThreadLocal::SlotAllocator& tls);
  PolicyHostMap(std::unique_ptr<Envoy::Config::Subscription<cilium::NetworkPolicyHosts>>&& subscription,
		ThreadLocal::SlotAllocator& tls);
  PolicyHostMap(ThreadLocal::SlotAllocator& tls);
  ~PolicyHostMap() {
    ENVOY_LOG(debug, "Cilium PolicyHostMap({}): PolicyHostMap is deleted NOW!", name_);
  }

  void startSubscription() { subscription_->start({}, *this); }

  // A shared pointer to a immutable copy is held by each thread. Changes are done by
  // creating a new version and assigning the new shared pointer to the thread local
  // slot on each thread.
  struct ThreadLocalHostMap : public ThreadLocal::ThreadLocalObject {
  public:
    void insert(const cilium::NetworkPolicyHosts& proto) {
      uint64_t policy = proto.policy();
      const auto& hosts = proto.host_addresses();

      for (const auto& host: hosts) {
	auto pair = ip_to_policy_.emplace(std::make_pair(host, policy));
	if (pair.second == false) {
	  throw EnvoyException(fmt::format("NetworkPolicyHosts: Duplicate host entry {}:{}", host, policy));
	}
      }
    }

    uint64_t resolve(const std::string& addr) const {
      auto it = ip_to_policy_.find(addr);
      return it == ip_to_policy_.end() ? 2 /* WORLD */ : it->second;
    }

  private:
    std::unordered_map<std::string, uint64_t> ip_to_policy_;
  };
  typedef std::shared_ptr<ThreadLocalHostMap> ThreadLocalHostMapSharedPtr;

  const ThreadLocalHostMap* getHostMap() const {
    return tls_->get().get() ? &tls_->getTyped<ThreadLocalHostMap>() : nullptr;
  }

  uint64_t resolve(const std::string& addr) const {
    const ThreadLocalHostMap* hostmap = getHostMap();
    return (hostmap != nullptr) ? hostmap->resolve(addr) : 0;
  }

  // Config::SubscriptionCallbacks
  void onConfigUpdate(const ResourceVector& resources) override;
  void onConfigUpdateFailed(const EnvoyException* e) override;
  std::string resourceName(const ProtobufWkt::Any& resource) override {
    return fmt::format("{}", MessageUtil::anyConvert<cilium::NetworkPolicyHosts>(resource).policy());
  }

private:
  ThreadLocal::SlotPtr tls_;
  Stats::ScopePtr scope_;
  std::unique_ptr<Envoy::Config::Subscription<cilium::NetworkPolicyHosts>> subscription_;
  static uint64_t instance_id_;
  std::string name_;
};

} // namespace Cilium
} // namespace Envoy
