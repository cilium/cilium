#pragma once

#include <arpa/inet.h>

#include "envoy/local_info/local_info.h"
#include "envoy/upstream/cluster_manager.h"
#include "envoy/event/dispatcher.h"

#include "common/common/logger.h"
#include "envoy/config/subscription.h"
#include "envoy/singleton/instance.h"
#include "envoy/thread_local/thread_local.h"

#include "cilium/nphds.pb.h"

#include "absl/numeric/int128.h"

namespace std {
  template <> struct hash<absl::uint128>
  {
    size_t operator()(const absl::uint128& x) const
    {
      return hash<uint64_t>{}(absl::Uint128Low64(x)) ^ (hash<uint64_t>{}(absl::Uint128High64(x)) << 1);
    }
  };
}

namespace Envoy {
namespace Cilium {

enum ID : uint64_t { UNKNOWN = 0, WORLD = 2 };

class PolicyHostMap : public Singleton::Instance,
                      Config::SubscriptionCallbacks<cilium::NetworkPolicyHosts>,
                      public Logger::Loggable<Logger::Id::config> {
public:
  PolicyHostMap(const envoy::api::v2::core::Node& node,
		Upstream::ClusterManager& cm, Event::Dispatcher& dispatcher,
		Stats::Scope &scope, ThreadLocal::SlotAllocator& tls);
  PolicyHostMap(std::unique_ptr<Envoy::Config::Subscription<cilium::NetworkPolicyHosts>>&& subscription,
		ThreadLocal::SlotAllocator& tls);
  ~PolicyHostMap() {}

  struct ThreadLocalHostMap : public ThreadLocal::ThreadLocalObject {
  public:
    void insert(const cilium::NetworkPolicyHosts& proto) {
      uint64_t policy = proto.policy();
      const auto& hosts = proto.host_addresses();

      for (const auto& host: hosts) {
	uint32_t addr4;
	int rc = inet_pton(AF_INET, host.c_str(), &addr4);
	if (rc == 1) {
	  auto pair = ipv4_to_policy_.emplace(std::make_pair(addr4, policy));
	  if (pair.second == false) {
	    throw EnvoyException(fmt::format("NetworkPolicyHosts: Duplicate host entry {}:{}", host, policy));
	  }
	  continue;
	}
	absl::uint128 addr6;
	rc = inet_pton(AF_INET6, host.c_str(), &addr6);
	if (rc == 1) {
	  auto pair = ipv6_to_policy_.emplace(std::make_pair(addr6, policy));
	  if (pair.second == false) {
	    throw EnvoyException(fmt::format("NetworkPolicyHosts: Duplicate host entry {}:{}", host, policy));
	  }
	  continue;
	}
	throw EnvoyException(fmt::format("NetworkPolicyHosts: Invalid host entry {}:{}", host, policy));
      }
    }

    uint64_t resolve(const Network::Address::Ip* addr) const {
      auto* ipv4 = addr->ipv4();
      if (ipv4) {
	auto it = ipv4_to_policy_.find(ipv4->address());
	if (it != ipv4_to_policy_.end()) {
	  return it->second;
	}
      } else {
	auto* ipv6 = addr->ipv6();
	if (ipv6) {
	  auto it = ipv6_to_policy_.find(ipv6->address());
	  if (it != ipv6_to_policy_.end()) {
	    return it->second;
	  }
	}
      }
      return ID::WORLD;
    }

  private:
    std::unordered_map<uint32_t, uint64_t> ipv4_to_policy_;
    std::unordered_map<absl::uint128, uint64_t> ipv6_to_policy_;
  };
  typedef std::shared_ptr<ThreadLocalHostMap> ThreadLocalHostMapSharedPtr;

  const ThreadLocalHostMap* getHostMap() const {
    return &tls_->getTyped<ThreadLocalHostMap>();
  }

  uint64_t resolve(const Network::Address::Ip* addr) const {
    const ThreadLocalHostMap* hostmap = getHostMap();
    return (hostmap != nullptr) ? hostmap->resolve(addr) : ID::UNKNOWN;
  }

  // Config::SubscriptionCallbacks
  void onConfigUpdate(const ResourceVector& resources) override;
  void onConfigUpdateFailed(const EnvoyException* e) override;
  std::string resourceName(const ProtobufWkt::Any& resource) override {
    return fmt::format("{}", MessageUtil::anyConvert<cilium::NetworkPolicyHosts>(resource).policy());
  }

private:
  ThreadLocal::SlotPtr tls_;
  std::unique_ptr<Envoy::Config::Subscription<cilium::NetworkPolicyHosts>> subscription_;
  const ThreadLocalHostMapSharedPtr null_hostmap_{nullptr};
};

} // namespace Cilium
} // namespace Envoy
