#include "proxymap.h"

#include <arpa/inet.h>
#include <string.h>

#include <cstdint>

#include "common/network/address_impl.h"

#include "linux/bpf.h"

namespace Envoy {
namespace Cilium {

// These must be kept in sync with Cilium source code, should refactor
// them to a separate include file we can include here instead of
// copying them!

typedef uint32_t __be32; // Beware of the byte order!
typedef uint32_t __u32;
typedef uint16_t __u16;
typedef uint8_t __u8;

struct proxy4_tbl_key {
  __be32 saddr;
  __u16 dport; /* dport must be in front of sport, loaded with 4 bytes read */
  __u16 sport;
  __u8 nexthdr;
  __u8 pad;
} __attribute__((packed));

struct proxy4_tbl_value {
  __be32 orig_daddr;
  __u16 orig_dport;
  __u16 pad;
  __u32 identity;
  __u32 lifetime;
} __attribute__((packed));

struct proxy6_tbl_key {
  __be32 saddr[4];
  __u16 dport;
  __u16 sport;
  __u8 nexthdr;
  __u8 pad;
} __attribute__((packed));

struct proxy6_tbl_value {
  __be32 orig_daddr[4];
  __u16 orig_dport;
  __u16 pad;
  __u32 identity;
  __u32 lifetime;
} __attribute__((packed));

ProxyMap::Proxy4Map::Proxy4Map()
    : Bpf(BPF_MAP_TYPE_HASH, sizeof(struct proxy4_tbl_key),
          sizeof(struct proxy4_tbl_value)) {}

ProxyMap::Proxy6Map::Proxy6Map()
    : Bpf(BPF_MAP_TYPE_HASH, sizeof(struct proxy6_tbl_key),
          sizeof(struct proxy6_tbl_value)) {}

ProxyMap::ProxyMap(const std::string &bpf_root) : bpf_root_(bpf_root) {
  // Open the bpf maps from Cilium specific paths

  std::string path4(bpf_root_ + "/tc/globals/cilium_proxy4");
  if (!proxy4map_.open(path4)) {
    ENVOY_LOG(info, "cilium.bpf_metadata: Cannot open IPv4 proxy map at {}", path4);
  }

  std::string path6(bpf_root_ + "/tc/globals/cilium_proxy6");
  if (!proxy6map_.open(path6)) {
    ENVOY_LOG(info, "cilium.bpf_metadata: Cannot open IPv6 proxy map at {}", path6);
  }

  ENVOY_LOG(trace, "cilium.bpf_metadata: Created proxymap.");
}

bool ProxyMap::getBpfMetadata(Network::ConnectionSocket &socket, uint32_t* identity, uint16_t* orig_dport, uint16_t* proxy_port) {
  Network::Address::InstanceConstSharedPtr local_address =
      socket.localAddress();
  Network::Address::InstanceConstSharedPtr remote_address =
      socket.remoteAddress();

  if (local_address->type() == Network::Address::Type::Ip &&
      remote_address->type() == Network::Address::Type::Ip) {
    const auto &ip = local_address->ip();
    const auto &rip = remote_address->ip();

    if (ip->version() == Network::Address::IpVersion::v4 &&
        rip->version() == Network::Address::IpVersion::v4) {
      struct proxy4_tbl_key key {};
      struct proxy4_tbl_value value {};

      key.saddr = rip->ipv4()->address();
      key.dport = htons(ip->port());
      key.sport = htons(rip->port());
      key.nexthdr = 6;

      ENVOY_LOG(
          trace,
          "cilium.bpf_metadata: Looking up key: {:x}, {:x}, {:x}, {:x}, {:x}",
          ntohl(key.saddr), ntohs(key.dport), ntohs(key.sport), key.nexthdr,
          key.pad);

      if (proxy4map_.lookup(&key, &value)) {
        struct sockaddr_in ip4 {};
        ip4.sin_family = AF_INET;
        ip4.sin_addr.s_addr = value.orig_daddr; // already in network byte order
        ip4.sin_port = value.orig_dport;        // already in network byte order
        Network::Address::InstanceConstSharedPtr orig_local_address =
            std::make_shared<Network::Address::Ipv4Instance>(&ip4);
	if (*orig_local_address != *socket.localAddress()) {
	  socket.setLocalAddress(orig_local_address, true);
	}
        *identity = value.identity;
	*proxy_port = ntohs(key.dport);
        *orig_dport = ntohs(value.orig_dport);
        return true;
      }
      ENVOY_LOG(info, "cilium.bpf_metadata: IPv4 bpf map lookup failed: {}",
                strerror(errno));
    } else if (ip->version() == Network::Address::IpVersion::v6 &&
               rip->version() == Network::Address::IpVersion::v6) {
      struct proxy6_tbl_key key {};
      struct proxy6_tbl_value value {};

      absl::uint128 saddr = rip->ipv6()->address();
      memcpy(&key.saddr, &saddr, 16);
      key.dport = htons(ip->port());
      key.sport = htons(rip->port());
      key.nexthdr = 6;

      if (proxy6map_.lookup(&key, &value)) {
        struct sockaddr_in6 ip6 {};
        ip6.sin6_family = AF_INET6;
        memcpy(&ip6.sin6_addr, &value.orig_daddr, 16);
        ip6.sin6_port = value.orig_dport; // already in network byte order
        Network::Address::InstanceConstSharedPtr orig_local_address =
            std::make_shared<Network::Address::Ipv6Instance>(ip6);
	if (*orig_local_address != *socket.localAddress()) {
	  socket.setLocalAddress(orig_local_address, true);
	}
        *identity = value.identity;
	*proxy_port = ntohs(key.dport);
        *orig_dport = ntohs(value.orig_dport);
        return true;
      }
      ENVOY_LOG(info, "cilium.bpf_metadata: IPv6 bpf map lookup failed: {}",
                strerror(errno));
    } else {
      ENVOY_LOG(
          info,
          "cilium.bpf_metadata: Address type mismatch: Source: {}, Dest: {}",
          rip->addressAsString(), ip->addressAsString());
    }
  }
  return false;
}

bool ProxyMap::removeBpfMetadata(Network::Connection &conn, uint16_t proxy_port) {
  Network::Address::InstanceConstSharedPtr local_address = conn.localAddress();
  Network::Address::InstanceConstSharedPtr remote_address = conn.remoteAddress();

  if (local_address->type() == Network::Address::Type::Ip &&
      remote_address->type() == Network::Address::Type::Ip) {
    const auto &ip = local_address->ip();
    const auto &rip = remote_address->ip();

    if (ip->version() == Network::Address::IpVersion::v4 &&
        rip->version() == Network::Address::IpVersion::v4) {
      struct proxy4_tbl_key key {};

      key.saddr = rip->ipv4()->address();
      key.dport = htons(proxy_port);
      key.sport = htons(rip->port());
      key.nexthdr = 6;

      ENVOY_CONN_LOG(
          trace,
          "cilium.bpf_metadata: Deleting key: {:x}, {:x}, {:x}, {:x}, {:x}", conn,
          ntohl(key.saddr), ntohs(key.dport), ntohs(key.sport), key.nexthdr,
          key.pad);

      if (proxy4map_.remove(&key)) {
        return true;
      }
      ENVOY_CONN_LOG(info, "cilium.bpf_metadata: IPv4 bpf proxymap remove failed: {}", conn,
                strerror(errno));
    } else if (ip->version() == Network::Address::IpVersion::v6 &&
               rip->version() == Network::Address::IpVersion::v6) {
      struct proxy6_tbl_key key {};

      absl::uint128 saddr = rip->ipv6()->address();
      memcpy(&key.saddr, &saddr, 16);
      key.dport = htons(proxy_port);
      key.sport = htons(rip->port());
      key.nexthdr = 6;

      if (proxy6map_.remove(&key)) {
        return true;
      }
      ENVOY_CONN_LOG(info, "cilium.bpf_metadata: IPv6 bpf proxymap remove failed: {}", conn,
                strerror(errno));
    } else {
      ENVOY_CONN_LOG(
          info,
          "cilium.bpf_metadata: IP address type mismatch: Source: {}, Dest: {}", conn,
          rip->addressAsString(), ip->addressAsString());
    }
  } else {
    ENVOY_CONN_LOG(
	info,
        "cilium.bpf_metadata: Address type mismatch: Source: {}, Dest: {}", conn,
        remote_address->asString(), local_address->asString());
  }
  return false;
}

} // namespace Cilium
} // namespace Envoy
