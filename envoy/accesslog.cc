#include "accesslog.h"

#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "common/common/utility.h"

namespace Envoy {
namespace Cilium {

std::mutex AccessLog::logs_mutex;
std::map<std::string, AccessLogPtr> AccessLog::logs;

AccessLog *AccessLog::Open(std::string path) {
  std::lock_guard<std::mutex> guard1(logs_mutex);
  AccessLog *log;
  auto it = logs.find(path);
  if (it != logs.end()) {
    log = it->second.get();
    std::lock_guard<std::mutex> guard2(log->fd_mutex_);
    log->open_count_++;
    return log;
  }
  // Not found, open
  log = new AccessLog(path);
  if (!log->Connect()) {
    delete log;
    return nullptr;
  }
  logs.emplace(path, AccessLogPtr{log});
  return log;
}

void AccessLog::Close() {
  std::lock_guard<std::mutex> guard1(logs_mutex);
  std::lock_guard<std::mutex> guard2(fd_mutex_);
  open_count_--;

  if (open_count_ > 0) {
    return;
  }
  if (fd_ != -1) {
    ::close(fd_);
    fd_ = -1;
  }

  logs.erase(path_);
}

AccessLog::AccessLog(std::string path) : path_(path), fd_(-1), open_count_(1) {}

AccessLog::~AccessLog() {}

void AccessLog::Entry::InitFromRequest(std::string listener_id,
                                       const Network::Connection *conn,
                                       const Http::HeaderMap &headers,
                                       const Http::AccessLog::RequestInfo &info,
                                       const Router::RouteEntry *route) {
  auto time = info.startTime();
  entry.set_timestamp(std::chrono::duration_cast<std::chrono::nanoseconds>(
                          time.time_since_epoch())
                          .count());

  ::pb::cilium::Protocol proto;
  switch (info.protocol()) {
  case Http::Protocol::Http10:
    proto = ::pb::cilium::Protocol::HTTP10;
    break;
  case Http::Protocol::Http11:
  default: // Just to make compiler happy
    proto = ::pb::cilium::Protocol::HTTP11;
    break;
  case Http::Protocol::Http2:
    proto = ::pb::cilium::Protocol::HTTP2;
    break;
  }
  entry.set_http_protocol(proto);

  entry.set_cilium_resource_name(listener_id);

  // Get rule reference from the opaque config of the route entry
  if (route) {
    auto ocmap = route->opaqueConfig();
    auto it = ocmap.find("cilium_rule_ref");
    if (it != ocmap.end()) {
      entry.set_cilium_rule_ref(it->second);
    }
  }

  if (conn) {
    entry.set_source_security_id(conn->socketMark() & 0xffff);
    entry.set_source_address(conn->remoteAddress().asString());
    entry.set_destination_address(conn->localAddress().asString());
  }

  // request headers
  headers.iterate(
      [](const Http::HeaderEntry &header, void *entry_) -> void {
        const Http::HeaderString &key = header.key();
        const char *value = header.value().c_str();
        ::pb::cilium::HttpLogEntry *entry =
            static_cast<::pb::cilium::HttpLogEntry *>(entry_);

        if (key == ":path") {
          entry->set_path(value);
        } else if (key == ":method") {
          entry->set_method(value);
        } else if (key == ":authority") {
          entry->set_host(value);
        } else if (key == "x-forwarded-proto") {
	  // Envoy sets the ":scheme" header later in the router filter according to
	  // the upstream protocol (TLS vs. clear), but we want to get the downstream
	  // scheme, which is provided in "x-forwarded-proto".
          entry->set_scheme(value);
        } else {
          ::pb::cilium::KeyValue *kv = entry->add_headers();
          kv->set_key(key.c_str());
          kv->set_value(value);
        }
      },
      &entry);
}

void AccessLog::Entry::UpdateFromResponse(
    const Http::HeaderMap &headers, const Http::AccessLog::RequestInfo &info) {
  auto time = info.startTime() + info.duration();
  entry.set_timestamp(std::chrono::duration_cast<std::chrono::nanoseconds>(
                          time.time_since_epoch())
                          .count());

  auto rc = info.responseCode();
  if (rc.valid()) {
    entry.set_status(rc.value());
  } else {
    // Find response code from response headers
    headers.iterate(
        [](const Http::HeaderEntry &header, void *entry_) -> void {
          if (header.key() == ":status") {
            uint64_t status;
            if (StringUtil::atoul(header.value().c_str(), status, 10)) {
              static_cast<::pb::cilium::HttpLogEntry *>(entry_)->set_status(
                  status);
            }
          }
        },
        &entry);
  }
}

void AccessLog::Log(AccessLog::Entry &entry_,
                    ::pb::cilium::EntryType entry_type) {
  ::pb::cilium::HttpLogEntry &entry = entry_.entry;

  entry.set_entry_type(entry_type);

  if (Connect()) {
    // encode protobuf
    std::string msg;
    entry.SerializeToString(&msg);
    ssize_t length = msg.length();
    ssize_t sent =
        ::send(fd_, msg.data(), length, MSG_DONTWAIT | MSG_EOR | MSG_NOSIGNAL);
    if (sent == length) {
      ENVOY_LOG(debug, "Cilium access log msg sent: {}", entry.DebugString());
      return;
    }
    if (sent == -1) {
      ENVOY_LOG(warn, "Cilium access log send failed: {}", strerror(errno));
    } else {
      ENVOY_LOG(warn, "Cilium access log send truncated by {} bytes.",
                length - sent);
    }
  }
  // Log the message in Envoy logs if it could not be sent to Cilium
  ENVOY_LOG(debug, "Cilium access log msg: {}", entry.DebugString());
}

bool AccessLog::Connect() {
  if (fd_ != -1) {
    return true;
  }
  if (path_.length() == 0) {
    return false;
  }
  std::lock_guard<std::mutex> guard(fd_mutex_);

  fd_ = ::socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if (fd_ == -1) {
    ENVOY_LOG(warn, "Can't create socket: {}", strerror(errno));
    return false;
  }

  struct sockaddr_un addr = {.sun_family = AF_UNIX, .sun_path = {}};
  strncpy(addr.sun_path, path_.c_str(), sizeof(addr.sun_path) - 1);
  if (::connect(fd_, reinterpret_cast<struct sockaddr *>(&addr),
                sizeof(addr)) == -1) {
    ENVOY_LOG(warn, "Connect to {} failed: {}", path_, strerror(errno));
    ::close(fd_);
    fd_ = -1;
    return false;
  }

  return true;
}

} // namespace Cilium
} // namespace Envoy
