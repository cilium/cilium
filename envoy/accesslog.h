#pragma once

#include <map>
#include <mutex>
#include <string>

#include "envoy/http/access_log.h"
#include "envoy/http/header_map.h"
#include "envoy/network/connection.h"
#include "envoy/router/router.h"

#include "common/common/logger.h"

#include "accesslog.pb.h"

namespace Envoy {
namespace Cilium {

class AccessLog : Logger::Loggable<Logger::Id::router> {
public:
  static AccessLog *Open(std::string path);
  void Close();

  // wrapper for protobuf
  class Entry {
  public:
    void InitFromRequest(std::string listener_id, const Network::Connection *,
                         const Http::HeaderMap &,
                         const Http::AccessLog::RequestInfo &,
                         const Router::RouteEntry *);
    void UpdateFromResponse(const Http::HeaderMap &,
                            const Http::AccessLog::RequestInfo &);

    ::pb::cilium::HttpLogEntry entry{};
  };
  void Log(Entry &entry, ::pb::cilium::EntryType);

  ~AccessLog();

private:
  static std::mutex logs_mutex;
  static std::map<std::string, std::unique_ptr<AccessLog>> logs;

  AccessLog(std::string path);

  bool Connect();

  const std::string path_;
  std::mutex fd_mutex_;
  int fd_;
  int open_count_;
};

typedef std::unique_ptr<AccessLog> AccessLogPtr;

} // namespace Cilium
} // namespace Envoy
