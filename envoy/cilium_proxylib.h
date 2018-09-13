#pragma once

#include "envoy/network/connection.h"
#include "envoy/singleton/instance.h"

#include "common/buffer/buffer_impl.h"
#include "common/common/logger.h"

#include "proxylib/libcilium.h"

#include <google/protobuf/map.h>

namespace Envoy {
namespace Cilium {

// GoString has the same layout as Buffer::RawSlice
struct GoString {
  GoString(const std::string& str) : mem_(str.c_str()), len_(str.length()) {
    ASSERT(sizeof(*this) == sizeof(Buffer::RawSlice) &&
	   offsetof(Buffer::RawSlice, len_) == offsetof(struct GoString, len_));
  }
  GoString() : mem_(nullptr), len_(0) {}
  const char* mem_;
  GoInt len_;
};

template <typename T>
struct GoSlice {
GoSlice(T* data, GoInt len, GoInt cap) : data_(data), len_(len), cap_(cap), base_(data) {}
GoSlice(T* data, GoInt cap) : data_(data), len_(0), cap_(cap), base_(data) {}
  GoInt len() const { return len_; }
  GoInt cap() const { return cap_; }
  T& operator[] (GoInt x) { return data_[x]; }
  const T& operator[] (GoInt x) const { return data_[x]; }
  operator T*() { return data_; }
  operator const T*() const { return data_; }
  operator void*() { return data_; }
  operator const void*() const { return data_; }

  // Non-Go helpers to consume data filled in by Go. Must reset() before slice used by Go again.
  GoInt drain(GoInt len) {
    if (len > len_) {
      len = len_;
    }
    data_ += len;
    len_ -= len;

    return len;
  }
  void reset() {
    data_ = base_;
    len_ = 0;
  }
  
  T*    data_;
  GoInt len_;
  GoInt cap_;

  // private part not visible to Go
  T* base_;
};

struct GoDataSlice : GoSlice<const GoString> {
  GoDataSlice(const Buffer::RawSlice* data, size_t ndata)
    : GoSlice<const GoString>(reinterpret_cast<const GoString*>(data), ndata, ndata) {}
};

typedef GoSlice<uint8_t> GoBufferSlice;
typedef GoSlice<FilterOp> GoFilterOpSlice;

typedef GoSlice<GoString[2]> GoKeyValueSlice;

typedef bool (*GoInitCB)(GoKeyValueSlice, bool);
typedef FilterResult (*GoOnNewConnectionCB)(GoString, uint64_t, bool, uint32_t, uint32_t, GoString, GoString, GoString, GoBufferSlice*, GoBufferSlice*);
typedef FilterResult (*GoOnDataCB)(uint64_t, bool, bool, GoDataSlice*, GoFilterOpSlice*);
typedef void (*GoCloseCB)(uint64_t);

class GoFilter : public Singleton::Instance, public Logger::Loggable<Logger::Id::filter> {
public:
  GoFilter(const std::string& go_module, const ::google::protobuf::Map< ::std::string, ::std::string >&);
  ~GoFilter();

  class Instance : public Logger::Loggable<Logger::Id::filter>{
  public:
    Instance(const GoFilter& parent, Network::Connection& conn) : parent_(parent), conn_(conn) {}
    ~Instance() {
      if (connection_id_) {
	// Tell Go parser to scrap the state kept for the connection
	(*parent_.go_close_)(connection_id_);
      }
    }

    void Close();

    FilterResult OnIO(bool reply, Buffer::Instance& data, bool end_stream);

    bool WantReplyInject() const { return reply_.WantToInject(); }
    void SetOrigEndStream(bool end_stream) { orig_.closed_ = end_stream; }
    void SetReplyEndStream(bool end_stream) { reply_.closed_ = end_stream; }

    struct Direction {
      Direction() : inject_slice_(inject_buf_, sizeof(inject_buf_)) {}

      bool WantToInject() const { return !closed_ && inject_slice_.len() > 0; }
      void Close() { closed_ = true; }
      
      Buffer::OwnedImpl buffer_; // Buffered data in this direction
      uint64_t need_bytes_{0};   // Number of additional data bytes needed before can parse again
      uint64_t pass_bytes_{0};   // Number of bytes to pass without calling the parser again
      uint64_t drop_bytes_{0};
      bool closed_{false};
      GoBufferSlice inject_slice_;
      uint8_t inject_buf_[1024];
    };

    const GoFilter& parent_;
    Network::Connection& conn_;
    Direction orig_;
    Direction reply_;
    uint64_t connection_id_ = 0;
  };
  typedef std::unique_ptr<Instance> InstancePtr;

  InstancePtr NewInstance(Network::Connection& conn, const std::string& go_proto, bool ingress,
			  uint32_t src_id, uint32_t dst_id,
			  const std::string& src_addr, const std::string& dst_addr, const std::string& policy_name) const;

private:
  void *go_module_handle_{nullptr};
  GoOnNewConnectionCB go_on_new_connection_;
  GoOnDataCB go_on_data_;
  GoCloseCB go_close_;
};

typedef std::shared_ptr<const GoFilter> GoFilterSharedPtr;

} // namespace Cilium
} // namespace Envoy
