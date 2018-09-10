#include <dlfcn.h>

#include "envoy/common/exception.h"

#include "common/buffer/buffer_impl.h"
#include "common/common/assert.h"
#include "common/common/fmt.h"

#include "cilium_proxylib.h"

namespace Envoy {
namespace Cilium {

GoFilter::GoFilter(const std::string& go_module,
		   const ::google::protobuf::Map< ::std::string, ::std::string >& params) {
  if (go_module.length() > 0) {
    ::dlerror(); // clear any possible error state
    go_module_handle_ = ::dlopen(go_module.c_str(), RTLD_NOW);
    if (!go_module_handle_) {
      throw EnvoyException(fmt::format("cilium.network: Cannot load go module \'{}\': {}",
				       go_module, dlerror()));
    }

    GoInitCB go_init_module = GoInitCB(::dlsym(go_module_handle_, "InitModule"));
    if (!go_init_module) {
      throw EnvoyException(fmt::format("cilium.network: Cannot find symbol \'InitModule\' from module \'{}\': {}",
				       go_module, dlerror()));
    } else {
      // Convert params to KeyValue pairs
      auto num = params.size();
      GoString values[num][2];

      int i = 0;
      for (const auto& pair: params) {
	values[i][0] = GoString(pair.first);
	values[i++][1] = GoString(pair.second);
      }

      bool ok = go_init_module(GoKeyValueSlice(&values[0], num, num), ENVOY_LOG_CHECK_LEVEL(debug));
      if (!ok) {
	throw EnvoyException(fmt::format("cilium.network: \'{}::InitModule()\' rejected parameters",
					 go_module));
      }
    }

    go_on_new_connection_ = GoOnNewConnectionCB(::dlsym(go_module_handle_, "OnNewConnection"));
    if (!go_on_new_connection_) {
      throw EnvoyException(fmt::format("cilium.network: Cannot find symbol \'OnNewConnection\' from module \'{}\': {}",
				       go_module, dlerror()));
    }
    go_on_data_ = GoOnDataCB(::dlsym(go_module_handle_, "OnData"));
    if (!go_on_data_) {
      throw EnvoyException(fmt::format("cilium.network: Cannot find symbol \'OnData\' from module \'{}\': {}",
				       go_module, dlerror()));
    }
    go_close_ = GoCloseCB(::dlsym(go_module_handle_, "Close"));
    if (!go_close_) {
      throw EnvoyException(fmt::format("cilium.network: Cannot find symbol \'Close\' from module \'{}\': {}",
				       go_module, dlerror()));
    }
  } else {
    ENVOY_LOG(trace, "GoFilter: No go module");
  }
}

GoFilter::~GoFilter() {
  if (go_module_handle_) {
    ::dlclose(go_module_handle_);
  }
}

GoFilter::InstancePtr GoFilter::NewInstance(Network::Connection& conn, const std::string& go_proto, bool ingress,
					    uint32_t src_id, uint32_t dst_id,
					    const std::string& src_addr, const std::string& dst_addr,
					    const std::string& policy_name) {
  InstancePtr parser{nullptr};
  if (go_module_handle_) {
    parser = std::make_unique<Instance>(*this, conn);
    ENVOY_CONN_LOG(trace, "GoFilter: Calling go module", conn);
    auto res = (*go_on_new_connection_)(go_proto, conn.id(), ingress, src_id, dst_id, src_addr, dst_addr,
					policy_name,
					&parser->orig_.inject_slice_, &parser->reply_.inject_slice_);
    if (res != FILTER_OK) {
      const char *reason = "Unknown error";
      switch (res) {
      case FILTER_OK:
	reason = "No error";
	break;
      case FILTER_PARSER_ERROR:
	reason = "Parser error";
	break;
      case FILTER_UNKNOWN_CONNECTION:
	reason = "Unknown connection";
	break;
      case FILTER_UNKNOWN_PARSER:
	reason = "Unknown parser";
	break;
      case FILTER_INVALID_ADDRESS:
	reason = "Invalid address";
	break;
      case FILTER_POLICY_DROP:
	reason = "Connection rejected";
	break;
      }
      ENVOY_CONN_LOG(warn, "Cilium Network: Connection with parser \"{}\" rejected: {}", conn, go_proto, reason);
      parser.reset(nullptr);
    } else {
      parser->connection_id_ = conn.id();
    }
  }
  return parser;
}

FilterResult GoFilter::Instance::OnIO(bool reply, Buffer::Instance& data, bool end_stream) {
  auto& dir = reply ? reply_ : orig_;
  uint64_t input_len = data.length();

  // Pass bytes based on an earlier verdict?
  if (dir.pass_bytes_ > 0) {
    ASSERT(dir.drop_bytes_ == 0);      // Can't drop and pass the same bytes
    ASSERT(dir.buffer_.length() == 0); // Passed data is not buffered
    ASSERT(dir.need_bytes_ == 0);      // Passed bytes can't be needed
    if (dir.pass_bytes_ > input_len) {
      if (input_len > 0) {
	ENVOY_CONN_LOG(debug, "Cilium Network::OnIO: Passing all input: {} bytes: {} ", conn_, input_len, data.toString());
	dir.pass_bytes_ -= input_len;
      }
      return FILTER_OK; // everything was passed, nothing more to be done
    }
    // Pass of dir.pass_bytes_ is done after buffer rearrangement below
  } else {
    // Drop bytes based on an earlier verdict?
    if (dir.drop_bytes_ > 0) {
      ASSERT(dir.buffer_.length() == 0); // Dropped data is not buffered
      ASSERT(dir.need_bytes_ == 0);      // Dropped bytes can't be needed
      if (dir.drop_bytes_ > input_len) {
	if (input_len > 0) {
	  ENVOY_CONN_LOG(debug, "Cilium Network::OnIO: Dropping all input: {} bytes: {} ", conn_, input_len, data.toString());
	  dir.drop_bytes_ -= input_len;
	  data.drain(input_len);
	}
	return FILTER_OK; // everything was dropped, nothing more to be done
      }
      ENVOY_CONN_LOG(debug, "Cilium Network::OnIO: Dropping first {} bytes of input: {}", conn_, input_len, data.toString());
      data.drain(dir.drop_bytes_);
      input_len -= dir.drop_bytes_;
      dir.drop_bytes_ = 0;
      // At frame boundary, more data may remain
    }
  }

  // Move data to the end of the input buffer, use 'data' as the output buffer
  dir.buffer_.move(data);
  ASSERT(data.length() == 0);
  auto& input = dir.buffer_;
  input_len = input.length();
  auto& output = data;

  // Move pre-passed input to output.
  // Note that the case of all new input being passed is already taken care of above.
  if (dir.pass_bytes_ > 0) {
    ENVOY_CONN_LOG(debug, "Cilium Network::OnIO: Passing first {} bytes of input: {}", conn_, input_len, input.toString());
    output.move(input, dir.pass_bytes_);
    input_len -= dir.pass_bytes_;
    dir.pass_bytes_ = 0;
  }

  // Output now at frame boundary, output frame(s) injected by the reverse direction first
  if (dir.inject_slice_.len() > 0) {
    ENVOY_CONN_LOG(debug, "Cilium Network::OnIO: Reverse Injecting: {} bytes: {} ", conn_, dir.inject_slice_.len(),
		   std::string(reinterpret_cast<char *>(dir.inject_slice_.data_), dir.inject_slice_.len()));
    output.add(dir.inject_slice_.data_, dir.inject_slice_.len());
    dir.inject_slice_.reset();
  }
  
  // Do nothing if we don't have enought input (partial input remains buffered)
  if (input_len < dir.need_bytes_) {
    return FILTER_OK;
  }
  
  const int max_ops = 16; // Make shorter for testing purposes
  FilterOp ops_[max_ops];
  GoFilterOpSlice ops(ops_, max_ops);

  FilterResult res;
  bool terminal_op_seen = false;

  do {
    ops.reset();
    uint64_t num_slices = input.getRawSlices(nullptr, 0);
    Buffer::RawSlice slices[num_slices];
    input.getRawSlices(slices, num_slices);
    GoDataSlice input_slice(slices, num_slices);

    ENVOY_CONN_LOG(trace, "Cilium Network::OnIO: Calling go module, data {}", conn_, slices[0].mem_);
    res = (*parent_.go_on_data_)(connection_id_, reply, end_stream, &input_slice, &ops);
    ENVOY_CONN_LOG(trace, "Cilium Network::OnIO: \'go_on_data\' returned {}, ops({})", conn_, res, ops.len());
    if (res == FILTER_OK) {
      // Process all returned filter operations.
      for (int i = 0; i < ops.len(); i++) {
	auto op = ops_[i].op;
	auto n_bytes = ops_[i].n_bytes;

	if (n_bytes == 0) {
	  ENVOY_CONN_LOG(warn, "Cilium Network::OnIO: INVALID op ({}) length: {} bytes", conn_, op, n_bytes);
	  return FILTER_PARSER_ERROR;
	}

	if (terminal_op_seen) {
	  ENVOY_CONN_LOG(warn, "Cilium Network::OnIO: Filter operation {} after terminal opertion.", conn_, op);
	  return FILTER_PARSER_ERROR;
	}

	switch (op) {
	case FILTEROP_MORE:
	  ENVOY_CONN_LOG(debug, "Cilium Network::OnIO: FILTEROP_MORE: {} bytes", conn_, n_bytes);
	  dir.need_bytes_ = input_len + n_bytes;
	  terminal_op_seen = true;   // MORE can not be followed with other ops.
	  continue;

	case FILTEROP_PASS:
	  ENVOY_CONN_LOG(debug, "Cilium Network::OnIO: FILTEROP_PASS: {} bytes", conn_, n_bytes);
	  if (n_bytes > input_len) {
	    output.move(input, input_len);
	    dir.pass_bytes_ = n_bytes - input_len; // pass the remainder later
	    input_len = 0;
	    terminal_op_seen = true;   // PASS more than input is terminal operation.
	    continue;
	  }
	  output.move(input, n_bytes);
	  input_len -= n_bytes;
	  break;

	case FILTEROP_DROP:
	  ENVOY_CONN_LOG(debug, "Cilium Network::OnIO: FILTEROP_DROP: {} bytes", conn_, n_bytes);
	  if (n_bytes > input_len) {
	    input.drain(input_len);
	    dir.drop_bytes_ = n_bytes - input_len; // drop the remainder later
	    input_len = 0;
	    terminal_op_seen = true;   // DROP more than input is terminal operation.
	    continue;
	  }
	  input.drain(n_bytes);
	  input_len -= n_bytes;
	  break;

	case FILTEROP_INJECT:
	  if (n_bytes > dir.inject_slice_.len()) {
	    ENVOY_CONN_LOG(warn, "Cilium Network::OnIO: FILTEROP_INJECT: INVALID length: {} bytes", conn_, n_bytes);
	    return FILTER_PARSER_ERROR;
	  }
	  ENVOY_CONN_LOG(debug, "Cilium Network::OnIO: FILTEROP_INJECT: {} bytes: {}", conn_, n_bytes,
			 std::string(reinterpret_cast<char *>(dir.inject_slice_.data_), dir.inject_slice_.len()));
	  output.add(dir.inject_slice_.data_, n_bytes);
	  dir.inject_slice_.drain(n_bytes);
	  break;

	case FILTEROP_ERROR:
	default:
	  ENVOY_CONN_LOG(warn, "Cilium Network::OnIO: FILTEROP_ERROR: {} bytes", conn_, n_bytes);
	  return FILTER_PARSER_ERROR;
	}
      }
    } else {
      // Close the connection an any error
      switch (res) {
      case FILTER_POLICY_DROP:
	ENVOY_CONN_LOG(warn, "Cilium Network::OnIO: FILTER_POLICY_DROP", conn_);
	break;

      case FILTER_PARSER_ERROR:
	ENVOY_CONN_LOG(warn, "Cilium Network::OnIO: FILTER_PARSER_ERROR", conn_);
	break;

      case FILTER_UNKNOWN_PARSER:
	ENVOY_CONN_LOG(warn, "Cilium Network::OnIO: FILTER_UNKNOWN_PARSER", conn_);
	break;

      case FILTER_UNKNOWN_CONNECTION:
	ENVOY_CONN_LOG(warn, "Cilium Network::OnIO: FILTER_UNKNOWN_CONNECTION", conn_);
	break;

      case FILTER_INVALID_ADDRESS:
	ENVOY_CONN_LOG(warn, "Cilium Network::OnIO: FILTER_INVALID_ADDRESS", conn_);
	break;

      case FILTER_OK:
	break;
      }
      return FILTER_PARSER_ERROR;
    }

    // Make space for more injected data
    dir.inject_slice_.reset();

  } while (!terminal_op_seen && ops.len() == max_ops);

  if (output.length() < 100) {
    ENVOY_CONN_LOG(debug, "Cilium Network::OnIO: Output on return: {}", conn_, output.toString());
  } else {
    ENVOY_CONN_LOG(debug, "Cilium Network::OnIO: Output length return: {}", conn_, output.length());
  }
  return res;
}

void GoFilter::Instance::Close() {
  (*parent_.go_close_)(connection_id_);
  connection_id_ = 0;
  conn_.close(Network::ConnectionCloseType::NoFlush);
}

} // namespace Cilium
} // namespace Envoy
