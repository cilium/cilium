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
  ENVOY_LOG(info, "GoFilter: Opening go module {}", go_module);
  ::dlerror(); // clear any possible error state
  go_module_handle_ = ::dlopen(go_module.c_str(), RTLD_NOW);
  if (!go_module_handle_) {
    throw EnvoyException(fmt::format("cilium.network: Cannot load go module \'{}\': {}",
				     go_module, dlerror()));
  }

  go_close_module_ = GoCloseModuleCB(::dlsym(go_module_handle_, "CloseModule"));
  if (!go_close_module_) {
    throw EnvoyException(fmt::format("cilium.network: Cannot find symbol \'CloseModule\' from module \'{}\': {}",
				     go_module, dlerror()));
  }
  GoOpenModuleCB go_open_module = GoOpenModuleCB(::dlsym(go_module_handle_, "OpenModule"));
  if (!go_open_module) {
    throw EnvoyException(fmt::format("cilium.network: Cannot find symbol \'OpenModule\' from module \'{}\': {}",
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

    go_module_id_ = go_open_module(GoKeyValueSlice(&values[0], num), ENVOY_LOG_CHECK_LEVEL(debug));
    if (go_module_id_ == 0) {
      throw EnvoyException(fmt::format("cilium.network: \'{}::OpenModule()\' rejected parameters",
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
}

GoFilter::~GoFilter() {
  if (go_module_id_ != 0) {
    go_close_module_(go_module_id_);
  }
  if (go_module_handle_) {
    ::dlclose(go_module_handle_);
  }
}

namespace {

const char* filter_strerror(FilterResult res) {
  switch (res) {
  case FILTER_OK:
    return "No error";
  case FILTER_PARSER_ERROR:
    return "Parser error";
  case FILTER_UNKNOWN_CONNECTION:
    return "Unknown connection";
  case FILTER_UNKNOWN_PARSER:
    return "Unknown parser";
  case FILTER_INVALID_ADDRESS:
    return "Invalid address";
  case FILTER_POLICY_DROP:
    return "Connection rejected";
  case FILTER_INVALID_INSTANCE:
    return "Invalid proxylib instance";
  case FILTER_UNKNOWN_ERROR:
    break;
  }
  return "Unknown error";
}

}

GoFilter::InstancePtr GoFilter::NewInstance(Network::Connection& conn, const std::string& go_proto, bool ingress,
					    uint32_t src_id, uint32_t dst_id,
					    const std::string& src_addr, const std::string& dst_addr,
					    const std::string& policy_name) const {
  InstancePtr parser{nullptr};
  if (go_module_handle_) {
    parser = std::make_unique<Instance>(*this, conn);
    ENVOY_CONN_LOG(trace, "GoFilter: Calling go module", conn);
    auto res = (*go_on_new_connection_)(go_module_id_, go_proto, conn.id(), ingress, src_id, dst_id, src_addr, dst_addr,
					policy_name,
					&parser->orig_.inject_slice_, &parser->reply_.inject_slice_);
    if (res == FILTER_OK) {
      parser->connection_id_ = conn.id();
    } else {
      ENVOY_CONN_LOG(warn, "Cilium Network: Connection with parser \"{}\" rejected: {}", conn, go_proto,
		     filter_strerror(res));
      parser.reset(nullptr);
    }
  }
  return parser;
}

FilterResult GoFilter::Instance::OnIO(bool reply, Buffer::Instance& data, bool end_stream) {
  auto& dir = reply ? reply_ : orig_;
  int64_t input_len = data.length();

  // Pass bytes based on an earlier verdict?
  if (dir.pass_bytes_ > 0) {
    ASSERT(dir.drop_bytes_ == 0);      // Can't drop and pass the same bytes
    ASSERT(dir.buffer_.length() == 0); // Passed data is not buffered
    ASSERT(dir.need_bytes_ == 0);      // Passed bytes can't be needed
    // Can return immediately if passing more that we have input.
    // May need to process injected data even when there is no input left.
    if (dir.pass_bytes_ > input_len) {
      if (input_len > 0) {
	ENVOY_CONN_LOG(debug, "Cilium Network::OnIO: Passing all input: {} bytes: {} ", conn_, input_len, data.toString());
	dir.pass_bytes_ -= input_len;
      }
      return FILTER_OK; // all of 'data' is passed to the next filter
    }
    // Pass of dir.pass_bytes_ is done after buffer rearrangement below.
    // Using the available APIs it is easier to move data from the beginning of a buffer to another
    // rather than from the end of a buffer to another.
  } else {
    // Drop bytes based on an earlier verdict?
    if (dir.drop_bytes_ > 0) {
      ASSERT(dir.buffer_.length() == 0); // Dropped data is not buffered
      ASSERT(dir.need_bytes_ == 0);      // Dropped bytes can't be needed
      // Can return immediately if passing more that we have input.
      // May need to process injected data even when there is no input left.
      if (dir.drop_bytes_ > input_len) {
	if (input_len > 0) {
	  ENVOY_CONN_LOG(debug, "Cilium Network::OnIO: Dropping all input: {} bytes: {} ", conn_, input_len, data.toString());
	  dir.drop_bytes_ -= input_len;
	  data.drain(input_len);
	}
	return FILTER_OK; // everything was dropped, nothing more to be done
      }
      ENVOY_CONN_LOG(debug, "Cilium Network::OnIO: Dropping first {} bytes of input: {}", conn_, dir.drop_bytes_, data.toString());
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
    // At frame boundary, more data may remain
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
    Buffer::RawSlice raw_slices[num_slices];
    input.getRawSlices(raw_slices, num_slices);

    int64_t total_length = 0;
    GoSlice<uint8_t> buffer_slices[num_slices];
    uint64_t non_empty_slices = 0;
    for (uint64_t i = 0; i < num_slices; i++) {
      if (raw_slices[i].len_ > 0) {
	buffer_slices[non_empty_slices++] = GoSlice<uint8_t>(reinterpret_cast<uint8_t*>(raw_slices[i].mem_), raw_slices[i].len_);
	total_length += raw_slices[i].len_;
      }
    }
    GoDataSlices input_slices(buffer_slices, non_empty_slices);

    ENVOY_CONN_LOG(trace, "Cilium Network::OnIO: Calling go module, data starting at {}, {} bytes", conn_, raw_slices[0].mem_, total_length);
    res = (*parent_.go_on_data_)(connection_id_, reply, end_stream, &input_slices, &ops);
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
	  continue;                  // errors out if more operations follow

	case FILTEROP_PASS:
	  ENVOY_CONN_LOG(debug, "Cilium Network::OnIO: FILTEROP_PASS: {} bytes", conn_, n_bytes);
	  if (n_bytes > input_len) {
	    output.move(input, input_len);
	    dir.pass_bytes_ = n_bytes - input_len; // pass the remainder later
	    input_len = 0;
	    terminal_op_seen = true;   // PASS more than input is terminal operation.
	    continue;                  // errors out if more operations follow
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
	    continue;                  // errors out if more operations follow
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
      ENVOY_CONN_LOG(warn, "Cilium Network::OnIO: FILTER_POLICY_DROP {}", conn_, filter_strerror(res));
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
