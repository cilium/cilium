#include "bpf.h"

#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "linux/bpf.h"

namespace Envoy {
namespace Cilium {

enum {
  BPF_KEY_MAX_LEN = 64,
};

Bpf::Bpf(uint32_t map_type, uint32_t key_size, uint32_t value_size)
    : fd_(-1), map_type_(map_type), key_size_(key_size),
      value_size_(value_size) {
  struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
  setrlimit(RLIMIT_MEMLOCK, &rl);
}

Bpf::~Bpf() { close(); }

void Bpf::close() {
  if (fd_ >= 0)
    ::close(fd_);
  fd_ = -1;
}

bool Bpf::open(const std::string &path) {
  union bpf_attr attr = {};
  attr.pathname = uintptr_t(path.c_str());

  fd_ = bpfSyscall(BPF_OBJ_GET, &attr);
  if (fd_ >= 0) {
    // Open fdinfo to check the map type and key and value size.
    std::string line;
    std::ifstream bpf_file("/proc/" + std::to_string(getpid()) + "/fdinfo/" +
                           std::to_string(fd_));
    if (bpf_file.is_open()) {
      uint32_t map_type = UINT32_MAX, key_size = UINT32_MAX,
               value_size = UINT32_MAX;

      while (std::getline(bpf_file, line)) {
        std::istringstream iss(line);
        std::string tag;

        if (std::getline(iss, tag, ':')) {
          unsigned int value;

          if (iss >> value) {
            if (tag == "map_type") {
              map_type = value;
            } else if (tag == "key_size") {
              key_size = value;
            } else if (tag == "value_size") {
              value_size = value;
            }
          }
        }
      }
      bpf_file.close();

      if (map_type == map_type_ && key_size == key_size_ &&
          value_size == value_size_) {
        return true;
      }
    }
    close();
  }

  return false;
}

bool Bpf::create(uint32_t max_entries, uint32_t flags) {
  union bpf_attr attr = {};
  attr.map_type = map_type_;
  attr.key_size = key_size_;
  attr.value_size = value_size_;
  attr.max_entries = max_entries;
  attr.map_flags = flags;

  fd_ = bpfSyscall(BPF_MAP_CREATE, &attr);
  return fd_ >= 0;
}

bool Bpf::pin(const std::string &path) {
  union bpf_attr attr = {};
  attr.pathname = uintptr_t(path.c_str());
  attr.bpf_fd = uint32_t(fd_);

  return bpfSyscall(BPF_OBJ_PIN, &attr) == 0;
}

bool Bpf::insert(const void *key, const void *value) {
  union bpf_attr attr = {};
  attr.map_fd = uint32_t(fd_);
  attr.key = uintptr_t(key);
  attr.value = uintptr_t(value);
  attr.flags = BPF_ANY;

  return bpfSyscall(BPF_MAP_UPDATE_ELEM, &attr) == 0;
}

bool Bpf::remove(const void *key) {
  union bpf_attr attr = {};
  attr.map_fd = uint32_t(fd_);
  attr.key = uintptr_t(key);
  attr.flags = BPF_ANY;

  return bpfSyscall(BPF_MAP_DELETE_ELEM, &attr) == 0;
}

bool Bpf::lookup(const void *key, void *value) {
  union bpf_attr attr = {};
  attr.map_fd = uint32_t(fd_);
  attr.key = uintptr_t(key);
  attr.value = uintptr_t(value);

  return bpfSyscall(BPF_MAP_LOOKUP_ELEM, &attr) == 0;
}

#ifndef __NR_bpf
#if defined(__i386__)
#define __NR_bpf 357
#elif defined(__x86_64__)
#define __NR_bpf 321
#elif defined(__aarch64__)
#define __NR_bpf 280
#else
#error __NR_bpf not defined.
#endif
#endif

int Bpf::bpfSyscall(int cmd, union bpf_attr *attr) {
  return ::syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

} // namespace Cilium
} // namespace Envoy
