#pragma once

#include <linux/bpf.h>
#include <string.h>
#include <unistd.h>

#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace Envoy {
namespace Cilium {

/**
 * Bpf system call interface.
 */
class Bpf {
public:
  /**
   * Create a bpf map object without actually creating or opening a bpf map yet.
   * @param map_type the type of a bpf map to be opened or created, e.g.,
   * BPF_MAP_TYPE_HASH
   * @param key_size the size of the bpf map entry lookup key.
   * @param value_size the size of the bpf map entry value.
   */
  Bpf(uint32_t map_type, uint32_t key_size, uint32_t value_size);
  virtual ~Bpf();

  /**
   * Close the bpf file descriptor, if open.
   */
  void close();

  /**
   * Open an existing bpf map. The bpf map must have the map type and key and
   * value sizes that match with the ones given to the constructor.
   * @param path the file system path to the pinned bpf map.
   * @returns boolean for success of the operation.
   */
  bool open(const std::string &path);

  /**
   * Create a new bpf map.
   * @param max_entries the maximum capacity of the bpf map to be created. For
   * many map types memory for this number of entries is allocated when the map
   * is created.
   * @param flags the required flags for the map type. Typically 0.
   * @returns boolean for success of the operation.
   */
  bool create(uint32_t max_entries, uint32_t flags);

  /**
   * Pin the map to a file system path.
   * @param path the file system path where to pin the bpf map.
   * @returns boolean for success of the operation.
   */
  bool pin(const std::string &path);

  /**
   * Insert an entry with value and identified with the key to the map.
   * @param key pointer to the key identifying the new entry to be inserted.
   * @param value pointer to the value to be stored in the new entry to be
   * inserted.
   * @returns boolean for success of the operation.
   */
  bool insert(const void *key, const void *value);

  /**
   * Lookup an entry from the bpf map identified with the key, storing the found
   * value, if any.
   * @param key pointer to the key identifying the entry to be found.
   * @param value pointer at which the value is copied to if the entry is found.
   * @returns boolean for success of the operation.
   */
  bool lookup(const void *key, void *value);

private:
  int bpfSyscall(int cmd, union bpf_attr *attr);

protected:
  int fd_;

public:
  uint32_t map_type_;
  uint32_t key_size_;
  uint32_t value_size_;
};

} // namespace Cilium
} // namespace Envoy
