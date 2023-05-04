#include "common.h"

union ip_address {
  struct {
    __u32		ip4;
    __u32		pad4;
    __u32		pad5;
    __u32		pad6;
  };
  union v6addr	ip6;
} __packed;