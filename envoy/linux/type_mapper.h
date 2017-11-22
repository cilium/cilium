#ifndef __LINUX_TYPE_MAPPER_H__
#define __LINUX_TYPE_MAPPER_H__

#include <stdint.h>

#define __u64 uint64_t
#define __u32 uint32_t
#define __u16 uint16_t
#define __u8 uint8_t

#define __s64 int64_t
#define __s32 int32_t
#define __s16 int16_t
#define __s8 int8_t

#define __aligned_u64 uint64_t

#define __be64 uint64_t
#define __be32 uint32_t
#define __be16 uint16_t

#define __le64 uint64_t
#define __le32 uint32_t
#define __le16 uint16_t

#define __sum16 uint16_t

#endif

