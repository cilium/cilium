#ifndef __EVENT_H_
#define __EVENT_H_

#include <iproute2/bpf_api.h>
#include <stdint.h>

enum {
	EVENT_TYPE_UNSPEC = 0,
	EVENT_TYPE_SAMPLE,
};

struct event_msg {
	__u8	type;
	__u8	data[20];
};

#endif
