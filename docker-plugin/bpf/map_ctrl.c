#include <iproute2/bpf_api.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "libbpf.h"
#include "common.h"

static void usage(void)
{
	fprintf(stderr, "Usage: map_ctrl <command> <map> [...]\n");
	fprintf(stderr, "       map_ctrl create <map file>\n");
	fprintf(stderr, "       map_ctrl dump <map file>\n");
	fprintf(stderr, "       map_ctrl lookup <map file> <key>\n");
}

static int create_lxc_map(void)
{
	return bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u16),
			      sizeof(struct lxc_info), 1024);
}

static const char *format_lxc_info(struct lxc_info *lxc)
{
	static char str[256] = {0};
	__u16 *tmp = (__u16 *) &lxc->mac;

	snprintf(str, sizeof(str), "ifindex=%u mac=%02x:%02x:%02x:%02x:%02x:%02x",
		lxc->ifindex,
		tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5]);

	return str;
}

static void lookup_lxc(const char *file, __u16 key)
{
	struct lxc_info value;
	int fd, ret;

	fd = bpf_obj_get(file);
	printf("bpf: get fd:%d (%s)\n", fd, strerror(errno));
	assert(fd > 0);

	ret = bpf_lookup_elem(fd, &key, &value);
	printf("bpf: fd:%d key:%u ret:(%d,%s)\n",
		fd, key, ret, strerror(errno));

	printf("%u: %s\n", key, format_lxc_info(&value));
	assert(ret == 0);
}

static void dump_lxc_table(const char *file)
{
	__u16 key = 0, next_key;
	int fd, ret;

	fd = bpf_obj_get(file);
	printf("bpf: get fd:%d (%s)\n", fd, strerror(errno));
	assert(fd > 0);

	while (bpf_get_next_key(fd, &key, &next_key) == 0) {
		struct lxc_info value;

		ret = bpf_lookup_elem(fd, &next_key, &value);
		printf("bpf: fd:%d key:%u ret:(%d,%s)\n",
			fd, key, ret, strerror(errno));

		printf("%u: %s\n", key, format_lxc_info(&value));
		assert(ret == 0);
	}
}

static void update_lxc(const char *file, __u16 key, struct lxc_info *value)
{
	int fd, ret;

	fd = bpf_obj_get(file);
	printf("bpf: get fd:%d (%s)\n", fd, strerror(errno));
	assert(fd > 0);

	ret = bpf_update_elem(fd, &key, value, 0);
	printf("bpf: fd:%d u->(%u:%s) ret:(%d,%s)\n",
		fd, key, format_lxc_info(value),
	       ret, strerror(errno));
	assert(ret == 0);
}

int main(int argc, char **argv)
{
	const char *file;

	if (argc < 3)
		goto out;

	file = argv[2];

	if (!strcasecmp(argv[1], "create")) {
		int fd, ret;

		fd = create_lxc_map();
		printf("new map fd:%d (%s)\n", fd, strerror(errno));
		assert(fd > 0);

		ret = bpf_obj_pin(fd, file);
		printf("bpf: pin ret:(%d,%s)\n", ret, strerror(errno));
		assert(ret == 0);
	} else if (!strcasecmp(argv[1], "get")) {
		__u16 key;

		if (argc < 4)
			goto out;

		key = (__u16) strtoul(argv[3], NULL, 0);
		lookup_lxc(file ,key);
	} else if (!strcasecmp(argv[1], "dump")) {
		dump_lxc_table(file);
	} else if (!strcasecmp(argv[1], "update")) {
		__u16 key;
		struct lxc_info info;

		if (argc < 6)
			goto out;

		key = (__u16) strtoul(argv[3], NULL, 0);
		info.ifindex = strtoul(argv[4], NULL, 0);
		info.mac = strtoul(argv[4], NULL, 0);

		update_lxc(file, key, &info);
	}

	return 0;

out:
	usage();
	return -1;
}
