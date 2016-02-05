#include <arpa/inet.h>
#include <iproute2/bpf_api.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/resource.h>
#include "libbpf.h"
#include "lib/common.h"

static void usage(void)
{
	fprintf(stderr, "Usage: map_ctrl <command> <map> [...]\n");
	fprintf(stderr, "       map_ctrl create <map file>\n");
	fprintf(stderr, "       map_ctrl dump <map file>\n");
	fprintf(stderr, "       map_ctrl lookup <map file> <key>\n");
	fprintf(stderr, "       map_ctrl update <map file> <key> <ifindex> <mac> <ipv6> [<map>]\n");
	fprintf(stderr, "                map := from:to [from:to]...\n");
	fprintf(stderr, "       map_ctrl delete <map file> <key>\n");
}

static int create_lxc_map(void)
{
	return bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(__u16),
			      sizeof(struct lxc_info), 1024);
}

static const char *format_lxc_info(struct lxc_info *lxc)
{
	static char str[256] = {0};
	char buf[INET6_ADDRSTRLEN];
	__u8 *tmp = (__u8 *) &lxc->mac;
	int i;

	inet_ntop(AF_INET6, &lxc->ip, buf, sizeof(buf));

	snprintf(str, sizeof(str),
		"ifindex=%u mac=%02x:%02x:%02x:%02x:%02x:%02x ip=%s",
		lxc->ifindex,
		tmp[0], tmp[1], tmp[2], tmp[3], tmp[4], tmp[5],
		buf);

	for (i = 0; i < PORTMAP_MAX; i++) {
		char buf2[32];
		if (!lxc->portmap[i].from && !lxc->portmap[i].to)
			break;

		snprintf(buf2, sizeof(buf2), " %u:%u",
			ntohs(lxc->portmap[i].from), ntohs(lxc->portmap[i].to));
		strncat(str, buf2, sizeof(str) - strlen(str) - 1);
	}

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

		printf("bpf_get_next_key: fd:%d key:%u nextkey:%u errno:(%s)\n",
			fd, key, next_key, strerror(errno));
		key = next_key;

		ret = bpf_lookup_elem(fd, &key, &value);
		printf("bpf_lookup_elem: fd:%d key:%u ret:(%d,%s)\n",
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

static void delete_lxc(const char *file, __u16 key)
{
	struct lxc_info value;
	int fd, ret;

	fd = bpf_obj_get(file);
	printf("bpf: get fd:%d (%s)\n", fd, strerror(errno));
	assert(fd > 0);

	ret = bpf_delete_elem(fd, &key);
	printf("bpf: fd:%d key:%u ret:(%d,%s)\n",
		fd, key, ret, strerror(errno));
	assert(ret == 0);
}

int main(int argc, char **argv)
{
	const char *file;
        struct rlimit limit = {
                .rlim_cur = RLIM_INFINITY,
                .rlim_max = RLIM_INFINITY,
        };

        /* Don't bother in case we fail! */
        setrlimit(RLIMIT_MEMLOCK, &limit);

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
		struct lxc_info info = { };
		__u8 *m = (__u8 *) &info.mac;
		int i, n;

		if (argc < 7)
			goto out;

		key = (__u16) strtoul(argv[3], NULL, 0);
		info.ifindex = strtoul(argv[4], NULL, 0);

		if (sscanf(argv[5], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
			   &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) != 6)
			goto out;

		if (inet_pton(AF_INET6, argv[6], (struct in6_addr *) &info.ip) != 1) {
			fprintf(stderr, "Invalid IPv6 address: %s\n", argv[6]);
			goto out;
		}

		for (i = 7, n = 0; i < argc; i++, n++) {
			uint16_t from, to;
			int n;

			if (sscanf(argv[i], "%hu:%hu", &from, &to) != 2) {
				fprintf(stderr, "Error while parsing portmap %s\n",
					argv[i]);
				goto out;
			}

			if (n < (PORTMAP_MAX - 1)) {
				info.portmap[n].from = htons(from);
				info.portmap[n].to = htons(to);
			} else {
				fprintf(stderr, "Warning: Only %u portmaps supported\n",
					PORTMAP_MAX);
			}
		}

		update_lxc(file, key, &info);
	} else if (!strcasecmp(argv[1], "delete")) {
		__u16 key;

		if (argc < 4)
			goto out;

		key = (__u16) strtoul(argv[3], NULL, 0);
		delete_lxc(file ,key);
	}

	return 0;

out:
	usage();
	return -1;
}
