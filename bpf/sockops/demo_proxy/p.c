#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdbool.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <time.h>
#include <sched.h>

#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/sendfile.h>

#include <linux/netlink.h>
#include <linux/socket.h>
#include <linux/sock_diag.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/tls.h>
#include <assert.h>
#include <libgen.h>

#include <getopt.h>

#if 0
#include "bpf_util.h"
#include "bpf_rlimit.h"
#include "cgroup_helpers.h"
#endif

int running;
static void running_handler(int a);

#ifndef __NR_bpf
# if defined(__i386__)
#  define __NR_bpf 357
# elif defined(__x86_64__)
#  define __NR_bpf 321
# elif defined(__aarch64__)
#  define __NR_bpf 280
# elif defined(__sparc__)
#  define __NR_bpf 349
# elif defined(__s390__)
#  define __NR_bpf 351
# else
#  error __NR_bpf not defined. libbpf does not support your arch.
# endif
#endif

struct sock_key {
	union {
		struct {
			__u32		sip4;
			__u32		pad1;
			__u32		pad2;
			__u32		pad3;
		};
	};
	union {
		struct {
			__u32		dip4;
			__u32		pad4;
			__u32		pad5;
			__u32		pad6;
		};
	};
	__u8 family;
	__u8 pad7;
	__u16 pad8;
	__u32 sport;
	__u32 dport;
	__u32 size;
} __attribute__((packed));


static inline __u64 ptr_to_u64(const void *ptr)
{
	return (__u64) (unsigned long) ptr;
}

static inline int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr,
			  unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

int bpf_obj_get(const char *pathname)
{
	union bpf_attr attr;

	bzero(&attr, sizeof(attr));
	attr.pathname = ptr_to_u64((void *)pathname);

	return sys_bpf(BPF_OBJ_GET, &attr, sizeof(attr));
}

int bpf_map_update_elem(int fd, const void *key, const void *value,
			__u64 flags)
{
	union bpf_attr attr;

	bzero(&attr, sizeof(attr));
	attr.map_fd = fd;
	attr.key = ptr_to_u64(key);
	attr.value = ptr_to_u64(value);
	attr.flags = flags;

	return sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static int msg_alloc_iov(struct msghdr *msg,
			 int iov_count, int iov_length, bool alloc)
{
	unsigned char k = 0;
	struct iovec *iov;
	int i;

	iov = calloc(iov_count, sizeof(struct iovec));
	if (!iov)
		return errno;

	if (alloc) {
		for (i = 0; i < iov_count; i++) {
			unsigned char *d = calloc(iov_length, sizeof(char));

			if (!d) {
				fprintf(stderr, "iov_count %i/%i OOM\n", i, iov_count);
				goto unwind_iov;
			}
			iov[i].iov_base = d;
			iov[i].iov_len = iov_length;
		}
	}

	msg->msg_iov = iov;
	msg->msg_iovlen = iov_count;

	return 0;
unwind_iov:
	for (i--; i >= 0 ; i--)
		free(msg->msg_iov[i].iov_base);
	return -ENOMEM;
}

static void msg_free_iov(struct msghdr *msg)
{
	int i;

	for (i = 0; i < msg->msg_iovlen; i++)
		free(msg->msg_iov[i].iov_base);
	free(msg->msg_iov);
	msg->msg_iov = NULL;
	msg->msg_iovlen = 0;
}

#define IOV_COUNT 1
#define IOV_LENGTH 8096

#define SFD_PORT 4321

__u8 *pkt_ptr, *base_ptr;
struct msghdr txmsg;

struct byte_stats {
	size_t bytes_recvd;
	size_t bytes_sent;
};

int proxy_glue(int cfd, int pfd, struct msghdr *msg, char *type, struct byte_stats *stats)
{
	struct sock_key *key = NULL;
	int recv = 0, sent = 0, flags = 0;

	recv += recvmsg(cfd, msg, flags);
	printf("\n%s: proxy: recvmsg %i\n", type, recv);
	if (recv < 0) {
		if (errno != EWOULDBLOCK) {
			perror("recv failed()\n");
			goto out_errno;
		}
		printf("proxy: (non)blocking\n");
		return 0;
	}

	stats->bytes_recvd += recv;
	msg->msg_iov[0].iov_len = recv;

	pkt_ptr = msg->msg_iov[0].iov_base;
	while (recv) {
		if (!key) {
			key = (struct sock_key *)pkt_ptr;
			txmsg.msg_iov[0].iov_base = pkt_ptr;
			txmsg.msg_iov[0].iov_len = key->size;
		}
		printf("%s: recv %i: key %i %i %i (%i.%i) %i %i %i\n", type, recv, key->sport, key->dport, key->family, key->pad7, key->pad8, key->sip4, key->dip4, key->size);

		if (recv < key->size) // need more data
			break;
		if (!key->size) {
			printf("datapath error? Zero length message\n");
			goto out_errno;
		}

		sent = sendmsg(pfd, &txmsg, flags);
		printf("%s: proxy: sent %i\n", type, sent);
		if (sent < 0) {
			perror("send loop error:");
				goto out_errno;
		}
		if (sent != key->size) {
			printf("txmsg partial send abortin.\n");
			goto out_errno;
		}
		recv -= sent;
		pkt_ptr += sent;
		stats->bytes_sent += sent;
		key = NULL;
	}
	// Bit of a trick but slide msg along if we have leftover
	// bytes to avoid stomping on them from rx side. Otherwise
	// point at the begining of the buffer.
	if (key) {
		msg->msg_iov[0].iov_base = pkt_ptr + recv;
		msg->msg_iov[0].iov_len = IOV_LENGTH - (pkt_ptr - base_ptr);
	} else {
		msg->msg_iov[0].iov_base = base_ptr;
		msg->msg_iov[0].iov_len = IOV_LENGTH;
	}
	return 0;
out_errno:
	return errno;
}

int main(int argc, char **argv)
{
	int i, upmapfd, downmapfd, sfd, cfd, pfd, err, one = 1, recv = 0;
	struct byte_stats up = {0}, down = {0};
	struct sockaddr_in addr;
	struct msghdr msg;
	char *downmap = "/sys/fs/bpf/tc/globals/sock_ops_ktls_down";
	char *upmap = "/sys/fs/bpf/tc/globals/sock_ops_ktls_up";

	err = msg_alloc_iov(&msg, IOV_COUNT, IOV_LENGTH, true);
	if (err) {
		perror("msg alloc iov failed");
		return errno;
	}

	err = msg_alloc_iov(&txmsg, IOV_COUNT, IOV_LENGTH, false);
	if (err) {
		perror("txmsg alloc iov failed");
		return errno;
	}
	base_ptr = msg.msg_iov[0].iov_base;

	sfd = socket(AF_INET, SOCK_STREAM, 0);
	cfd = socket(AF_INET, SOCK_STREAM, 0);

	setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one));
	err = ioctl(sfd, FIONBIO, (char *)&one);
	if (err < 0) {
		perror("ioctl sfd failed()");
		return errno;
	}

	/* Bind server sockets */
	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	addr.sin_port = htons(SFD_PORT);
	err = bind(sfd, (struct sockaddr *)&addr, sizeof(addr));
	if (err < 0) {
		perror("bind sfd failed()\n");
		return errno;
	}

	/* Listen server sockets */
	addr.sin_port = htons(SFD_PORT);
	err = listen(sfd, 32);
	if (err < 0) {
		perror("listen sfd failed()\n");
		return errno;
	}

	/* Connect */
	addr.sin_port = htons(SFD_PORT);
	err = connect(cfd, (struct sockaddr *)&addr, sizeof(addr));
	if (err < 0 && errno != EINPROGRESS) {
		perror("connect c1 failed()\n");
		return errno;
	}

	pfd = accept(sfd, NULL, NULL);
	if (pfd < 0) {
		perror("accept sfd failed()\n");
		return errno;
	}

	downmapfd = bpf_obj_get(downmap);
	if (!downmapfd) {
		perror("Failed map open: ");
		return errno;
	}

	upmapfd = bpf_obj_get(upmap);
	if (!upmapfd) {
		perror("Failed map open: ");
		return errno;
	}

	i = 0;
	err = bpf_map_update_elem(downmapfd, &i, &cfd, BPF_ANY);
	if (err) {
		perror("Failed map update cfd");
		return err;
	}
	err = bpf_map_update_elem(upmapfd, &i, &pfd, BPF_ANY);
	if (err) {
		perror("Failed map update pfd");
		return err;
	}

	running = 1;
	signal(SIGINT, running_handler);

	printf("proxy running: downstream: %i upstream: %i\n", cfd, pfd);
	while (running) {
		int ready, slct, max_fd = cfd;
		struct timeval timeout;
		fd_set w;

		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		/* FD sets */
		FD_ZERO(&w);
		FD_SET(pfd, &w);
		FD_SET(cfd, &w);

		slct = select(pfd + 1, &w, NULL, NULL, &timeout);
		if (slct == -1) {
			perror("select()");
			goto out;
		} else if (!slct) {
			printf(".");
			fflush(stdout);
			continue;
		}

		errno = 0;
		ready = FD_ISSET(cfd, &w);
		if (ready) {
			err = proxy_glue(cfd, pfd, &msg, "downstream", &down);
			if (err < 0)
				goto out;
		}
		ready = FD_ISSET(pfd, &w);
		if (ready) {
			err = proxy_glue(pfd, cfd, &msg, "upstream", &up); 
			if (err < 0)
				goto out;
		}
	}
out:
	printf("\nSummary proxy-tester: downstream(%zu->%zu) upstream(%zu->%zu)\n",
			down.bytes_sent,
			down.bytes_recvd,
			up.bytes_sent,
			up.bytes_recvd);
	msg_free_iov(&msg);
	return -1;
}

void running_handler(int a)
{
	running = 0;
}
