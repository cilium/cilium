#if 0
 # gcc -Wall -O2 example.c -o example
 # ./example 1.1.1.1 8080 10.10.10.1 10.10.10.2 10.10.10.3
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/tcp.h>

#define PRIORITY_HEALTH	7

int main(int argc, char **argv)
{
	int ret, fd, i, cnt = 0, prio = PRIORITY_HEALTH, retries = 2;
	struct timeval tmo = {
		.tv_sec		= 1,
	};
	struct sockaddr_in f_addr = {
		.sin_family	= AF_INET,
	}, b_addr[128] = {};
	const int b_max = sizeof(b_addr) / sizeof(b_addr[0]), b_real = argc - 3;

	if (argc < 4 || b_real > b_max) {
		fprintf(stderr, "Usage: %s [fe] [port] [be1] [be2] ... [beN] (N_max=%d)\n",
			argv[0], b_max);
		return -1;
	}

	ret = inet_pton(AF_INET, argv[1], &f_addr.sin_addr);
	if (ret != 1) {
		fprintf(stderr, "pton(%s): %s\n", argv[1],
			strerror(errno));
		return ret;
	}

	f_addr.sin_port = htons(atoi(argv[2]));
	for (i = 0; i < b_real; i++) {
		b_addr[i].sin_family = f_addr.sin_family;
		b_addr[i].sin_port   = f_addr.sin_port;

		ret = inet_pton(AF_INET, argv[3 + i], &b_addr[i].sin_addr);
		if (ret != 1) {
			fprintf(stderr, "pton(%s): %s\n", argv[3 + i],
				strerror(errno));
			return ret;
		}
	}

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		perror("socket");
		return -1;
	}

	ret = setsockopt(fd, SOL_SOCKET, SO_PRIORITY, &prio, sizeof(prio));
	if (ret < 0) {
		perror("setsockopt(SO_PRIORITY)");
		goto out;
	}

	ret = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tmo, sizeof(tmo));
	if (ret < 0) {
		perror("setsockopt(SO_SNDTIMEO)");
		goto out;
	}

	ret = setsockopt(fd, IPPROTO_TCP, TCP_SYNCNT, &retries, sizeof(retries));
	if (ret < 0) {
		perror("setsockopt(TCP_SYNCNT)");
		goto out;
	}

	for (i = 0; i < b_real; i++) {
		ret = bind(fd, (struct sockaddr*)&b_addr[i], sizeof(b_addr[i]));
		if (ret < 0) {
			fprintf(stderr, "bind(%s): %s\n", argv[3 + i],
				strerror(errno));
			goto out;
		}

		ret = connect(fd, (struct sockaddr*)&f_addr, sizeof(f_addr));
		if (ret < 0) {
			fprintf(stderr, "backend down(%s): %s\n", argv[3 + i],
				strerror(errno));
			cnt++;
		}

		shutdown(fd, SHUT_RDWR);
	}
	ret = 0;
	printf("Summary for %s:%d: %d/%d backends reachable\n",
	       argv[1], ntohs(f_addr.sin_port), b_real - cnt, b_real);
out:
	close(fd);
	return ret;
}
