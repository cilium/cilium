// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2017-2020 Authors of Cilium */

/*
 *  Parts from iproute2 bpf.c loader code:
 *
 *  This program is free software; you can distribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version
 *  2 of the License, or (at your option) any later version.
 *
 *  Authors:
 *
 *    Daniel Borkmann <daniel@iogearbox.net>
 *    Jiri Pirko <jiri@resnulli.us>
 *    Alexei Starovoitov <ast@kernel.org>
 */

#include <stdio.h>
#include <syslog.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>

#include <sys/syscall.h>
#include <sys/stat.h>

#include <arpa/inet.h>

#include <linux/bpf.h>

#include "elf/libelf.h"
#include "elf/gelf.h"

#include "bpf/ctx/nobpf.h"
#include "bpf/api.h"

#ifndef EM_BPF
# define EM_BPF		247
#endif

#define ELF_MAX_MAPS	64

#define STATE_PENDING	"pending"

#define BPF_ENV_MNT "CILIUM_BPF_MNT"

struct bpf_elf_sec_data {
	GElf_Shdr	sec_hdr;
	Elf_Data	*sec_data;
	const char	*sec_name;
};

struct bpf_elf_ctx {
	GElf_Ehdr	elf_hdr;
	Elf		*elf_fd;
	Elf_Data	*sym_tab;
	Elf_Data	*str_tab;
	Elf_Data	*map_tab;
	int		map_len;
	int		map_num;
	int		map_sec;
	int		sym_num;
	int		obj_fd;
};

static int bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
#ifndef __NR_bpf
# if defined(__i386__)
#  define __NR_bpf 357
# elif defined(__x86_64__)
#  define __NR_bpf 321
# elif defined(__aarch64__)
#  define __NR_bpf 280
# else
#  error __NR_bpf not defined.
# endif
#endif
	return syscall(__NR_bpf, cmd, attr, size);
}

static int renameat2(int dfd1, const char *path1,
		     int dfd2, const char *path2,
		     unsigned int flags)
{
#ifndef __NR_renameat2
# if defined(__i386__)
#  define __NR_renameat2 353
# elif defined(__x86_64__)
#  define __NR_renameat2 316
# elif defined(__aarch64__)
#  define __NR_renameat2 276
# else
#  error __NR_renameat2 not defined.
# endif
#endif
	return syscall(__NR_renameat2, dfd1, path1, dfd2, path2, flags);
}

static inline __u64 bpf_ptr_to_u64(const void *ptr)
{
	return (__u64)(unsigned long)ptr;
}

static int bpf_elf_check_ehdr(const struct bpf_elf_ctx *ctx)
{
	if (ctx->elf_hdr.e_type != ET_REL ||
	    (ctx->elf_hdr.e_machine != EM_NONE &&
	     ctx->elf_hdr.e_machine != EM_BPF) ||
	    ctx->elf_hdr.e_version != EV_CURRENT) {
		fprintf(stderr, "ELF format error, ELF file not for eBPF?\n");
		return -EINVAL;
	}

	switch (ctx->elf_hdr.e_ident[EI_DATA]) {
	default:
		fprintf(stderr, "ELF format error, wrong endianness info?\n");
		return -EINVAL;
	case ELFDATA2LSB:
		if (htons(1) == 1) {
			fprintf(stderr,
				"We are big endian, eBPF object is little endian!\n");
			return -EIO;
		}
		break;
	case ELFDATA2MSB:
		if (htons(1) != 1) {
			fprintf(stderr,
				"We are little endian, eBPF object is big endian!\n");
			return -EIO;
		}
		break;
	}

	return 0;
}

static int bpf_elf_init(struct bpf_elf_ctx *ctx, const char *pathname)
{
	int ret;

	if (elf_version(EV_CURRENT) == EV_NONE)
		return -EIO;
	ctx->obj_fd = open(pathname, O_RDONLY);
	if (ctx->obj_fd < 0)
		return ctx->obj_fd;
	ctx->elf_fd = elf_begin(ctx->obj_fd, ELF_C_READ, NULL);
	if (!ctx->elf_fd) {
		ret = -EINVAL;
		goto out_fd;
	}
	if (elf_kind(ctx->elf_fd) != ELF_K_ELF) {
		ret = -EINVAL;
		goto out_fd;
	}
	if (gelf_getehdr(ctx->elf_fd, &ctx->elf_hdr) !=
	    &ctx->elf_hdr) {
		ret = -EIO;
		goto out_elf;
	}
	ret = bpf_elf_check_ehdr(ctx);
	if (ret < 0)
		goto out_elf;
	return 0;
out_elf:
	elf_end(ctx->elf_fd);
out_fd:
	close(ctx->obj_fd);
	return ret;
}

static void bpf_elf_close(const struct bpf_elf_ctx *ctx)
{
	elf_end(ctx->elf_fd);
	close(ctx->obj_fd);
}

static const char *bpf_str_tab_name(const struct bpf_elf_ctx *ctx,
				    const GElf_Sym *sym)
{
	return ctx->str_tab->d_buf + sym->st_name;
}

static int bpf_map_verify_all_offs(const struct bpf_elf_ctx *ctx, int end)
{
	GElf_Sym sym;
	int off, i;

	for (off = 0; off < end; off += ctx->map_len) {
		/* Order doesn't need to be linear here, hence we walk
		 * the table again.
		 */
		for (i = 0; i < ctx->sym_num; i++) {
			if (gelf_getsym(ctx->sym_tab, i, &sym) != &sym)
				continue;
			if (GELF_ST_BIND(sym.st_info) != STB_GLOBAL ||
			    !(GELF_ST_TYPE(sym.st_info) == STT_NOTYPE ||
			      GELF_ST_TYPE(sym.st_info) == STT_OBJECT) ||
			    sym.st_shndx != ctx->map_sec)
				continue;
			if (sym.st_value == off)
				break;
			if (i == ctx->sym_num - 1)
				return -1;
		}
	}

	return off == end ? 0 : -1;
}

static const char *bpf_map_fetch_name(struct bpf_elf_ctx *ctx, unsigned long off)
{
	GElf_Sym sym;
	int i;

	for (i = 0; i < ctx->sym_num; i++) {
		if (gelf_getsym(ctx->sym_tab, i, &sym) != &sym)
			continue;

		if (GELF_ST_BIND(sym.st_info) != STB_GLOBAL ||
		    !(GELF_ST_TYPE(sym.st_info) == STT_NOTYPE ||
		      GELF_ST_TYPE(sym.st_info) == STT_OBJECT) ||
		    sym.st_shndx != ctx->map_sec ||
		    sym.st_value != off)
			continue;
		return bpf_str_tab_name(ctx, &sym);
	}

	return NULL;
}

static int bpf_map_num_sym(const struct bpf_elf_ctx *ctx)
{
	int i, num = 0;
	GElf_Sym sym;

	for (i = 0; i < ctx->sym_num; i++) {
		if (gelf_getsym(ctx->sym_tab, i, &sym) != &sym)
			continue;

		if (GELF_ST_BIND(sym.st_info) != STB_GLOBAL ||
		    !(GELF_ST_TYPE(sym.st_info) == STT_NOTYPE ||
		      GELF_ST_TYPE(sym.st_info) == STT_OBJECT) ||
		    sym.st_shndx != ctx->map_sec)
			continue;
		num++;
	}

	return num;
}

static int bpf_derive_elf_map_from_fdinfo(int fd, struct bpf_elf_map *map)
{
	char file[PATH_MAX], buff[256];
	unsigned int val;
	FILE *fp;

	snprintf(file, sizeof(file), "/proc/%d/fdinfo/%d", getpid(), fd);
	memset(map, 0, sizeof(*map));

	fp = fopen(file, "r");
	if (!fp) {
		fprintf(stderr, "No procfs support?!\n");
		return -EIO;
	}

	while (fgets(buff, sizeof(buff), fp)) {
		if (sscanf(buff, "map_type:\t%u", &val) == 1)
			map->type = val;
		else if (sscanf(buff, "key_size:\t%u", &val) == 1)
			map->size_key = val;
		else if (sscanf(buff, "value_size:\t%u", &val) == 1)
			map->size_value = val;
		else if (sscanf(buff, "max_entries:\t%u", &val) == 1)
			map->max_elem = val;
		else if (sscanf(buff, "map_flags:\t%x", &val) == 1)
			map->flags = val;
	}

	fclose(fp);
	return 0;
}

static int bpf_obj_get(const char *pathname)
{
	union bpf_attr attr = {};

	attr.pathname = bpf_ptr_to_u64(pathname);
	return bpf(BPF_OBJ_GET, &attr, sizeof(attr));
}

typedef int (*bpf_handle_state_t)(struct bpf_elf_ctx *ctx,
				  const struct bpf_elf_map *map,
				  const char *name, int exit);

char fs_base[PATH_MAX + 1];

void fs_base_init(void)
{
	const char *mnt_env = getenv(BPF_ENV_MNT);

	if (mnt_env)
		snprintf(fs_base, sizeof(fs_base), "%s/tc/globals", mnt_env);
	else
		strcpy(fs_base, "/sys/fs/bpf/tc/globals");
}

static int bpf_handle_pending(struct bpf_elf_ctx *ctx,
			      const struct bpf_elf_map *map,
			      const char *name, int exit)
{
	char file[PATH_MAX + 1], dest[PATH_MAX + 1];
	struct bpf_elf_map pinned;
	struct stat sb;
	int fd, ret;

	snprintf(file, sizeof(file), "%s/%s", fs_base, name);
	ret = stat(file, &sb);
	if (ret < 0) {
		if (errno == ENOENT)
			return 0;
		fprintf(stderr, "Cannot stat node %s!\n", file);
		return -errno;
	}

	fd = bpf_obj_get(file);
	if (fd < 0) {
		fprintf(stderr, "Cannot open pinned node %s!\n", file);
		return -errno;
	}
	ret = bpf_derive_elf_map_from_fdinfo(fd, &pinned);
	close(fd);
	if (ret < 0) {
		fprintf(stderr, "Cannot fetch fdinfo from %s!\n", file);
		return ret;
	}

	pinned.id = map->id;
	pinned.inner_id = map->inner_id;
	pinned.inner_idx = map->inner_idx;
	pinned.pinning = map->pinning;
	if (!memcmp(map, &pinned, sizeof(pinned)))
		return 0;

	snprintf(dest, sizeof(dest), "%s:%s", file, STATE_PENDING);
	syslog(LOG_WARNING, "Property mismatch in %s, migrating node to %s!\n",
	       file, dest);
	utimensat(AT_FDCWD, file, NULL, 0);
	return rename(file, dest);
}

static int bpf_handle_finalize(struct bpf_elf_ctx *ctx,
			       const struct bpf_elf_map *map,
			       const char *name, int exit)
{
	char file[PATH_MAX + 1], dest[PATH_MAX + 1];
	struct stat sb;
	int ret;

	snprintf(file, sizeof(file), "%s/%s:%s", fs_base, name,
		 STATE_PENDING);
	ret = stat(file, &sb);
	if (ret < 0) {
		if (errno == ENOENT)
			return 0;
		fprintf(stderr, "Cannot stat node %s!\n", file);
		return -errno;
	}

	if (exit) {
		snprintf(dest, sizeof(dest), "%s/%s", fs_base, name);
		syslog(LOG_WARNING, "Restoring migrated node %s into %s due to bad exit.\n",
		       file, dest);
		utimensat(AT_FDCWD, file, NULL, 0);
		renameat2(AT_FDCWD, file, AT_FDCWD, dest, 1);
		return 0;
	}

	syslog(LOG_WARNING, "Unlinking migrated node %s due to good exit.\n",
	       file);
	return unlink(file);
}

static int bpf_fill_section_data(const struct bpf_elf_ctx *ctx, int section,
				 struct bpf_elf_sec_data *data)
{
	Elf_Data *sec_edata;
	GElf_Shdr sec_hdr;
	Elf_Scn *sec_fd;
	char *sec_name;

	memset(data, 0, sizeof(*data));

	sec_fd = elf_getscn(ctx->elf_fd, section);
	if (!sec_fd)
		return -EINVAL;
	if (gelf_getshdr(sec_fd, &sec_hdr) != &sec_hdr)
		return -EIO;

	sec_name = elf_strptr(ctx->elf_fd, ctx->elf_hdr.e_shstrndx,
			      sec_hdr.sh_name);
	if (!sec_name || !sec_hdr.sh_size)
		return -ENOENT;

	sec_edata = elf_getdata(sec_fd, NULL);
	if (!sec_edata || elf_getdata(sec_fd, sec_edata))
		return -EIO;

	memcpy(&data->sec_hdr, &sec_hdr, sizeof(sec_hdr));

	data->sec_name = sec_name;
	data->sec_data = sec_edata;
	return 0;
}

static int bpf_fetch_symtab(struct bpf_elf_ctx *ctx, int section,
			    const struct bpf_elf_sec_data *data)
{
	ctx->sym_tab = data->sec_data;
	ctx->sym_num = data->sec_hdr.sh_size /
		       data->sec_hdr.sh_entsize;
	return 0;
}

static int bpf_fetch_strtab(struct bpf_elf_ctx *ctx, int section,
			    const struct bpf_elf_sec_data *data)
{
	ctx->str_tab = data->sec_data;
	return 0;
}

static int bpf_fetch_maps_begin(struct bpf_elf_ctx *ctx, int section,
				const struct bpf_elf_sec_data *data)
{
	ctx->map_tab = data->sec_data;
	ctx->map_len = data->sec_data->d_size;
	ctx->map_sec = section;
	return 0;
}

static int bpf_fetch_maps_end(struct bpf_elf_ctx *ctx, bpf_handle_state_t cb,
			      int exit)
{
	int i, ret = 0, sym_num = bpf_map_num_sym(ctx);
	struct bpf_elf_map *map;
	unsigned long off;
	const char *name;

	if (sym_num == 0 || sym_num > 64) {
		fprintf(stderr, "%d maps not supported in current map section!\n",
			sym_num);
		return -EINVAL;
	}

	if (ctx->map_len != sym_num * sizeof(struct bpf_elf_map)) {
		fprintf(stderr, "Number BPF map symbols are not multiple of struct bpf_elf_map!\n");
		return -EINVAL;
	}

	ctx->map_len /= sym_num;
	if (bpf_map_verify_all_offs(ctx, ctx->map_num)) {
		fprintf(stderr, "Different struct bpf_elf_map in use!\n");
		return -EINVAL;
	}

	ctx->map_num = sym_num;
	for (i = 0, map = ctx->map_tab->d_buf; i < sym_num; i++, map++) {
		if (map->pinning != PIN_GLOBAL_NS)
			continue;
		off = (void *)map - ctx->map_tab->d_buf;
		name = bpf_map_fetch_name(ctx, off);
		if (!name) {
			fprintf(stderr, "Count not fetch map name at off %lu!\n", off);
			return -EIO;
		}
		ret = cb(ctx, map, name, exit);
		if (ret)
			break;
	}

	return ret;
}

static bool bpf_has_map_data(const struct bpf_elf_ctx *ctx)
{
	return ctx->sym_tab && ctx->str_tab && ctx->map_tab;
}

static int bpf_check_ancillary(struct bpf_elf_ctx *ctx, bpf_handle_state_t cb,
			       int exit)
{
	struct bpf_elf_sec_data data;
	int i, ret = 0;

	for (i = 1; i < ctx->elf_hdr.e_shnum; i++) {
		ret = bpf_fill_section_data(ctx, i, &data);
		if (ret < 0)
			continue;
		if (data.sec_hdr.sh_type == SHT_PROGBITS &&
		    !strcmp(data.sec_name, "maps"))
			ret = bpf_fetch_maps_begin(ctx, i, &data);
		else if (data.sec_hdr.sh_type == SHT_SYMTAB &&
			 !strcmp(data.sec_name, ".symtab"))
			ret = bpf_fetch_symtab(ctx, i, &data);
		else if (data.sec_hdr.sh_type == SHT_STRTAB &&
			 !strcmp(data.sec_name, ".strtab"))
			ret = bpf_fetch_strtab(ctx, i, &data);
		if (ret < 0) {
			fprintf(stderr, "Error parsing section %d! Perhaps check with readelf -a?\n",
				i);
			return ret;
		}
	}

	if (bpf_has_map_data(ctx)) {
		ret = bpf_fetch_maps_end(ctx, cb, exit);
		if (ret < 0) {
			fprintf(stderr, "Error fixing up map structure, incompatible struct bpf_elf_map used?\n");
			return ret;
		}
	}

	return ret;
}

static int migrate_state(const char *pathname, bpf_handle_state_t cb, int exit)
{
	struct bpf_elf_ctx ctx = {};
	int ret;

	ret = bpf_elf_init(&ctx, pathname);
	if (!ret) {
		ret = bpf_check_ancillary(&ctx, cb, exit);
		bpf_elf_close(&ctx);
	}
	return ret;
}

int main(int argc, char **argv)
{
	const char *pathname = NULL;
	bpf_handle_state_t fn = NULL;
	int opt, exit = 0;

	fs_base_init();

	openlog("cilium-map-migrate", LOG_NDELAY, 0);
	while ((opt = getopt(argc, argv, "s:e:r:")) != -1) {
		switch (opt) {
		case 's':
		case 'e':
			pathname = optarg;
			fn = opt == 's' ?
			     bpf_handle_pending :
			     bpf_handle_finalize;
			break;
		case 'r':
			exit = atoi(optarg);
			break;
		default:
			return -1;
		}
	}

	if (fn == NULL)
		return -1;

	exit = pathname ? migrate_state(pathname, fn, exit) : -1;
	closelog();
	return exit;
}
