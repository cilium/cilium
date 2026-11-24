/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

/*
 *   **** WARNING, THIS FILE IS DEPRECATED, DO NOT ADD NEW CONFIG HERE ****
 *
 * For adding new configuration to the datapath, see the documentation at
 * https://docs.cilium.io/en/latest/contributing/development/datapath_config.
 *
 * Variables in this file will gradually be migrated to the new format, and this
 * file will eventually be removed.
 */
#include <lib/static_data.h>

#define LRU_MEM_FLAVOR 0

#define LB_MAGLEV_LUT_SIZE 32749
#define IPCACHE_MAP_SIZE 512000

/*
 *   **** WARNING, THIS FILE IS DEPRECATED, SEE COMMENT AT THE TOP ****
 */
