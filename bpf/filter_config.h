/*
 *  Copyright (C) 2017 Authors of Cilium
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
/*
 * This is just a dummy header with dummy values to allow for test
 * compilation without the full code generation engine backend.
 */
#define CIDR4_HMAP_ELEMS 1024
#define CIDR4_LMAP_ELEMS 1024
#define CIDR4_HMAP_NAME v4_fix
#define CIDR4_LMAP_NAME v4_dyn
#define CIDR4_FILTER
#define CIDR4_LPM_PREFILTER
#define CIDR6_HMAP_NAME v6_fix
#define CIDR6_LMAP_NAME v6_dyn
#define CIDR6_FILTER
#define CIDR6_LPM_PREFILTER
