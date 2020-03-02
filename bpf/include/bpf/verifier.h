/*
 *  Copyright (C) 2016-2020 Authors of Cilium
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
#ifndef __BPF_VERIFIER__
#define __BPF_VERIFIER__

/* relax_verifier is a dummy helper call to introduce a pruning checkpoint
 * to help relax the verifier to avoid reaching complexity limits on older
 * kernels.
 */
static __always_inline void relax_verifier(void)
{
	int foo = 0;
	csum_diff(0, 0, &foo, 1, 0);
}

#endif /* __BPF_VERIFIER__ */
