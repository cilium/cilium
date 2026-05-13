//go:build darwin

package table

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework CoreServices -framework IOKit

#include <stdio.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <mach/mach.h>

int get_page_size() {
	int mib[2] = {CTL_HW, HW_PAGESIZE};
	int pagesize = 0;
	size_t length = sizeof(pagesize);

	if (sysctl(mib, 2, &pagesize, &length, NULL, 0) < 0) {
		return -1;
	}
	return pagesize;
}

int get_vm_stats(vm_statistics_data_t *vmstat_out) {
	mach_msg_type_number_t count = HOST_VM_INFO_COUNT;
	return host_statistics(mach_host_self(), HOST_VM_INFO, (host_info_t)vmstat_out, &count);
}
*/
import "C"

func SystemMemoryAvailableMiB() uint64 {
	// Get page size
	pageSize := C.get_page_size()
	if pageSize < 0 {
		return 0
	}

	// Get VM statistics
	var vmstat C.vm_statistics_data_t
	if C.get_vm_stats(&vmstat) != C.KERN_SUCCESS {
		return 0
	}

	// Compute total and usage breakdown
	return uint64(vmstat.free_count) * uint64(pageSize) >> 20 // Convert to MiB
}
