package linux

import (
	"io/ioutil"
	"strconv"
	"strings"
)

type VMStat struct {
	NrFreePages                   uint64 `json:"nr_free_pages"`
	NrAllocBatch                  uint64 `json:"nr_alloc_batch"`
	NrInactiveAnon                uint64 `json:"nr_inactive_anon"`
	NrActiveAnon                  uint64 `json:"nr_active_anon"`
	NrInactiveFile                uint64 `json:"nr_inactive_file"`
	NrActiveFile                  uint64 `json:"nr_active_file"`
	NrUnevictable                 uint64 `json:"nr_unevictable"`
	NrMlock                       uint64 `json:"nr_mlock"`
	NrAnonPages                   uint64 `json:"nr_anon_pages"`
	NrMapped                      uint64 `json:"nr_mapped"`
	NrFilePages                   uint64 `json:"nr_file_pages"`
	NrDirty                       uint64 `json:"nr_dirty"`
	NrWriteback                   uint64 `json:"nr_writeback"`
	NrSlabReclaimable             uint64 `json:"nr_slab_reclaimable"`
	NrSlabUnreclaimable           uint64 `json:"nr_slab_unreclaimable"`
	NrPageTablePages              uint64 `json:"nr_page_table_pages"`
	NrKernelStack                 uint64 `json:"nr_kernel_stack"`
	NrUnstable                    uint64 `json:"nr_unstable"`
	NrBounce                      uint64 `json:"nr_bounce"`
	NrVmscanWrite                 uint64 `json:"nr_vmscan_write"`
	NrVmscanImmediateReclaim      uint64 `json:"nr_vmscan_immediate_reclaim"`
	NrWritebackTemp               uint64 `json:"nr_writeback_temp"`
	NrIsolatedAnon                uint64 `json:"nr_isolated_anon"`
	NrIsolatedFile                uint64 `json:"nr_isolated_file"`
	NrShmem                       uint64 `json:"nr_shmem"`
	NrDirtied                     uint64 `json:"nr_dirtied"`
	NrWritten                     uint64 `json:"nr_written"`
	NumaHit                       uint64 `json:"numa_hit"`
	NumaMiss                      uint64 `json:"numa_miss"`
	NumaForeign                   uint64 `json:"numa_foreign"`
	NumaInterleave                uint64 `json:"numa_interleave"`
	NumaLocal                     uint64 `json:"numa_local"`
	NumaOther                     uint64 `json:"numa_other"`
	WorkingsetRefault             uint64 `json:"workingset_refault"`
	WorkingsetActivate            uint64 `json:"workingset_activate"`
	WorkingsetNodereclaim         uint64 `json:"workingset_nodereclaim"`
	NrAnonTransparentHugepages    uint64 `json:"nr_anon_transparent_hugepages"`
	NrFreeCma                     uint64 `json:"nr_free_cma"`
	NrDirtyThreshold              uint64 `json:"nr_dirty_threshold"`
	NrDirtyBackgroundThreshold    uint64 `json:"nr_dirty_background_threshold"`
	PagePagein                    uint64 `json:"pgpgin"`
	PagePageout                   uint64 `json:"pgpgout"`
	PageSwapin                    uint64 `json:"pswpin"`
	PageSwapout                   uint64 `json:"pswpout"`
	PageAllocDMA                  uint64 `json:"pgalloc_dma"`
	PageAllocDMA32                uint64 `json:"pgalloc_dma32"`
	PageAllocNormal               uint64 `json:"pgalloc_normal"`
	PageAllocMovable              uint64 `json:"pgalloc_movable"`
	PageFree                      uint64 `json:"pgfree"`
	PageActivate                  uint64 `json:"pgactivate"`
	PageDeactivate                uint64 `json:"pgdeactivate"`
	PageFault                     uint64 `json:"pgfault"`
	PageMajorFault                uint64 `json:"pgmajfault"`
	PageRefillDMA                 uint64 `json:"pgrefill_dma"`
	PageRefillDMA32               uint64 `json:"pgrefill_dma32"`
	PageRefillMormal              uint64 `json:"pgrefill_normal"`
	PageRefillMovable             uint64 `json:"pgrefill_movable"`
	PageStealKswapdDMA            uint64 `json:"pgsteal_kswapd_dma"`
	PageStealKswapdDMA32          uint64 `json:"pgsteal_kswapd_dma32"`
	PageStealKswapdNormal         uint64 `json:"pgsteal_kswapd_normal"`
	PageStealKswapdMovable        uint64 `json:"pgsteal_kswapd_movable"`
	PageStealDirectDMA            uint64 `json:"pgsteal_direct_dma"`
	PageStealDirectDMA32          uint64 `json:"pgsteal_direct_dma32"`
	PageStealDirectNormal         uint64 `json:"pgsteal_direct_normal"`
	PageStealDirectMovable        uint64 `json:"pgsteal_direct_movable"`
	PageScanKswapdDMA             uint64 `json:"pgscan_kswapd_dma"`
	PageScanKswapdDMA32           uint64 `json:"pgscan_kswapd_dma32"`
	PageScanKswapdNormal          uint64 `json:"pgscan_kswapd_normal"`
	PageScanKswapdMovable         uint64 `json:"pgscan_kswapd_movable"`
	PageScanDirectDMA             uint64 `json:"pgscan_direct_dma"`
	PageScanDirectDMA32           uint64 `json:"pgscan_direct_dma32"`
	PageScanDirectNormal          uint64 `json:"pgscan_direct_normal"`
	PageScanDirectMovable         uint64 `json:"pgscan_direct_movable"`
	PageScanDirectThrottle        uint64 `json:"pgscan_direct_throttle"`
	ZoneReclaimFailed             uint64 `json:"zone_reclaim_failed"`
	PageInodeSteal                uint64 `json:"pginodesteal"`
	SlabsScanned                  uint64 `json:"slabs_scanned"`
	KswapdInodesteal              uint64 `json:"kswapd_inodesteal"`
	KswapdLowWatermarkHitQuickly  uint64 `json:"kswapd_low_wmark_hit_quickly"`
	KswapdHighWatermarkHitQuickly uint64 `json:"kswapd_high_wmark_hit_quickly"`
	PageoutRun                    uint64 `json:"pageoutrun"`
	AllocStall                    uint64 `json:"allocstall"`
	PageRotated                   uint64 `json:"pgrotated"`
	DropPagecache                 uint64 `json:"drop_pagecache"`
	DropSlab                      uint64 `json:"drop_slab"`
	NumaPteUpdates                uint64 `json:"numa_pte_updates"`
	NumaHugePteUpdates            uint64 `json:"numa_huge_pte_updates"`
	NumaHintFaults                uint64 `json:"numa_hint_faults"`
	NumaHintFaults_local          uint64 `json:"numa_hint_faults_local"`
	NumaPagesMigrated             uint64 `json:"numa_pages_migrated"`
	PageMigrateSuccess            uint64 `json:"pgmigrate_success"`
	PageMigrateFail               uint64 `json:"pgmigrate_fail"`
	CompactMigrateScanned         uint64 `json:"compact_migrate_scanned"`
	CompactFreeScanned            uint64 `json:"compact_free_scanned"`
	CompactIsolated               uint64 `json:"compact_isolated"`
	CompactStall                  uint64 `json:"compact_stall"`
	CompactFail                   uint64 `json:"compact_fail"`
	CompactSuccess                uint64 `json:"compact_success"`
	HtlbBuddyAllocSuccess         uint64 `json:"htlb_buddy_alloc_success"`
	HtlbBuddyAllocFail            uint64 `json:"htlb_buddy_alloc_fail"`
	UnevictablePagesCulled        uint64 `json:"unevictable_pgs_culled"`
	UnevictablePagesScanned       uint64 `json:"unevictable_pgs_scanned"`
	UnevictablePagesRescued       uint64 `json:"unevictable_pgs_rescued"`
	UnevictablePagesMlocked       uint64 `json:"unevictable_pgs_mlocked"`
	UnevictablePagesMunlocked     uint64 `json:"unevictable_pgs_munlocked"`
	UnevictablePagesCleared       uint64 `json:"unevictable_pgs_cleared"`
	UnevictablePagesStranded      uint64 `json:"unevictable_pgs_stranded"`
	THPFaultAlloc                 uint64 `json:"thp_fault_alloc"`
	THPFaultFallback              uint64 `json:"thp_fault_fallback"`
	THPCollapseAlloc              uint64 `json:"thp_collapse_alloc"`
	THPCollapseAllocFailed        uint64 `json:"thp_collapse_alloc_failed"`
	THPSplit                      uint64 `json:"thp_split"`
	THPZeroPageAlloc              uint64 `json:"thp_zero_page_alloc"`
	THPZeroPageAllocFailed        uint64 `json:"thp_zero_page_alloc_failed"`
}

func ReadVMStat(path string) (*VMStat, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	content := string(b)
	lines := strings.Split(content, "\n")
	vmstat := VMStat{}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		name := fields[0]
		value, _ := strconv.ParseUint(fields[1], 10, 64)
		switch name {
		case "nr_free_pages":
			vmstat.NrFreePages = value
		case "nr_alloc_batch":
			vmstat.NrAllocBatch = value
		case "nr_inactive_anon":
			vmstat.NrInactiveAnon = value
		case "nr_active_anon":
			vmstat.NrActiveAnon = value
		case "nr_inactive_file":
			vmstat.NrInactiveFile = value
		case "nr_active_file":
			vmstat.NrActiveFile = value
		case "nr_unevictable":
			vmstat.NrUnevictable = value
		case "nr_mlock":
			vmstat.NrMlock = value
		case "nr_anon_pages":
			vmstat.NrAnonPages = value
		case "nr_mapped":
			vmstat.NrMapped = value
		case "nr_file_pages":
			vmstat.NrFilePages = value
		case "nr_dirty":
			vmstat.NrDirty = value
		case "nr_writeback":
			vmstat.NrWriteback = value
		case "nr_slab_reclaimable":
			vmstat.NrSlabReclaimable = value
		case "nr_slab_unreclaimable":
			vmstat.NrSlabUnreclaimable = value
		case "nr_page_table_pages":
			vmstat.NrPageTablePages = value
		case "nr_kernel_stack":
			vmstat.NrKernelStack = value
		case "nr_unstable":
			vmstat.NrUnstable = value
		case "nr_bounce":
			vmstat.NrBounce = value
		case "nr_vmscan_write":
			vmstat.NrVmscanWrite = value
		case "nr_vmscan_immediate_reclaim":
			vmstat.NrVmscanImmediateReclaim = value
		case "nr_writeback_temp":
			vmstat.NrWritebackTemp = value
		case "nr_isolated_anon":
			vmstat.NrIsolatedAnon = value
		case "nr_isolated_file":
			vmstat.NrIsolatedFile = value
		case "nr_shmem":
			vmstat.NrShmem = value
		case "nr_dirtied":
			vmstat.NrDirtied = value
		case "nr_written":
			vmstat.NrWritten = value
		case "numa_hit":
			vmstat.NumaHit = value
		case "numa_miss":
			vmstat.NumaMiss = value
		case "numa_foreign":
			vmstat.NumaForeign = value
		case "numa_interleave":
			vmstat.NumaInterleave = value
		case "numa_local":
			vmstat.NumaLocal = value
		case "numa_other":
			vmstat.NumaOther = value
		case "workingset_refault":
			vmstat.WorkingsetRefault = value
		case "workingset_activate":
			vmstat.WorkingsetActivate = value
		case "workingset_nodereclaim":
			vmstat.WorkingsetNodereclaim = value
		case "nr_anon_transparent_hugepages":
			vmstat.NrAnonTransparentHugepages = value
		case "nr_free_cma":
			vmstat.NrFreeCma = value
		case "nr_dirty_threshold":
			vmstat.NrDirtyThreshold = value
		case "nr_dirty_background_threshold":
			vmstat.NrDirtyBackgroundThreshold = value
		case "pgpgin":
			vmstat.PagePagein = value
		case "pgpgout":
			vmstat.PagePageout = value
		case "pswpin":
			vmstat.PageSwapin = value
		case "pswpout":
			vmstat.PageSwapout = value
		case "pgalloc_dma":
			vmstat.PageAllocDMA = value
		case "pgalloc_dma32":
			vmstat.PageAllocDMA32 = value
		case "pgalloc_normal":
			vmstat.PageAllocNormal = value
		case "pgalloc_movable":
			vmstat.PageAllocMovable = value
		case "pgfree":
			vmstat.PageFree = value
		case "pgactivate":
			vmstat.PageActivate = value
		case "pgdeactivate":
			vmstat.PageDeactivate = value
		case "pgfault":
			vmstat.PageFault = value
		case "pgmajfault":
			vmstat.PageMajorFault = value
		case "pgrefill_dma":
			vmstat.PageRefillDMA = value
		case "pgrefill_dma32":
			vmstat.PageRefillDMA32 = value
		case "pgrefill_normal":
			vmstat.PageRefillMormal = value
		case "pgrefill_movable":
			vmstat.PageRefillMovable = value
		case "pgsteal_kswapd_dma":
			vmstat.PageStealKswapdDMA = value
		case "pgsteal_kswapd_dma32":
			vmstat.PageStealKswapdDMA32 = value
		case "pgsteal_kswapd_normal":
			vmstat.PageStealKswapdNormal = value
		case "pgsteal_kswapd_movable":
			vmstat.PageStealKswapdMovable = value
		case "pgsteal_direct_dma":
			vmstat.PageStealDirectDMA = value
		case "pgsteal_direct_dma32":
			vmstat.PageStealDirectDMA32 = value
		case "pgsteal_direct_normal":
			vmstat.PageStealDirectNormal = value
		case "pgsteal_direct_movable":
			vmstat.PageStealDirectMovable = value
		case "pgscan_kswapd_dma":
			vmstat.PageScanKswapdDMA = value
		case "pgscan_kswapd_dma32":
			vmstat.PageScanKswapdDMA32 = value
		case "pgscan_kswapd_normal":
			vmstat.PageScanKswapdNormal = value
		case "pgscan_kswapd_movable":
			vmstat.PageScanKswapdMovable = value
		case "pgscan_direct_dma":
			vmstat.PageScanDirectDMA = value
		case "pgscan_direct_dma32":
			vmstat.PageScanDirectDMA32 = value
		case "pgscan_direct_normal":
			vmstat.PageScanDirectNormal = value
		case "pgscan_direct_movable":
			vmstat.PageScanDirectMovable = value
		case "pgscan_direct_throttle":
			vmstat.PageScanDirectThrottle = value
		case "zone_reclaim_failed":
			vmstat.ZoneReclaimFailed = value
		case "pginodesteal":
			vmstat.PageInodeSteal = value
		case "slabs_scanned":
			vmstat.SlabsScanned = value
		case "kswapd_inodesteal":
			vmstat.KswapdInodesteal = value
		case "kswapd_low_wmark_hit_quickly":
			vmstat.KswapdLowWatermarkHitQuickly = value
		case "kswapd_high_wmark_hit_quickly":
			vmstat.KswapdHighWatermarkHitQuickly = value
		case "pageoutrun":
			vmstat.PageoutRun = value
		case "allocstall":
			vmstat.AllocStall = value
		case "pgrotated":
			vmstat.PageRotated = value
		case "drop_pagecache":
			vmstat.DropPagecache = value
		case "drop_slab":
			vmstat.DropSlab = value
		case "numa_pte_updates":
			vmstat.NumaPteUpdates = value
		case "numa_huge_pte_updates":
			vmstat.NumaHugePteUpdates = value
		case "numa_hint_faults":
			vmstat.NumaHintFaults = value
		case "numa_hint_faults_local":
			vmstat.NumaHintFaults_local = value
		case "numa_pages_migrated":
			vmstat.NumaPagesMigrated = value
		case "pgmigrate_success":
			vmstat.PageMigrateSuccess = value
		case "pgmigrate_fail":
			vmstat.PageMigrateFail = value
		case "compact_migrate_scanned":
			vmstat.CompactMigrateScanned = value
		case "compact_free_scanned":
			vmstat.CompactFreeScanned = value
		case "compact_isolated":
			vmstat.CompactIsolated = value
		case "compact_stall":
			vmstat.CompactStall = value
		case "compact_fail":
			vmstat.CompactFail = value
		case "compact_success":
			vmstat.CompactSuccess = value
		case "htlb_buddy_alloc_success":
			vmstat.HtlbBuddyAllocSuccess = value
		case "htlb_buddy_alloc_fail":
			vmstat.HtlbBuddyAllocFail = value
		case "unevictable_pgs_culled":
			vmstat.UnevictablePagesCulled = value
		case "unevictable_pgs_scanned":
			vmstat.UnevictablePagesScanned = value
		case "unevictable_pgs_rescued":
			vmstat.UnevictablePagesRescued = value
		case "unevictable_pgs_mlocked":
			vmstat.UnevictablePagesMlocked = value
		case "unevictable_pgs_munlocked":
			vmstat.UnevictablePagesMunlocked = value
		case "unevictable_pgs_cleared":
			vmstat.UnevictablePagesCleared = value
		case "unevictable_pgs_stranded":
			vmstat.UnevictablePagesStranded = value
		case "thp_fault_alloc":
			vmstat.THPFaultAlloc = value
		case "thp_fault_fallback":
			vmstat.THPFaultFallback = value
		case "thp_collapse_alloc":
			vmstat.THPCollapseAlloc = value
		case "thp_collapse_alloc_failed":
			vmstat.THPCollapseAllocFailed = value
		case "thp_split":
			vmstat.THPSplit = value
		case "thp_zero_page_alloc":
			vmstat.THPZeroPageAlloc = value
		case "thp_zero_page_alloc_failed":
			vmstat.THPZeroPageAllocFailed = value
		}
	}
	return &vmstat, nil
}
