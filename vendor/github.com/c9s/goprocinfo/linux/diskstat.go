package linux

import (
	"io/ioutil"
	"strconv"
	"strings"
	"time"
)

// DiskStat is disk statistics to help measure disk activity.
//
// Note:
// * On a very busy or long-lived system values may wrap.
// * No kernel locks are held while modifying these counters. This implies that
//   minor inaccuracies may occur.
//
// More more info see:
// https://www.kernel.org/doc/Documentation/iostats.txt and
// https://www.kernel.org/doc/Documentation/block/stat.txt
type DiskStat struct {
	Major        int    `json:"major"`         // major device number
	Minor        int    `json:"minor"`         // minor device number
	Name         string `json:"name"`          // device name
	ReadIOs      uint64 `json:"read_ios"`      // number of read I/Os processed
	ReadMerges   uint64 `json:"read_merges"`   // number of read I/Os merged with in-queue I/O
	ReadSectors  uint64 `json:"read_sectors"`  // number of 512 byte sectors read
	ReadTicks    uint64 `json:"read_ticks"`    // total wait time for read requests in milliseconds
	WriteIOs     uint64 `json:"write_ios"`     // number of write I/Os processed
	WriteMerges  uint64 `json:"write_merges"`  // number of write I/Os merged with in-queue I/O
	WriteSectors uint64 `json:"write_sectors"` // number of 512 byte sectors written
	WriteTicks   uint64 `json:"write_ticks"`   // total wait time for write requests in milliseconds
	InFlight     uint64 `json:"in_flight"`     // number of I/Os currently in flight
	IOTicks      uint64 `json:"io_ticks"`      // total time this block device has been active in milliseconds
	TimeInQueue  uint64 `json:"time_in_queue"` // total wait time for all requests in milliseconds
}

// ReadDiskStats reads and parses the file.
//
// Note:
// * Assumes a well formed file and will panic if it isn't.
func ReadDiskStats(path string) ([]DiskStat, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	devices := strings.Split(string(data), "\n")
	results := make([]DiskStat, len(devices)-1)

	for i := range results {
		fields := strings.Fields(devices[i])
		Major, _ := strconv.ParseInt(fields[0], 10, strconv.IntSize)
		results[i].Major = int(Major)
		Minor, _ := strconv.ParseInt(fields[1], 10, strconv.IntSize)
		results[i].Minor = int(Minor)
		results[i].Name = fields[2]
		results[i].ReadIOs, _ = strconv.ParseUint(fields[3], 10, 64)
		results[i].ReadMerges, _ = strconv.ParseUint(fields[4], 10, 64)
		results[i].ReadSectors, _ = strconv.ParseUint(fields[5], 10, 64)
		results[i].ReadTicks, _ = strconv.ParseUint(fields[6], 10, 64)
		results[i].WriteIOs, _ = strconv.ParseUint(fields[7], 10, 64)
		results[i].WriteMerges, _ = strconv.ParseUint(fields[8], 10, 64)
		results[i].WriteSectors, _ = strconv.ParseUint(fields[9], 10, 64)
		results[i].WriteTicks, _ = strconv.ParseUint(fields[10], 10, 64)
		results[i].InFlight, _ = strconv.ParseUint(fields[11], 10, 64)
		results[i].IOTicks, _ = strconv.ParseUint(fields[12], 10, 64)
		results[i].TimeInQueue, _ = strconv.ParseUint(fields[13], 10, 64)
	}

	return results, nil
}

// GetReadBytes returns the number of bytes read.
func (ds *DiskStat) GetReadBytes() int64 {
	return int64(ds.ReadSectors) * 512
}

// GetReadTicks returns the duration waited for read requests.
func (ds *DiskStat) GetReadTicks() time.Duration {
	return time.Duration(ds.ReadTicks) * time.Millisecond
}

// GetWriteBytes returns the number of bytes written.
func (ds *DiskStat) GetWriteBytes() int64 {
	return int64(ds.WriteSectors) * 512
}

// GetReadTicks returns the duration waited for write requests.
func (ds *DiskStat) GetWriteTicks() time.Duration {
	return time.Duration(ds.WriteTicks) * time.Millisecond
}

// GetIOTicks returns the duration the disk has been active.
func (ds *DiskStat) GetIOTicks() time.Duration {
	return time.Duration(ds.IOTicks) * time.Millisecond
}

// GetTimeInQueue returns the duration waited for all requests.
func (ds *DiskStat) GetTimeInQueue() time.Duration {
	return time.Duration(ds.TimeInQueue) * time.Millisecond
}
