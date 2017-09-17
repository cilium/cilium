// Copyright 2014 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package libcontainer

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/google/cadvisor/container"
	info "github.com/google/cadvisor/info/v1"

	"github.com/golang/glog"
	"github.com/opencontainers/runc/libcontainer"
	"github.com/opencontainers/runc/libcontainer/cgroups"
)

/*
#include <unistd.h>
*/
import "C"

type CgroupSubsystems struct {
	// Cgroup subsystem mounts.
	// e.g.: "/sys/fs/cgroup/cpu" -> ["cpu", "cpuacct"]
	Mounts []cgroups.Mount

	// Cgroup subsystem to their mount location.
	// e.g.: "cpu" -> "/sys/fs/cgroup/cpu"
	MountPoints map[string]string
}

// Get information about the cgroup subsystems.
func GetCgroupSubsystems() (CgroupSubsystems, error) {
	// Get all cgroup mounts.
	allCgroups, err := cgroups.GetCgroupMounts(true)
	if err != nil {
		return CgroupSubsystems{}, err
	}
	if len(allCgroups) == 0 {
		return CgroupSubsystems{}, fmt.Errorf("failed to find cgroup mounts")
	}

	// Trim the mounts to only the subsystems we care about.
	supportedCgroups := make([]cgroups.Mount, 0, len(allCgroups))
	mountPoints := make(map[string]string, len(allCgroups))
	for _, mount := range allCgroups {
		for _, subsystem := range mount.Subsystems {
			if _, ok := supportedSubsystems[subsystem]; ok {
				supportedCgroups = append(supportedCgroups, mount)
				mountPoints[subsystem] = mount.Mountpoint
			}
		}
	}

	return CgroupSubsystems{
		Mounts:      supportedCgroups,
		MountPoints: mountPoints,
	}, nil
}

// Cgroup subsystems we support listing (should be the minimal set we need stats from).
var supportedSubsystems map[string]struct{} = map[string]struct{}{
	"cpu":     {},
	"cpuacct": {},
	"memory":  {},
	"cpuset":  {},
	"blkio":   {},
}

// Get cgroup and networking stats of the specified container
func GetStats(cgroupManager cgroups.Manager, rootFs string, pid int, ignoreMetrics container.MetricSet) (*info.ContainerStats, error) {
	cgroupStats, err := cgroupManager.GetStats()
	if err != nil {
		return nil, err
	}
	libcontainerStats := &libcontainer.Stats{
		CgroupStats: cgroupStats,
	}
	stats := newContainerStats(libcontainerStats)

	// If we know the pid then get network stats from /proc/<pid>/net/dev
	if pid == 0 {
		return stats, nil
	}
	if !ignoreMetrics.Has(container.NetworkUsageMetrics) {
		netStats, err := networkStatsFromProc(rootFs, pid)
		if err != nil {
			glog.V(4).Infof("Unable to get network stats from pid %d: %v", pid, err)
		} else {
			stats.Network.Interfaces = append(stats.Network.Interfaces, netStats...)
		}
	}
	if !ignoreMetrics.Has(container.NetworkTcpUsageMetrics) {
		t, err := tcpStatsFromProc(rootFs, pid, "net/tcp")
		if err != nil {
			glog.V(4).Infof("Unable to get tcp stats from pid %d: %v", pid, err)
		} else {
			stats.Network.Tcp = t
		}

		t6, err := tcpStatsFromProc(rootFs, pid, "net/tcp6")
		if err != nil {
			glog.V(4).Infof("Unable to get tcp6 stats from pid %d: %v", pid, err)
		} else {
			stats.Network.Tcp6 = t6
		}
	}
	if !ignoreMetrics.Has(container.NetworkUdpUsageMetrics) {
		u, err := udpStatsFromProc(rootFs, pid, "net/udp")
		if err != nil {
			glog.V(4).Infof("Unable to get udp stats from pid %d: %v", pid, err)
		} else {
			stats.Network.Udp = u
		}

		u6, err := udpStatsFromProc(rootFs, pid, "net/udp6")
		if err != nil {
			glog.V(4).Infof("Unable to get udp6 stats from pid %d: %v", pid, err)
		} else {
			stats.Network.Udp6 = u6
		}
	}

	// For backwards compatibility.
	if len(stats.Network.Interfaces) > 0 {
		stats.Network.InterfaceStats = stats.Network.Interfaces[0]
	}

	return stats, nil
}

func networkStatsFromProc(rootFs string, pid int) ([]info.InterfaceStats, error) {
	netStatsFile := path.Join(rootFs, "proc", strconv.Itoa(pid), "/net/dev")

	ifaceStats, err := scanInterfaceStats(netStatsFile)
	if err != nil {
		return []info.InterfaceStats{}, fmt.Errorf("couldn't read network stats: %v", err)
	}

	return ifaceStats, nil
}

var (
	ignoredDevicePrefixes = []string{"lo", "veth", "docker"}
)

func isIgnoredDevice(ifName string) bool {
	for _, prefix := range ignoredDevicePrefixes {
		if strings.HasPrefix(strings.ToLower(ifName), prefix) {
			return true
		}
	}
	return false
}

func scanInterfaceStats(netStatsFile string) ([]info.InterfaceStats, error) {
	file, err := os.Open(netStatsFile)
	if err != nil {
		return nil, fmt.Errorf("failure opening %s: %v", netStatsFile, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	// Discard header lines
	for i := 0; i < 2; i++ {
		if b := scanner.Scan(); !b {
			return nil, scanner.Err()
		}
	}

	stats := []info.InterfaceStats{}
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.Replace(line, ":", "", -1)

		fields := strings.Fields(line)
		// If the format of the  line is invalid then don't trust any of the stats
		// in this file.
		if len(fields) != 17 {
			return nil, fmt.Errorf("invalid interface stats line: %v", line)
		}

		devName := fields[0]
		if isIgnoredDevice(devName) {
			continue
		}

		i := info.InterfaceStats{
			Name: devName,
		}

		statFields := append(fields[1:5], fields[9:13]...)
		statPointers := []*uint64{
			&i.RxBytes, &i.RxPackets, &i.RxErrors, &i.RxDropped,
			&i.TxBytes, &i.TxPackets, &i.TxErrors, &i.TxDropped,
		}

		err := setInterfaceStatValues(statFields, statPointers)
		if err != nil {
			return nil, fmt.Errorf("cannot parse interface stats (%v): %v", err, line)
		}

		stats = append(stats, i)
	}

	return stats, nil
}

func setInterfaceStatValues(fields []string, pointers []*uint64) error {
	for i, v := range fields {
		val, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return err
		}
		*pointers[i] = val
	}
	return nil
}

func tcpStatsFromProc(rootFs string, pid int, file string) (info.TcpStat, error) {
	tcpStatsFile := path.Join(rootFs, "proc", strconv.Itoa(pid), file)

	tcpStats, err := scanTcpStats(tcpStatsFile)
	if err != nil {
		return tcpStats, fmt.Errorf("couldn't read tcp stats: %v", err)
	}

	return tcpStats, nil
}

func scanTcpStats(tcpStatsFile string) (info.TcpStat, error) {

	var stats info.TcpStat

	data, err := ioutil.ReadFile(tcpStatsFile)
	if err != nil {
		return stats, fmt.Errorf("failure opening %s: %v", tcpStatsFile, err)
	}

	tcpStateMap := map[string]uint64{
		"01": 0, //ESTABLISHED
		"02": 0, //SYN_SENT
		"03": 0, //SYN_RECV
		"04": 0, //FIN_WAIT1
		"05": 0, //FIN_WAIT2
		"06": 0, //TIME_WAIT
		"07": 0, //CLOSE
		"08": 0, //CLOSE_WAIT
		"09": 0, //LAST_ACK
		"0A": 0, //LISTEN
		"0B": 0, //CLOSING
	}

	reader := strings.NewReader(string(data))
	scanner := bufio.NewScanner(reader)

	scanner.Split(bufio.ScanLines)

	// Discard header line
	if b := scanner.Scan(); !b {
		return stats, scanner.Err()
	}

	for scanner.Scan() {
		line := scanner.Text()

		state := strings.Fields(line)
		// TCP state is the 4th field.
		// Format: sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt  uid timeout inode
		tcpState := state[3]
		_, ok := tcpStateMap[tcpState]
		if !ok {
			return stats, fmt.Errorf("invalid TCP stats line: %v", line)
		}
		tcpStateMap[tcpState]++
	}

	stats = info.TcpStat{
		Established: tcpStateMap["01"],
		SynSent:     tcpStateMap["02"],
		SynRecv:     tcpStateMap["03"],
		FinWait1:    tcpStateMap["04"],
		FinWait2:    tcpStateMap["05"],
		TimeWait:    tcpStateMap["06"],
		Close:       tcpStateMap["07"],
		CloseWait:   tcpStateMap["08"],
		LastAck:     tcpStateMap["09"],
		Listen:      tcpStateMap["0A"],
		Closing:     tcpStateMap["0B"],
	}

	return stats, nil
}

func udpStatsFromProc(rootFs string, pid int, file string) (info.UdpStat, error) {
	var err error
	var udpStats info.UdpStat

	udpStatsFile := path.Join(rootFs, "proc", strconv.Itoa(pid), file)

	r, err := os.Open(udpStatsFile)
	if err != nil {
		return udpStats, fmt.Errorf("failure opening %s: %v", udpStatsFile, err)
	}

	udpStats, err = scanUdpStats(r)
	if err != nil {
		return udpStats, fmt.Errorf("couldn't read udp stats: %v", err)
	}

	return udpStats, nil
}

func scanUdpStats(r io.Reader) (info.UdpStat, error) {
	var stats info.UdpStat

	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanLines)

	// Discard header line
	if b := scanner.Scan(); !b {
		return stats, scanner.Err()
	}

	listening := uint64(0)
	dropped := uint64(0)
	rxQueued := uint64(0)
	txQueued := uint64(0)

	for scanner.Scan() {
		line := scanner.Text()
		// Format: sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt  uid timeout inode ref pointer drops

		listening++

		fs := strings.Fields(line)
		if len(fs) != 13 {
			continue
		}

		rx, tx := uint64(0), uint64(0)
		fmt.Sscanf(fs[4], "%X:%X", &rx, &tx)
		rxQueued += rx
		txQueued += tx

		d, err := strconv.Atoi(string(fs[12]))
		if err != nil {
			continue
		}
		dropped += uint64(d)
	}

	stats = info.UdpStat{
		Listen:   listening,
		Dropped:  dropped,
		RxQueued: rxQueued,
		TxQueued: txQueued,
	}

	return stats, nil
}

func GetProcesses(cgroupManager cgroups.Manager) ([]int, error) {
	pids, err := cgroupManager.GetPids()
	if err != nil {
		return nil, err
	}
	return pids, nil
}

func DiskStatsCopy0(major, minor uint64) *info.PerDiskStats {
	disk := info.PerDiskStats{
		Major: major,
		Minor: minor,
	}
	disk.Stats = make(map[string]uint64)
	return &disk
}

type DiskKey struct {
	Major uint64
	Minor uint64
}

func DiskStatsCopy1(disk_stat map[DiskKey]*info.PerDiskStats) []info.PerDiskStats {
	i := 0
	stat := make([]info.PerDiskStats, len(disk_stat))
	for _, disk := range disk_stat {
		stat[i] = *disk
		i++
	}
	return stat
}

func DiskStatsCopy(blkio_stats []cgroups.BlkioStatEntry) (stat []info.PerDiskStats) {
	if len(blkio_stats) == 0 {
		return
	}
	disk_stat := make(map[DiskKey]*info.PerDiskStats)
	for i := range blkio_stats {
		major := blkio_stats[i].Major
		minor := blkio_stats[i].Minor
		disk_key := DiskKey{
			Major: major,
			Minor: minor,
		}
		diskp, ok := disk_stat[disk_key]
		if !ok {
			diskp = DiskStatsCopy0(major, minor)
			disk_stat[disk_key] = diskp
		}
		op := blkio_stats[i].Op
		if op == "" {
			op = "Count"
		}
		diskp.Stats[op] = blkio_stats[i].Value
	}
	return DiskStatsCopy1(disk_stat)
}

func minUint32(x, y uint32) uint32 {
	if x < y {
		return x
	}
	return y
}

// var to allow unit tests to stub it out
var numCpusFunc = getNumberOnlineCPUs

// Convert libcontainer stats to info.ContainerStats.
func setCpuStats(s *cgroups.Stats, ret *info.ContainerStats) {
	ret.Cpu.Usage.User = s.CpuStats.CpuUsage.UsageInUsermode
	ret.Cpu.Usage.System = s.CpuStats.CpuUsage.UsageInKernelmode
	numPossible := uint32(len(s.CpuStats.CpuUsage.PercpuUsage))
	// Note that as of https://patchwork.kernel.org/patch/8607101/ (kernel v4.7),
	// the percpu usage information includes extra zero values for all additional
	// possible CPUs. This is to allow statistic collection after CPU-hotplug.
	// We intentionally ignore these extra zeroes.
	numActual, err := numCpusFunc()
	if err != nil {
		glog.Errorf("unable to determine number of actual cpus; defaulting to maximum possible number: errno %v", err)
		numActual = numPossible
	}
	if numActual > numPossible {
		// The real number of cores should never be greater than the number of
		// datapoints reported in cpu usage.
		glog.Errorf("PercpuUsage had %v cpus, but the actual number is %v; ignoring extra CPUs", numPossible, numActual)
	}
	numActual = minUint32(numPossible, numActual)
	ret.Cpu.Usage.PerCpu = make([]uint64, numActual)

	ret.Cpu.Usage.Total = 0
	for i := uint32(0); i < numActual; i++ {
		ret.Cpu.Usage.PerCpu[i] = s.CpuStats.CpuUsage.PercpuUsage[i]
		ret.Cpu.Usage.Total += s.CpuStats.CpuUsage.PercpuUsage[i]
	}

	ret.Cpu.CFS.Periods = s.CpuStats.ThrottlingData.Periods
	ret.Cpu.CFS.ThrottledPeriods = s.CpuStats.ThrottlingData.ThrottledPeriods
	ret.Cpu.CFS.ThrottledTime = s.CpuStats.ThrottlingData.ThrottledTime
}

// Copied from
// https://github.com/moby/moby/blob/8b1adf55c2af329a4334f21d9444d6a169000c81/daemon/stats/collector_unix.go#L73
// Apache 2.0, Copyright Docker, Inc.
func getNumberOnlineCPUs() (uint32, error) {
	i, err := C.sysconf(C._SC_NPROCESSORS_ONLN)
	// According to POSIX - errno is undefined after successful
	// sysconf, and can be non-zero in several cases, so look for
	// error in returned value not in errno.
	// (https://sourceware.org/bugzilla/show_bug.cgi?id=21536)
	if i == -1 {
		return 0, err
	}
	return uint32(i), nil
}

func setDiskIoStats(s *cgroups.Stats, ret *info.ContainerStats) {
	ret.DiskIo.IoServiceBytes = DiskStatsCopy(s.BlkioStats.IoServiceBytesRecursive)
	ret.DiskIo.IoServiced = DiskStatsCopy(s.BlkioStats.IoServicedRecursive)
	ret.DiskIo.IoQueued = DiskStatsCopy(s.BlkioStats.IoQueuedRecursive)
	ret.DiskIo.Sectors = DiskStatsCopy(s.BlkioStats.SectorsRecursive)
	ret.DiskIo.IoServiceTime = DiskStatsCopy(s.BlkioStats.IoServiceTimeRecursive)
	ret.DiskIo.IoWaitTime = DiskStatsCopy(s.BlkioStats.IoWaitTimeRecursive)
	ret.DiskIo.IoMerged = DiskStatsCopy(s.BlkioStats.IoMergedRecursive)
	ret.DiskIo.IoTime = DiskStatsCopy(s.BlkioStats.IoTimeRecursive)
}

func setMemoryStats(s *cgroups.Stats, ret *info.ContainerStats) {
	ret.Memory.Usage = s.MemoryStats.Usage.Usage
	ret.Memory.Failcnt = s.MemoryStats.Usage.Failcnt
	ret.Memory.Cache = s.MemoryStats.Stats["cache"]

	if s.MemoryStats.UseHierarchy {
		ret.Memory.RSS = s.MemoryStats.Stats["total_rss"]
		ret.Memory.Swap = s.MemoryStats.Stats["total_swap"]
	} else {
		ret.Memory.RSS = s.MemoryStats.Stats["rss"]
		ret.Memory.Swap = s.MemoryStats.Stats["swap"]
	}
	if v, ok := s.MemoryStats.Stats["pgfault"]; ok {
		ret.Memory.ContainerData.Pgfault = v
		ret.Memory.HierarchicalData.Pgfault = v
	}
	if v, ok := s.MemoryStats.Stats["pgmajfault"]; ok {
		ret.Memory.ContainerData.Pgmajfault = v
		ret.Memory.HierarchicalData.Pgmajfault = v
	}

	workingSet := ret.Memory.Usage
	if v, ok := s.MemoryStats.Stats["total_inactive_file"]; ok {
		if workingSet < v {
			workingSet = 0
		} else {
			workingSet -= v
		}
	}
	ret.Memory.WorkingSet = workingSet
}

func setNetworkStats(libcontainerStats *libcontainer.Stats, ret *info.ContainerStats) {
	ret.Network.Interfaces = make([]info.InterfaceStats, len(libcontainerStats.Interfaces))
	for i := range libcontainerStats.Interfaces {
		ret.Network.Interfaces[i] = info.InterfaceStats{
			Name:      libcontainerStats.Interfaces[i].Name,
			RxBytes:   libcontainerStats.Interfaces[i].RxBytes,
			RxPackets: libcontainerStats.Interfaces[i].RxPackets,
			RxErrors:  libcontainerStats.Interfaces[i].RxErrors,
			RxDropped: libcontainerStats.Interfaces[i].RxDropped,
			TxBytes:   libcontainerStats.Interfaces[i].TxBytes,
			TxPackets: libcontainerStats.Interfaces[i].TxPackets,
			TxErrors:  libcontainerStats.Interfaces[i].TxErrors,
			TxDropped: libcontainerStats.Interfaces[i].TxDropped,
		}
	}

	// Add to base struct for backwards compatibility.
	if len(ret.Network.Interfaces) > 0 {
		ret.Network.InterfaceStats = ret.Network.Interfaces[0]
	}
}

func newContainerStats(libcontainerStats *libcontainer.Stats) *info.ContainerStats {
	ret := &info.ContainerStats{
		Timestamp: time.Now(),
	}

	if s := libcontainerStats.CgroupStats; s != nil {
		setCpuStats(s, ret)
		setDiskIoStats(s, ret)
		setMemoryStats(s, ret)
	}
	if len(libcontainerStats.Interfaces) > 0 {
		setNetworkStats(libcontainerStats, ret)
	}
	return ret
}
