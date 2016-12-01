#!/bin/bash

source "./helpers.bash"

set -e

TEST_NET="cilium"
NETPERF_IMAGE="noironetworks/netperf"

function cleanup {
	docker rm -f server1 server2 client 2> /dev/null || true
	monitor_stop
	rm netdev_config.h tmp_lb.o 2> /dev/null || true
	sudo ip link del lbtest1 2> /dev/null || true
}

function mac2array()
{
	echo "{0x${1//:/,0x}}"
}

function host_ip6()
{
	ip -6 addr show cilium_host scope global | grep inet6 | awk '{print $2}' | sed -e 's/\/.*//'
}

function host_ip4()
{
	ip -4 addr show cilium_host scope global | grep inet | awk '{print $2}' | sed -e 's/\/.*//'
}

trap cleanup EXIT

# Remove containers from a previously incomplete run
cleanup

set -x

# Test the addition and removal of services with and without daemon

# Clean everything first
cilium lb delete-service --all
sudo cilium lb --no-daemon dump-service

cilium lb delete-rev-nat --all
sudo cilium lb --no-daemon delete-rev-nat --all

# Check if everything was deleted
if [ -n "$(cilium lb dump-service)" ]; then
	abort "Daemon's services map should be clean"
fi
if [ -n "$(sudo cilium lb --no-daemon dump-service)" ]; then
	abort "Services map should be clean"
fi

if [ -n "$(cilium lb dump-rev-nat)" ]; then
	abort "Daemon's rev nat map should be clean"
fi
if [ -n "$(sudo cilium lb --no-daemon dump-rev-nat)" ]; then
	abort "Rev nat's map should be clean"
fi

# Add a service with ID 0, it should fail
sudo cilium lb --no-daemon update-service --frontend [::]:80 --backend [::1]:90 --backend [::2]:91 --id 0 --rev 2> /dev/null && {
	abort "Unexpected success in creating a frontend with reverse nat ID 0"
}

if [ -n "$(sudo cilium lb --no-daemon dump-service)" ]; then
	abort "Services map should be clean"
fi

# Add a service with ID 1
sudo cilium lb --no-daemon update-service --frontend [::]:80 --backend [::1]:90 --backend [::2]:91 --id 1 --rev 2> /dev/null || {
	abort "Service should have been added"
}

# Daemon's map should be empty
if [ -n "$(cilium lb dump-service)" ]; then
	abort "Daemon's services map should be clean"
fi

# Check if it's the only service present
if [[ "$(sudo cilium lb --no-daemon dump-service)" != \
      "$(echo -e "[::]:80 =>\n\t\t1 => [::1]:90 (1)\n\t\t2 => [::2]:91 (1)")" ]]; then
     abort "Service was not properly added"
fi

# Check if we can get the service by it's ID
if [[ "$(sudo cilium lb --no-daemon get-service [::]:80)" != \
      "$(echo -e "[::]:80 =>\n\t\t1 => [::1]:90 (1)\n\t\t2 => [::2]:91 (1)")" ]]; then
     abort "Service was not properly added"
fi

# Check if it's the only RevNAT present
if [[ "$(sudo cilium lb --no-daemon dump-rev-nat)" != \
      "$(echo -e "IPv6:\n1 => [::]:80")" ]]; then
     abort "RevNAT's service was not properly added"
fi

# Check if we can get the RevNAT by it's ID
if [[ "$(sudo cilium lb --no-daemon get-rev-nat 1)" != \
      "$(echo -e "1 => [::]:80")" ]]; then
     abort "RevNAT's service was not properly added"
fi

# Add a service with ID 0 to the daemon, it should fail
cilium lb update-service --frontend [::]:80 --backend [::1]:90 --backend [::2]:91 --id 0 --rev 2> /dev/null && {
	abort "Unexpected success in creating a frontend with reverse nat ID 0"
}

# Daemon's map should be empty
if [ -n "$(cilium lb dump-service)" ]; then
	abort "Daemon's services map should be clean"
fi

# BPF's map should be unmodified
if [[ "$(sudo cilium lb --no-daemon dump-service)" != \
      "$(echo -e "[::]:80 =>\n\t\t1 => [::1]:90 (1)\n\t\t2 => [::2]:91 (1)")" ]]; then
     abort "Service was not properly added"
fi

# Add a service with ID 2
cilium lb update-service --frontend [::]:80 --backend [::1]:90 --backend [::2]:91 --id 2 --rev 2> /dev/null || {
	abort "Service should have been added"
}

# Check if it's the only service present
if [[ "$(cilium lb dump-service)" != \
      "$(echo -e "[::]:80 =>\n\t\t1 => [::1]:90 (2)\n\t\t2 => [::2]:91 (2)")" ]]; then
     abort "Service was not properly added"
fi

# Check if we can get the service by it's ID
if [[ "$(cilium lb get-service [::]:80)" != \
      "$(echo -e "[::]:80 =>\n\t\t1 => [::1]:90 (2)\n\t\t2 => [::2]:91 (2)")" ]]; then
     abort "Service was not properly added"
fi

# BPF's map should contain service with a different RevNAT ID
if [[ "$(sudo cilium lb --no-daemon dump-service)" != \
      "$(echo -e "[::]:80 =>\n\t\t1 => [::1]:90 (2)\n\t\t2 => [::2]:91 (2)\n")" ]]; then
     abort "Service was not properly added"
fi

# Check if it's the only RevNAT present
if [[ "$(cilium lb dump-rev-nat)" != \
      "$(echo -e "IPv6:\n2 => [::]:80")" ]]; then
     abort "RevNAT's service was not properly added"
fi

# Check if we can get the RevNAT by it's ID
if [[ "$(cilium lb get-rev-nat 2)" != \
      "$(echo -e "2 => [::]:80")" ]]; then
     abort "RevNAT's service was not properly added"
fi

# BPF's RevNAT map's should contain both RevNATs
if [[ "$(sudo cilium lb --no-daemon dump-rev-nat)" != \
      "$(echo -e "IPv6:\n1 => [::]:80\n2 => [::]:80")" ]]; then
     abort "RevNAT's service was not properly added"
fi

# Let's try delete RevNAT 1
if [[ "$(cilium lb delete-rev-nat 1)" != \
      "$(echo -e "Successfully deleted")" ]]; then
     abort "RevNAT's was not deleted"
fi

# BPF's RevNAT map's should contain both RevNATs
if [[ "$(sudo cilium lb --no-daemon dump-rev-nat)" != \
      "$(echo -e "IPv6:\n1 => [::]:80\n2 => [::]:80")" ]]; then
     abort "RevNAT's service was wrongly deleted"
fi

# Let's try delete RevNAT 2
if [[ "$(cilium lb delete-rev-nat 2)" != \
      "$(echo -e "Successfully deleted")" ]]; then
     abort "RevNAT's was not deleted"
fi

# Let's try delete RevNAT 2
if [[ "$(cilium lb dump-rev-nat)" != \
      "$(echo -e "")" ]]; then
     abort "RevNAT's was not deleted"
fi

# BPF's RevNAT map's should contain RevNAT with ID 1
if [[ "$(sudo cilium lb --no-daemon dump-rev-nat)" != \
      "$(echo -e "IPv6:\n1 => [::]:80")" ]]; then
     abort "RevNAT's service was not properly deleted"
fi

# Let's try delete the only service
if [[ "$(cilium lb delete-service [::]:80)" != \
      "$(echo -e "Successfully deleted")" ]]; then
     abort "RevNAT's was not deleted"
fi

# Let's delete the remaining RevNAT with ID 1
if [[ "$(sudo cilium lb --no-daemon delete-rev-nat 1)" != \
      "$(echo -e "Successfully deleted")" ]]; then
     abort "RevNAT's service was not properly deleted"
fi

# Check if everything was deleted
if [ -n "$(cilium lb dump-service)" ]; then
	abort "Daemon's services map should be clean"
fi

#FIXME The services maps are not being properly cleaned
#if [ -n "$(sudo cilium lb --no-daemon dump-service)" ]; then
#	abort "Services map should be clean"
#fi

if [ -n "$(cilium lb dump-rev-nat)" ]; then
	abort "Daemon's rev nat map should be clean"
fi
if [ -n "$(sudo cilium lb --no-daemon dump-rev-nat)" ]; then
	abort "Rev nat's map should be clean"
fi

# Test SyncLBMap

# Clean everything first
cilium lb delete-service --all
sudo cilium lb --no-daemon dump-service
cilium lb delete-rev-nat --all
sudo cilium lb --no-daemon delete-rev-nat --all


# Add a service with ID 2
cilium lb update-service --frontend [::]:80 --backend [::1]:90 --backend [::2]:91 --id 2 --rev 2> /dev/null || {
	abort "Service should have been added"
}

# Add the same service with ID 1
sudo cilium lb --no-daemon update-service --frontend [::]:80 --backend [::1]:90 --backend [::2]:91 --id 1 --rev 2> /dev/null || {
	abort "Service should have been added"
}

# Add other service with ID 3
sudo cilium lb --no-daemon update-service --frontend [::1]:80 --backend [::1]:90 --backend [::2]:91 --id 3 --rev 2> /dev/null || {
	abort "Service should have been added"
}

# BPF's map should contain service with RevNAT ID 1
if [[ "$(sudo cilium lb --no-daemon dump-service)" != \
      "$(echo -e "[::1]:80 =>\n\t\t1 => [::1]:90 (3)\n\t\t2 => [::2]:91 (3)\n[::]:80 =>\n\t\t1 => [::1]:90 (1)\n\t\t2 => [::2]:91 (1)\n")" ]]; then
     abort "Service was not properly added"
fi

# Daemon's map should contain service with RevNAT ID 2
if [[ "$(cilium lb dump-service)" != \
      "$(echo -e "[::]:80 =>\n\t\t1 => [::1]:90 (2)\n\t\t2 => [::2]:91 (2)\n")" ]]; then
     abort "Service was not properly added"
fi

# BPF's RevNAT map's should contain all RevNATs
if [[ "$(sudo cilium lb --no-daemon dump-rev-nat)" != \
      "$(echo -e "IPv6:\n1 => [::]:80\n2 => [::]:80\n3 => [::1]:80")" ]]; then
     abort "RevNAT's service was not properly added"
fi

# Daemon's RevNAT map's should contain only 1 RevNATs
if [[ "$(cilium lb dump-rev-nat)" != \
      "$(echo -e "IPv6:\n2 => [::]:80")" ]]; then
     abort "RevNAT's service was not properly added"
fi

# Sync LB Maps
cilium lb sync-lb-maps 2> /dev/null || {
	abort "Unable to sync LB Maps"
}

# Daemon's map should contain service with RevNAT ID 2
if [[ "$(cilium lb dump-service)" != \
      "$(echo -e "[::1]:80 =>\n\t\t1 => [::1]:90 (3)\n\t\t2 => [::2]:91 (3)\n[::]:80 =>\n\t\t1 => [::1]:90 (2)\n\t\t2 => [::2]:91 (2)\n")" ]]; then
     abort "Service was not properly synced"
fi

# BPF's map should contain service with RevNAT ID 2
if [[ "$(sudo cilium lb --no-daemon dump-service)" != \
      "$(echo -e "[::1]:80 =>\n\t\t1 => [::1]:90 (3)\n\t\t2 => [::2]:91 (3)\n[::]:80 =>\n\t\t1 => [::1]:90 (2)\n\t\t2 => [::2]:91 (2)\n")" ]]; then
     abort "Service was not properly synced"
fi

# BPF's RevNAT map's should contain RevNATs 2 and 3, number 1 was removed since the new
# service ID is 2.
if [[ "$(sudo cilium lb --no-daemon dump-rev-nat)" != \
      "$(echo -e "IPv6:\n2 => [::]:80\n3 => [::1]:80")" ]]; then
     abort "RevNAT's service was not properly synced"
fi

# Daemon's RevNAT map's should contain RevNATs 2 and 3, number 1 was removed since the new
# service ID is 2.
if [[ "$(cilium lb dump-rev-nat)" != \
      "$(echo -e "IPv6:\n2 => [::]:80\n3 => [::1]:80")" ]]; then
     abort "RevNAT's service was not properly synced"
fi

# Test the same for IPv4 addresses
if [ -n "${IPV4}" ]; then

	# Clean everything first
	cilium lb delete-service --all
	sudo cilium lb --no-daemon dump-service

	cilium lb delete-rev-nat --all
	sudo cilium lb --no-daemon delete-rev-nat --all

	# Check if everything was deleted
	if [ -n "$(cilium lb dump-service)" ]; then
		abort "Daemon's services map should be clean"
	fi
	if [ -n "$(sudo cilium lb --no-daemon dump-service)" ]; then
		abort "Services map should be clean"
	fi

	if [ -n "$(cilium lb dump-rev-nat)" ]; then
		abort "Daemon's rev nat map should be clean"
	fi
	if [ -n "$(sudo cilium lb --no-daemon dump-rev-nat)" ]; then
		abort "Rev nat's map should be clean"
	fi

	# Add a service with ID 0, it should fail
	sudo cilium lb --no-daemon update-service --frontend 127.0.0.1:80 --backend 127.0.0.2:90 --backend 127.0.0.3:90 --id 0 --rev 2> /dev/null && {
		abort "Unexpected success in creating a frontend with reverse nat ID 0"
	}

	if [ -n "$(sudo cilium lb --no-daemon dump-service)" ]; then
		abort "Services map should be clean"
	fi

	# Add a service with ID 1
	sudo cilium lb --no-daemon update-service --frontend 127.0.0.1:80 --backend 127.0.0.2:90 --backend 127.0.0.3:90 --id 1 --rev 2> /dev/null || {
		abort "Service should have been added"
	}

	# Daemon's map should be empty
	if [ -n "$(cilium lb dump-service)" ]; then
		abort "Daemon's services map should be clean"
	fi

	# Check if it's the only service present
	if [[ "$(sudo cilium lb --no-daemon dump-service)" != \
	      "$(echo -e "127.0.0.1:80 =>\n\t\t1 => 127.0.0.2:90 (1)\n\t\t2 => 127.0.0.3:90 (1)")" ]]; then
	     abort "Service was not properly added"
	fi

	# Check if we can get the service by it's ID
	if [[ "$(sudo cilium lb --no-daemon get-service 127.0.0.1:80)" != \
	      "$(echo -e "127.0.0.1:80 =>\n\t\t1 => 127.0.0.2:90 (1)\n\t\t2 => 127.0.0.3:90 (1)")" ]]; then
	     abort "Service was not properly added"
	fi

	# Check if it's the only RevNAT present
	if [[ "$(sudo cilium lb --no-daemon dump-rev-nat)" != \
	      "$(echo -e "IPv4:\n1 => 127.0.0.1:80")" ]]; then
	     abort "RevNAT's service was not properly added"
	fi

	# Check if we can get the RevNAT by it's ID
	if [[ "$(sudo cilium lb --no-daemon get-rev-nat 1)" != \
	      "$(echo -e "1 => 127.0.0.1:80")" ]]; then
	     abort "RevNAT's service was not properly added"
	fi

	# Add a service with ID 0 to the daemon, it should fail
	cilium lb update-service --frontend 127.0.0.1:80 --backend 127.0.0.2:90 --backend 127.0.0.3:90 --id 0 --rev 2> /dev/null && {
		abort "Unexpected success in creating a frontend with reverse nat ID 0"
	}

	# Daemon's map should be empty
	if [ -n "$(cilium lb dump-service)" ]; then
		abort "Daemon's services map should be clean"
	fi

	# BPF's map should be unmodified
	if [[ "$(sudo cilium lb --no-daemon dump-service)" != \
	      "$(echo -e "127.0.0.1:80 =>\n\t\t1 => 127.0.0.2:90 (1)\n\t\t2 => 127.0.0.3:90 (1)")" ]]; then
	     abort "Service was not properly added"
	fi

	# Add a service with ID 2
	cilium lb update-service --frontend 127.0.0.1:80 --backend 127.0.0.2:90 --backend 127.0.0.3:90 --id 2 --rev 2> /dev/null || {
		abort "Service should have been added"
	}

	# Check if it's the only service present
	if [[ "$(cilium lb dump-service)" != \
	      "$(echo -e "127.0.0.1:80 =>\n\t\t1 => 127.0.0.2:90 (2)\n\t\t2 => 127.0.0.3:90 (2)")" ]]; then
	     abort "Service was not properly added"
	fi

	# Check if we can get the service by it's ID
	if [[ "$(cilium lb get-service 127.0.0.1:80)" != \
	      "$(echo -e "127.0.0.1:80 =>\n\t\t1 => 127.0.0.2:90 (2)\n\t\t2 => 127.0.0.3:90 (2)")" ]]; then
	     abort "Service was not properly added"
	fi

	# BPF's map should contain service with a different RevNAT ID
	if [[ "$(sudo cilium lb --no-daemon dump-service)" != \
	      "$(echo -e "127.0.0.1:80 =>\n\t\t1 => 127.0.0.2:90 (2)\n\t\t2 => 127.0.0.3:90 (2)\n")" ]]; then
	     abort "Service was not properly added"
	fi

	# Check if it's the only RevNAT present
	if [[ "$(cilium lb dump-rev-nat)" != \
	      "$(echo -e "IPv4:\n2 => 127.0.0.1:80")" ]]; then
	     abort "RevNAT's service was not properly added"
	fi

	# Check if we can get the RevNAT by it's ID
	if [[ "$(cilium lb get-rev-nat 2)" != \
	      "$(echo -e "2 => 127.0.0.1:80")" ]]; then
	     abort "RevNAT's service was not properly added"
	fi

	# BPF's RevNAT map's should contain both RevNATs
	if [[ "$(sudo cilium lb --no-daemon dump-rev-nat)" != \
	      "$(echo -e "IPv4:\n1 => 127.0.0.1:80\n2 => 127.0.0.1:80")" ]]; then
	     abort "RevNAT's service was not properly added"
	fi

	# Let's try delete RevNAT 1
	if [[ "$(cilium lb delete-rev-nat 1)" != \
	      "$(echo -e "Successfully deleted")" ]]; then
	     abort "RevNAT's was not deleted"
	fi

	# BPF's RevNAT map's should contain both RevNATs
	if [[ "$(sudo cilium lb --no-daemon dump-rev-nat)" != \
	      "$(echo -e "IPv4:\n1 => 127.0.0.1:80\n2 => 127.0.0.1:80")" ]]; then
	     abort "RevNAT's service was wrongly deleted"
	fi

	# Let's try delete RevNAT 2
	if [[ "$(cilium lb delete-rev-nat 2)" != \
	      "$(echo -e "Successfully deleted")" ]]; then
	     abort "RevNAT's was not deleted"
	fi

	# Let's try delete RevNAT 2
	if [[ "$(cilium lb dump-rev-nat)" != \
	      "$(echo -e "")" ]]; then
	     abort "RevNAT's was not deleted"
	fi

	# BPF's RevNAT map's should contain RevNAT with ID 1
	if [[ "$(sudo cilium lb --no-daemon dump-rev-nat)" != \
	      "$(echo -e "IPv4:\n1 => 127.0.0.1:80")" ]]; then
	     abort "RevNAT's service was not properly deleted"
	fi

	# Let's try delete the only service
	if [[ "$(cilium lb delete-service 127.0.0.1:80)" != \
	      "$(echo -e "Successfully deleted")" ]]; then
	     abort "RevNAT's was not deleted"
	fi

	# Let's delete the remaining RevNAT with ID 1
	if [[ "$(sudo cilium lb --no-daemon delete-rev-nat 1)" != \
	      "$(echo -e "Successfully deleted")" ]]; then
	     abort "RevNAT's service was not properly deleted"
	fi

	# Check if everything was deleted
	if [ -n "$(cilium lb dump-service)" ]; then
		abort "Daemon's services map should be clean"
	fi

	#FIXME The services maps are not being properly cleaned
	#if [ -n "$(sudo cilium lb --no-daemon dump-service)" ]; then
	#	abort "Services map should be clean"
	#fi

	if [ -n "$(cilium lb dump-rev-nat)" ]; then
		abort "Daemon's rev nat map should be clean"
	fi
	if [ -n "$(sudo cilium lb --no-daemon dump-rev-nat)" ]; then
		abort "Rev nat's map should be clean"
	fi

	# Test SyncLBMap

	# Clean everything first
	cilium lb delete-service --all
	sudo cilium lb --no-daemon dump-service
	cilium lb delete-rev-nat --all
	sudo cilium lb --no-daemon delete-rev-nat --all

	# Add a service with ID 2
	cilium lb update-service --frontend 127.0.0.1:80 --backend 127.0.0.2:90 --backend 127.0.0.3:90 --id 2 --rev 2> /dev/null || {
		abort "Service should have been added"
	}

	# Add the same service with ID 1
	sudo cilium lb --no-daemon update-service --frontend 127.0.0.1:80 --backend 127.0.0.2:90 --backend 127.0.0.3:90 --id 1 --rev 2> /dev/null || {
		abort "Service should have been added"
	}

	# Add other service with ID 3
	sudo cilium lb --no-daemon update-service --frontend 127.0.1.1:80 --backend 127.0.0.2:90 --backend 127.0.0.3:90 --id 3 --rev 2> /dev/null || {
		abort "Service should have been added"
	}

	# BPF's map should contain service with RevNAT ID 1
	if [[ "$(sudo cilium lb --no-daemon dump-service)" != \
	      "$(echo -e "127.0.0.1:80 =>\n\t\t1 => 127.0.0.2:90 (1)\n\t\t2 => 127.0.0.3:90 (1)\n127.0.1.1:80 =>\n\t\t1 => 127.0.0.2:90 (3)\n\t\t2 => 127.0.0.3:90 (3)\n")" ]]; then
	     abort "Service was not properly added"
	fi

	# Daemon's map should contain service with RevNAT ID 2
	if [[ "$(cilium lb dump-service)" != \
	      "$(echo -e "127.0.0.1:80 =>\n\t\t1 => 127.0.0.2:90 (2)\n\t\t2 => 127.0.0.3:90 (2)\n")" ]]; then
	     abort "Service was not properly added"
	fi

	# BPF's RevNAT map's should contain all RevNATs
	if [[ "$(sudo cilium lb --no-daemon dump-rev-nat)" != \
	      "$(echo -e "IPv4:\n1 => 127.0.0.1:80\n2 => 127.0.0.1:80\n3 => 127.0.1.1:80")" ]]; then
	     abort "RevNAT's service was not properly added"
	fi

	# Daemon's RevNAT map's should contain only 1 RevNATs
	if [[ "$(cilium lb dump-rev-nat)" != \
	      "$(echo -e "IPv4:\n2 => 127.0.0.1:80")" ]]; then
	     abort "RevNAT's service was not properly added"
	fi

	# Sync LB Maps
	cilium lb sync-lb-maps 2> /dev/null || {
		abort "Unable to sync LB Maps"
	}

	# Daemon's map should contain service with RevNAT ID 4 because ID 3 was taken for IPv6 and not properly cleaned in kvstore #FIXME
	if [[ "$(cilium lb dump-service)" != \
	      "$(echo -e "127.0.0.1:80 =>\n\t\t1 => 127.0.0.2:90 (1)\n\t\t2 => 127.0.0.3:90 (1)\n127.0.1.1:80 =>\n\t\t1 => 127.0.0.2:90 (4)\n\t\t2 => 127.0.0.3:90 (4)\n")" ]]; then
	     abort "Service was not properly synced"
	fi

	# BPF's map should contain service with RevNAT ID 4
	if [[ "$(sudo cilium lb --no-daemon dump-service)" != \
	      "$(echo -e "127.0.0.1:80 =>\n\t\t1 => 127.0.0.2:90 (1)\n\t\t2 => 127.0.0.3:90 (1)\n127.0.1.1:80 =>\n\t\t1 => 127.0.0.2:90 (4)\n\t\t2 => 127.0.0.3:90 (4)\n")" ]]; then
	     abort "Service was not properly synced"
	fi

	# BPF's RevNAT map's should contain RevNATs 1, 2 and 4. Number 3 was removed since the
	# new service ID is 4. Number 2 was not removed because the new assigned ID to service
	# 127.0.0.1:80 was the same ID of the bpf map.
	if [[ "$(sudo cilium lb --no-daemon dump-rev-nat)" != \
	      "$(echo -e "IPv4:\n1 => 127.0.0.1:80\n2 => 127.0.0.1:80\n4 => 127.0.1.1:80")" ]]; then
	     abort "RevNAT's service was not properly synced"
	fi

	# Daemon's RevNAT map's should contain RevNATs 1 and 4. Number 3 was removed since the
	# new service ID is 4.Number 2 was not removed because the new assigned ID to service
	# 127.0.0.1:80 was the same ID of the bpf map.
	if [[ "$(cilium lb dump-rev-nat)" != \
	      "$(echo -e "IPv4:\n1 => 127.0.0.1:80\n2 => 127.0.0.1:80\n4 => 127.0.1.1:80")" ]]; then
	     abort "RevNAT's service was not properly synced"
	fi
fi

sudo ip link add lbtest1 type veth peer name lbtest2
sudo ip link set lbtest1 up

# Route f00d::1:1 IPv6 packets to a fantasy router ("fbfb::10:10") behind lbtest1
sudo ip -6 route add fbfb::10:10/128 dev lbtest1
MAC=$(ip link show lbtest1 | grep ether | awk '{print $2}')
sudo ip neigh add fbfb::10:10 lladdr $MAC dev lbtest1
sudo ip -6 route add f00d::1:1/128 via fbfb::10:10

# Route 2.2.2.2 IPv4 packets to a fantasy router ("3.3.3.3") behind lbtest1
SRC=$(ip addr show dev cilium_host | grep 'inet ' | awk '{print $2}' | sed 's/\/32//')
sudo ip route add 3.3.3.3/32 dev lbtest1
MAC=$(ip link show lbtest1 | grep ether | awk '{print $2}')
sudo ip neigh add 3.3.3.3 lladdr $MAC dev lbtest1
sudo ip route add 2.2.2.2/32 via 3.3.3.3 src $SRC

sudo ip link set lbtest2 up
LIB=/usr/lib/cilium
RUN=/var/run/cilium
NH_IFINDEX=$(cat /sys/class/net/cilium_host/ifindex)
NH_MAC=$(ip link show cilium_host | grep ether | awk '{print $2}')
NH_MAC="{.addr=$(mac2array $NH_MAC)}"
CLANG_OPTS="-D__NR_CPUS__=$(nproc) -DLB_L3 -DLB_REDIRECT=$NH_IFINDEX -DLB_DSTMAC=$NH_MAC -O2 -target bpf -I. -I$LIB/include -I$RUN/globals -DDEBUG"
touch netdev_config.h
clang $CLANG_OPTS -c $LIB/bpf_lb.c -o tmp_lb.o

sudo tc qdisc del dev lbtest2 clsact 2> /dev/null || true
sudo tc qdisc add dev lbtest2 clsact
sudo tc filter add dev lbtest2 ingress bpf da obj tmp_lb.o sec from-netdev

docker network inspect $TEST_NET 2> /dev/null || {
	docker network create --ipv6 --subnet ::1/112 --ipam-driver cilium --driver cilium $TEST_NET
}

monitor_start

docker run -dt --net=$TEST_NET --name server1 -l io.cilium.server -l server1 httpd
docker run -dt --net=$TEST_NET --name server2 -l io.cilium.server -l server2 httpd
docker run -dt --net=$TEST_NET --name client -l io.cilium.client noironetworks/nettools

# FIXME IPv6 DAD period
sleep 5

CLIENT_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' client)
CLIENT_ID=$(cilium endpoint list | grep $CLIENT_IP | awk '{ print $1}')

SERVER1_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server1)
SERVER1_ID=$(cilium endpoint list | grep $SERVER1_IP | awk '{ print $1}')
SERVER1_IP4=$(cilium endpoint list | grep $SERVER1_IP | awk '{ print $5}')
SERVER2_IP=$(docker inspect --format '{{ .NetworkSettings.Networks.cilium.GlobalIPv6Address }}' server2)
SERVER2_ID=$(cilium endpoint list | grep $SERVER2_IP | awk '{ print $1}')
SERVER2_IP4=$(cilium endpoint list | grep $SERVER2_IP | awk '{ print $5}')

#IFACE=$(ip link | grep lxc | sed -e 's/.* \(lxc[^@]*\).*/\1/')
#for name in $IFACE; do
#	ethtool -k $name tso off gso off gro off
#done

cat <<EOF | cilium -D policy import -
{
        "name": "io.cilium",
        "children": {
		"client": { },
		"server": {
			"rules": [{
				"allow": ["reserved:host", "../client"]
			}]
		}

	}
}
EOF

# Clear eventual old entries, this may fail if the maps have not been created
cilium lb delete-service --all || true
cilium lb delete-rev-nat --all || true

# Create IPv4 L3 service without reverse entry
cilium lb update-service --frontend 4.4.4.4:0 --id 1 --backend 5.5.5.5:0 || {
	abort "Unable to add IPv4 service entry"
}

cilium lb dump-service

# Check if reverse NAT entry was created anyway, should fail
cilium lb get-rev-nat 1 2> /dev/null && {
	abort "Unexpected reverse NAT entry"
}

# Delete IPv4 L3 entry
cilium lb delete-service 4.4.4.4:0 || {
	abort "Unable to delete IPv4 service entry"
}

# Mixing L3/L4 in frontend and backend is not allowed
cilium lb update-service --frontend 4.4.4.4:0 --id 1 --backend 5.5.5.5:80 2> /dev/null && {
	abort "Unexpected success in creating mixed L3/L4 service"
}

# Add L4 IPv4 entry
cilium lb update-service --frontend 4.4.4.4:40 --rev --id 1 --backend 5.5.5.5:80 || {
	abort "Unable to add IPv4 service entry"
}

cilium lb dump-service

# Check if requested reverse NAT entry exists
cilium lb get-rev-nat 1 || {
	abort "Unable to find reverse NAT entry that should have been created"
}

# Try an L3 lookup for the created L4 entry, should fail
cilium lb delete-service 4.4.4.4:0 || {
	abort "Unexpected success in looking up with L3 key of L4 entry"
}

# Delete L4 entry
cilium lb delete-service 4.4.4.4:40 || {
	abort "Unable to delete IPv4 service entry"
}

SVC_IP6="f00d::1:1"
cilium lb update-service --rev --frontend "[$SVC_IP6]:0" --id 222 \
                        --backend "[$SERVER1_IP]:0" \
                        --backend "[$SERVER2_IP]:0"

SVC_IP4="2.2.2.2"
cilium lb update-service --rev --frontend "$SVC_IP4:0"  --id 223 \
			--backend "$SERVER1_IP4:0" \
			--backend "$SERVER2_IP4:0"

LB_HOST_IP6="f00d::1:2"
cilium lb update-service --rev --frontend "[$LB_HOST_IP6]:0" --id 224 \
			--backend "[$(host_ip6)]:0"

LB_HOST_IP4="3.3.3.3"
cilium lb update-service --rev --frontend "$LB_HOST_IP4:0" --id 225 \
			--backend "$(host_ip4):0"

## Test 1: local host => bpf_lb => local container
monitor_clear
ping6 $SVC_IP6 -c 4 || {
	abort "Error: Unable to ping"
}

monitor_clear
ping $SVC_IP4 -c 4 || {
	abort "Error: Unable to ping"
}

## Test 2: local container => bpf_lxc (LB) => local container
monitor_clear
docker exec -i client ping6 -c 4 $SVC_IP6 || {
	abort "Error: Unable to reach netperf TCP IPv6 endpoint"
}

monitor_clear
docker exec -i client ping -c 4 $SVC_IP4 || {
	abort "Error: Unable to reach netperf TCP IPv6 endpoint"
}

cilium endpoint config $CLIENT_ID Policy=false

## Test 3: local container => bpf_lxc (LB) => local host
monitor_clear
docker exec -i client ping6 -c 4 $LB_HOST_IP6 || {
	abort "Error: Unable to reach local IPv6 node via loadbalancer"
}

monitor_clear
docker exec -i client ping -c 4 $LB_HOST_IP4 || {
	abort "Error: Unable to reach local IPv4 node via loadbalancer"
}

monitor_stop

## Test 4: Run wrk & ab from container => bpf_lxc (LB) => local container

cilium lb update-service --rev --frontend "[$SVC_IP6]:80" --id 222 \
                        --backend "[$SERVER1_IP]:80" \
                        --backend "[$SERVER2_IP]:80"
cilium lb update-service --rev --frontend "$SVC_IP4:80" --id 223 \
			--backend "$SERVER1_IP4:80" \
			--backend "$SERVER2_IP4:80"


cilium daemon config Debug=false DropNotification=false
cilium endpoint config $SERVER1_ID Debug=false DropNotification=false
cilium endpoint config $SERVER2_ID Debug=false DropNotification=false

docker run --rm -t --net=$TEST_NET --name wrk -l io.cilium.client skandyla/wrk -t20 -c1000 -d60 "http://[$SVC_IP6]:80/"
docker run --rm -t --net=$TEST_NET --name wrk -l io.cilium.client skandyla/wrk -t20 -c1000 -d60 "http://$SVC_IP4:80/"

docker run --rm -t --net=$TEST_NET --name ab -l io.cilium.client jordi/ab ab -t 30 -c 20 -v 1 "http://[$SVC_IP6]/"
docker run --rm -t --net=$TEST_NET --name ab -l io.cilium.client jordi/ab ab -t 30 -c 20 -v 1 "http://$SVC_IP4/"

cilium daemon config Debug=true DropNotification=true

cleanup
cilium -D policy delete io.cilium
