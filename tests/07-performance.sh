#!/usr/bin/env bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

source "./helpers.bash"

set -e

current_branch="$(git rev-parse --abbrev-ref HEAD)"
TEST_NET="cilium"

function cleanup {
	cd "${dir}/.."
	git checkout "${current_branch}"
    make clean
    make
    sudo make install
    sudo service cilium-docker restart
}

trap cleanup EXIT

function install_master {
    cd "${dir}/.."
    git checkout origin/master
    make clean
    make
    sudo make install
}

function run_benchmark_1 {
    for i in `seq 1 10`; do
        docker run -dt --net=$TEST_NET --name "container-${i}" \
            -l "id.container-${i}" busybox:1.26 sleep 30000s
        cat <<EOF | cilium -D policy import -
{
	"name": "root",
	"rules": [{
		"coverage": ["id.container-${i}"],
		"allow": ["reserved:host", "id.container-${i}"]
	}]
}
EOF
    done
}

function clean_benchmark_1 {
    for i in `seq 1 10`; do
        docker rm -f "container-${i}"
    done
}

function run_benchmark {
{ time -p run_benchmark_${1} >"${dir}/benchmark_${1}_${2}.stdout" \
    2>"${dir}/benchmark_${1}_${2}.stderr"; } 2> "${dir}/benchmark_${1}_${2}.time"
}

function print_results {
    echo "Time gained against master (higher is better):"
    paste "${dir}/benchmark_${1}_new.time" \
        "${dir}/benchmark_${1}_master.time" | awk '{print $1" "($4-$2)/$4*100"%"}'
}

docker network inspect $TEST_NET &> /dev/null || {
    docker network create --ipv6 --subnet ::1/112 --ipam-driver cilium --driver cilium $TEST_NET
}

run_benchmark 1 new
until [ "$(cilium endpoint list | grep ready -c)" -eq "10" ]; do
    echo "Waiting for all endpoints to be ready"
    sleep 1s
done
clean_benchmark_1
install_master
docker rm -f `docker ps -aq` || true
sudo service cilium-consul restart
sudo service cilium-docker restart
until cilium status &>/dev/null ; do echo "Waiting for cilium to start"; sleep 1s; done
run_benchmark 1 master
until [ "$(cilium endpoint list | grep ready -c)" -eq "10" ]; do
    echo "Waiting for all endpoints to be ready"
    sleep 1s
done
clean_benchmark_1

print_results 1