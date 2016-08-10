DUMP_FILE=$(mktemp)
MONITOR_PID=""

function monitor_start {
	sudo cilium monitor > $DUMP_FILE &
	MONITOR_PID=$!
}

function monitor_clear {
	set +x
	sleep 1s
	cp /dev/null $DUMP_FILE
	set -x
}

function monitor_dump {
	cat $DUMP_FILE
}

function monitor_stop {
	if [ ! -z "$MONITOR_PID" ]; then
		sudo kill $MONITOR_PID
	fi
}

function abort {
	set +x

	echo "------------------------------------------------------------------------"
	echo "                            Test Failed"
	echo "$*"
	echo ""
	echo "------------------------------------------------------------------------"

	monitor_dump
	monitor_stop

	exit 1
}
