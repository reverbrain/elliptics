#!/bin/bash

. options

server_num=2
base_serv=localhost:1025:2
joining_serv=localhost:1030:2
test_file_id=ff

cnt=3
size=4096

. functions

tmpdir=`prepare_root`
log_file=$tmpdir/log

trap kill_servers EXIT

echo -en "Checking merge strategy ($tmpdir): "
for ((merge=0; merge<4; ++merge)); do
	prepare_servers $test_file_id $base_serv $joining_serv $cnt $size

	start_server $joining_serv 1 "$server_opt -r $base_serv -i ff -M $merge"

	cmpstr=""
	for ((i=0; i<$server_num; ++i)); do
		cmpstr="$cmpstr $tmpdir/root$i/$test_file_id/$test_file_id*.history"
	done

	cmp $cmpstr
	if test $? != 0; then
		die "Merge strategy $merge failed: histoies differ"
	fi

	echo -en "$merge "
	kill_servers
done

print_passed
#read_and_check_data 0 $total_size 0 "$base_serv" $test_file_id

kill_servers

trap - EXIT

rm -rf $tmpdir
