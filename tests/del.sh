#!/bin/bash

ioserv=../example/dnet_ioserv
log_mask=15
server_num=1

server_opt="-D"
daemon_start_string="$ioserv"
tmpdir="/tmp/elliptics-tmp"

base_serv=localhost:1025:2
test_file_id=ff

cnt=3
size=4096
total_size=`expr $cnt \* $size`

. functions

trap kill_servers EXIT

tmpdir=`prepare_root`
log=$tmpdir/log
test_file=$tmpdir/test_file

function write_and_remove_file()
{
	local base_serv=$1
	local test_file=$2
	local test_file_id=$3
	local total_size=$4
	local del=$5

	local offset=0
	write_data 0 $total_size $offset $base_serv $test_file $test_file_id
	remove_file 0 0 0 $base_serv $test_file $test_file_id
}

echo -en "Checking deletion ($tmpdir): "

dd if=/dev/urandom of=$test_file bs=$size count=$cnt > /dev/null 2>&1

start_server $base_serv 0 "$server_opt"

write_and_remove_file $base_serv $test_file $test_file_id $total_size
$ioserv -a localhost:0:2 -r $base_serv -l $tmpdir/log-client-read -m $log_mask -T sha1 -R $test_file -I $test_file_id > /dev/null 2>&1
status=$?

if test `expr 256 \- $status` = 2; then
	echo "done"
else
	echo "failed (read error: $status, must be 2 or 254)"
	die "Remove operation failed" -1
fi

kill_servers

trap - EXIT

rm -rf $tmpdir
