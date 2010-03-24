#!/bin/bash

. options
. functions

server_num=2
server_id_1=00
server1_addr=127.0.0.1:1025:2
server_id_2=ff
server2_addr=127.0.0.1:1030:2
file_id_1=99

tmpdir=`prepare_root`

log_file=$tmpdir/log
tmp_file=$tmpdir/tmp_1
res_file=$tmpdir/res_1

trap kill_servers EXIT

echo "rw_test ($tmpdir):"

generate_random_file $tmp_file

# ***************************************
# * 1 server - 1 client                 *
# ***************************************
echo "1 server - 1 client"

#start first server
start_server $server1_addr 0 "$server_opt -i $server_id_1"
serever1_pid=last_pid

write_data 0 0 0 $server1_addr $tmp_file $file_id_1
read_data 1 9999999999999 0 $server1_addr $res_file $file_id_1
cmp_files $tmp_file $res_file

#clean  
kill_servers
rm $res_file*

print_passed

# ***************************************
# * 1 server - 1 client                 *
# *  send file in 2 transactions        *
# ***************************************
echo "1 server - 1 client"
echo " send file in 2 transactions"

total_size=$(stat --printf="%s" $tmpdir/tmp_1)
first_trans_size=$(($total_size/2))
second_trans_size=$(($first_trans_size+($total_size%2)))

#start first server
start_server $server1_addr 0 "$server_opt -i $server_id_1"
serever1_pid=last_pid

write_data 0 $first_trans_size 0 $server1_addr $tmp_file $file_id_1
write_data 0 $second_trans_size $first_trans_size $server1_addr $tmp_file $file_id_1
read_data 1 9999999999999 0 $server1_addr $res_file $file_id_1
cmp_files $tmp_file $res_file

#clean  
kill_servers
rm $res_file*

print_passed

# ***************************************
# * 2 server - 1 client                 *
# *  send request to old first  server  *
# ***************************************
echo "2 server - 1 client"
echo " send request to old first  server"

#start first server
start_server $server1_addr 0 "$server_opt -i $server_id_1"
serever1_pid=last_pid

#start second server
start_server $server2_addr 0 "$server_opt -i $server_id_2 -r $server1_addr"
serever2_pid=last_pid

write_data 0 0 0 $server1_addr $tmp_file $file_id_1
read_data 1 9999999999999999999 0 $server1_addr $res_file $file_id_1
cmp_files $tmp_file $res_file

#clean  
kill_servers
rm $res_file*

print_passed

# ***************************************
# * 2 server - 1 client                 *
# *  send request to new second server  *
# ***************************************
echo "2 server - 1 client"
echo " send request to new second server"

#start first server
start_server $server1_addr 0 "$server_opt -i $server_id_1"
serever1_pid=last_pid

#start second server
start_server $server2_addr 0 "$server_opt -i $server_id_2 -r $server1_addr"
serever2_pid=last_pid

write_data 0 0 0 $server1_addr $tmp_file $file_id_1
read_data 1 999999999999999999 0 $server2_addr $res_file $file_id_1
cmp_files $tmp_file $res_file

#clean  
kill_servers
rm $res_file*

print_passed

# ***************************************
# * 1 server - 1 client                 *
# *  kill first server and              *
# *  send request to second server      *
# *  (simple join test)                 *
# ***************************************
echo "2 server - 1 client ====="
echo " kill first server and"
echo " send request to second server"
echo " (simple join test)"

#start first server
start_server $server1_addr 0 "$server_opt -i $server_id_1"
serever1_pid=last_pid

write_data 0 0 0 $server1_addr $tmp_file $file_id_1

#start second server
start_server $server2_addr 0 "$server_opt -i $server_id_2 -r $server1_addr"
serever2_pid=last_pid

read_data 1 99999999999999999 0 $server2_addr $res_file $file_id_1
cmp_files $tmp_file $res_file

#clean  
kill_servers
rm $res_file*

print_passed

rm -rf $tmpdir
