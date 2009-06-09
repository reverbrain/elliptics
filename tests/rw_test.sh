#!/bin/bash 

#options
TEMP_DIR=temp
GENERATING_TIME=5 #working time for cat /dev/urandom > some_test_file
LOGMASK=0xff
SERVER_ID_1=00
SERVER_ID_2=ff
FILE_ID_1=99
SERVER_FLAGS=$1
SERVER=../example/dnet_ioserv
CLIENT=../example/dnet_ioserv

echo "Read/write test"

#creating test directories
mkdir -p $TEMP_DIR

RUN_STACK="$TEMP_DIR/run_stack"

#cleaning resources on a fail or on the end
function clean_up() {
	if [ "$SERVER1_PID" ]; then
		kill $SERVER1_PID
		SERVER1_PID=
	fi
	if [ "$SERVER2_PID" ]; then
		kill $SERVER2_PID
		SERVER1_PID=
	fi
	rm -rf $TEMP_DIR/server1
	rm -rf $TEMP_DIR/server2
}

function repear_dirs() {
	if [ ! -e "$TEMP_DIR/server1" ]; then
		mkdir -p $TEMP_DIR/server1
	fi
	if [ ! -e "$TEMP_DIR/server2" ]; then
		mkdir -p $TEMP_DIR/server2
	fi
}

function do_cmd() {
	echo $@ >> $RUN_STACK
	$@ >> $RUN_STACK
	TMP=$?
	if [ "f$TMP" != "f0" ]; then
		echo "ERROR $TMP"
		echo -e "RUN STACK: \n\n"
		cat $RUN_STACK
		echo -e "\n\n"
		clean_up
		exit 1	
	fi
}

#compare test data and reading results
function cmp_files() {
	#compare test data and reading results
	cmp $1 $2
	if [ "f$?" != "f0" ]; then 
		echo -e "ERROR\nfiles differ!"	
		clean_up
		exit 1
	fi
}

function start_server() {
	repear_dirs

	local CMD=$(eval 'echo $'$2)
	echo $CMD >> $RUN_STACK
	$CMD &
	sleep 5
	if [ "f$(ps -p $! --no-headers -o comm)" = "f" ]; then
		echo "ERROR"
		echo -e "Command line: \n\n$CMD" 
		clean_up
		exit 1
	fi
	eval "$1=\"$!\""
}

#generating random file 
echo "Generating test file..."
cat /dev/urandom > $TEMP_DIR/tmp_1 &
sleep $GENERATING_TIME
kill $!

SERVER1_CMD="$SERVER -i $SERVER_ID_1 -a 127.0.0.1:1025:2 -d $TEMP_DIR/server1 -j -l $TEMP_DIR/server1_log -m $LOGMASK $SERVER_FLAGS"
SERVER2_CMD="$SERVER -i $SERVER_ID_2 -a 127.0.0.1:1030:2 -r 127.0.0.1:1025:2 -d $TEMP_DIR/server2 -j \
		-l $TEMP_DIR/server2_log -m $LOGMASK $SERVER_FLAGS"

# ***************************************
# * 1 server - 1 client                 *
# ***************************************
echo "===== 1 server - 1 client ====="
echo -n > $RUN_STACK

#start first server
echo -n > $TEMP_DIR/server1_log
start_server SERVER1_PID SERVER1_CMD

#write test data
echo -n > $TEMP_DIR/client_log
CMD="$CLIENT -i 22222222 -a 127.0.0.1:1111:2 -r 127.0.0.1:1025:2 -T jhash -W $TEMP_DIR/tmp_1 -I $FILE_ID_1 \
	       	-l $TEMP_DIR/client_log -m $LOGMASK"
do_cmd $CMD

#read test data
CMD="$CLIENT -i 22222222 -a 127.0.0.1:1111:2 -r 127.0.0.1:1025:2 -T jhash -R $TEMP_DIR/res_1 -I $FILE_ID_1 \
	       	-l $TEMP_DIR/client_log -m $LOGMASK"
do_cmd $CMD 

#compare test data and reading results
cmp_files $TEMP_DIR/tmp_1 $TEMP_DIR/res_1

#clean 
clean_up 
rm $TEMP_DIR/res_1*

# ***************************************
# * 1 server - 1 client                 *
# *  send file in 2 transactions        *
# ***************************************
echo "===== 1 server - 1 client ====="
echo "=====   send file in 2 transactions"
echo -n > $RUN_STACK

#start first server
echo -n > $TEMP_DIR/server1_log
start_server SERVER1_PID SERVER1_CMD

#calculating size of each transaction
TOTAL_SIZE=$(stat --printf="%s" $TEMP_DIR/tmp_1)
FIRST_TRANS_SIZE=$(($TOTAL_SIZE/2))
SECOND_TRANS_SIZE=$(($FIRST_TRANS_SIZE+($TOTAL_SIZE%2)))
echo "TOTAL_SIZE=$TOTAL_SIZE FIRST_TRANS_SIZE=$FIRST_TRANS_SIZE SECOND_TRANS_SIZE=$SECOND_TRANS_SIZE" >> $RUN_STACK

#write first part of test data
echo -n > $TEMP_DIR/client_log
CMD="$CLIENT -i 22222222 -a 127.0.0.1:1111:2 -r 127.0.0.1:1025:2 -T jhash \
		-W $TEMP_DIR/tmp_1 -I $FILE_ID_1 -l $TEMP_DIR/client_log -m $LOGMASK -O 0 -S $FIRST_TRANS_SIZE"
do_cmd $CMD

#write second part of test data
CMD="$CLIENT -i 22222222 -a 127.0.0.1:1111:2 -r 127.0.0.1:1025:2 -T jhash \
		-W $TEMP_DIR/tmp_1 -I $FILE_ID_1 -l $TEMP_DIR/client_log -m $LOGMASK -O $FIRST_TRANS_SIZE -S $SECOND_TRANS_SIZE"
do_cmd $CMD

#read test data
CMD="$CLIENT -i 22222222 -a 127.0.0.1:1111:2 -r 127.0.0.1:1025:2 -T jhash \
		-R $TEMP_DIR/res_1 -I $FILE_ID_1 -l $TEMP_DIR/client_log -m $LOGMASK"
do_cmd $CMD

#compare test data and reading results
cmp_files $TEMP_DIR/tmp_1 $TEMP_DIR/res_1

#clean
clean_up
rm $TEMP_DIR/res_1*

# ***************************************
# * 2 server - 1 client                 *
# *  send request to old first  server  *
# ***************************************
echo "===== 2 server - 1 client ====="
echo "=====  send request to old first  server"
echo -n > $RUN_STACK

#start first server
echo -n > $TEMP_DIR/server1_log
start_server SERVER1_PID SERVER1_CMD

#start second server
echo -n > $TEMP_DIR/server2_log
start_server SERVER2_PID SERVER2_CMD

#write test data
echo -n > $TEMP_DIR/client_log
CMD="$CLIENT -i 22222222 -a 127.0.0.1:1111:2 -r 127.0.0.1:1025:2 -T jhash -W $TEMP_DIR/tmp_1 -I $FILE_ID_1 \
	       	-l $TEMP_DIR/client_log -m $LOGMASK"
do_cmd $CMD

#read test data
echo -n > $TEMP_DIR/client_log
CMD="$CLIENT -i 22222222 -a 127.0.0.1:1111:2 -r 127.0.0.1:1025:2 -T jhash \
		-R $TEMP_DIR/res_1 -I $FILE_ID_1 -l $TEMP_DIR/client_log -m $LOGMASK"
do_cmd $CMD

#compare test data and reading results
cmp_files $TEMP_DIR/tmp_1 $TEMP_DIR/res_1
clean_up
rm $TEMP_DIR/res_1*


# ***************************************
# * 2 server - 1 client                 *
# *  send request to new second server  *
# ***************************************
echo "===== 2 server - 1 client ====="
echo "=====  send request to new second server"
echo -n > $RUN_STACK

#start first server
echo -n > $TEMP_DIR/server1_log
start_server SERVER1_PID SERVER1_CMD

#start second server
echo -n > $TEMP_DIR/server2_log
start_server SERVER2_PID SERVER2_CMD

#write test data
echo -n > $TEMP_DIR/client_log
CMD="$CLIENT -i 22222222 -a 127.0.0.1:1111:2 -r 127.0.0.1:1025:2 -T jhash -W $TEMP_DIR/tmp_1 -I $FILE_ID_1 \
	       	-l $TEMP_DIR/client_log -m $LOGMASK"
do_cmd $CMD

#read test data
echo -n > $TEMP_DIR/client_log
CMD="$CLIENT -i 22222222 -a 127.0.0.1:1111:2 -r 127.0.0.1:1030:2 -T jhash \
	       -R $TEMP_DIR/res_1 -I $FILE_ID_1 -l $TEMP_DIR/client_log -m $LOGMASK"
do_cmd $CMD

#compare test data and reading results
cmp_files $TEMP_DIR/tmp_1 $TEMP_DIR/res_1
clean_up
rm $TEMP_DIR/res_1*


# ***************************************
# * 1 server - 1 client                 *
# *  kill first server and              *
# *  send request to second server      *
# *  (join test)                        *
# ***************************************
echo "===== 2 server - 1 client ====="
echo "=====  kill first server and"
echo "=====  send request to second server"
echo "=====  (join test)"
echo -n > $RUN_STACK

#start first server
echo -n > $TEMP_DIR/server1_log
start_server SERVER1_PID SERVER1_CMD

#write test data
echo -n > $TEMP_DIR/client_log
CMD="$CLIENT -i 22222222 -a 127.0.0.1:1111:2 -r 127.0.0.1:1025:2 -T jhash -W $TEMP_DIR/tmp_1 -I $FILE_ID_1 \
	       	-l $TEMP_DIR/client_log -m $LOGMASK"
do_cmd $CMD

#start second server
echo -n > $TEMP_DIR/server2_log
start_server SERVER2_PID SERVER2_CMD

kill $SERVER1_PID
SERVER1_PID=

#read test data
CMD="$CLIENT -i 22222222 -a 127.0.0.1:1111:2 -r 127.0.0.1:1030:2 -T jhash \
		-R $TEMP_DIR/res_1 -I $FILE_ID_1 -l $TEMP_DIR/client_log -m $LOGMASK"
do_cmd $CMD

#compare test data and reading results
cmp_files $TEMP_DIR/tmp_1 $TEMP_DIR/res_1

#clean
clean_up
rm $TEMP_DIR/res_1*


#cleanup 
rm -rf $TEMP_DIR

echo -e "\n\nSUCCESSFUL!"
exit 0
