#!/bin/bash 

#options
TEMP_DIR=temp
GENERATING_TIME=5 #working time for cat /dev/urandom > some_test_file
LOGMASK=0xff
SERVER_ID_1=00
SERVER_ID_2=ff
FILE_ID_1=99
SERVER_FLAGS=$1

echo "Read/write test"

#creating test directories
mkdir -p $TEMP_DIR
mkdir -p $TEMP_DIR/server1
mkdir -p $TEMP_DIR/server2

RUN_STACK="$TEMP_DIR/run_stack"
echo -n > $RUN_STACK

#cleaning resources on a fail or on the end
function clean_up() {
	if [ "$SERVER1_PID" ]; then
		kill $SERVER1_PID
	fi
	if [ "$SERVER2_PID" ]; then
		kill $SERVER2_PID
	fi
}

#generating random file 
echo "Generating test file..."
cat /dev/urandom > $TEMP_DIR/tmp_1 &
sleep $GENERATING_TIME
kill $!

# ***************************************
# * 1 server - 1 client                 *
# ***************************************
echo "===== 1 server - 1 client ====="

#start first server
echo "starting first server..."
echo -n > $TEMP_DIR/server1_log
CMD="../example/example -i $SERVER_ID_1 -a 127.0.0.1:1025:2 -d $TEMP_DIR/server1 -j -l $TEMP_DIR/server1_log -m $LOGMASK $SERVER_FLAGS"
echo "$CMD" >> $RUN_STACK
$CMD &
sleep 5
if [ "f$(ps -p $! --no-headers -o comm)" = "f" ]; then
	echo "ERROR"
	echo -e "LOG: \n\n"
	clean_up
	exit 1
fi
SERVER1_PID=$!

#write test data
echo "writing data..."
echo -n > $TEMP_DIR/client_log
CMD="../example/example -i 22222222 -a 127.0.0.1:1111:2 -r 127.0.0.1:1025:2 -T jhash -W $TEMP_DIR/tmp_1 -I $FILE_ID_1 \
	       	-l $TEMP_DIR/client_log -m $LOGMASK"
echo "$CMD" >> $RUN_STACK
$CMD >> $RUN_STACK
TMP=$?
if [ "f$TMP" != "f0" ]; then
	echo "ERROR $TMP"
	echo -e "LOG: \n\n"
	clean_up
	exit 1	
fi

#read test data
echo "reading data..."
CMD="../example/example -i 22222222 -a 127.0.0.1:1111:2 -r 127.0.0.1:1025:2 -T jhash -R $TEMP_DIR/res_1 -I $FILE_ID_1 \
	       	-l $TEMP_DIR/client_log -m $LOGMASK"
echo "$CMD" >> $RUN_STACK
$CMD >> $RUN_STACK
TMP=$?
if [ "f$TMP" != "f0" ]; then
	echo "ERROR $TMP"
	echo -e "LOG: \n\n"
	clean_up
	exit 1	
fi

#compare test data and reading results
cmp $TEMP_DIR/tmp_1 $TEMP_DIR/res_1
if [ "f$?" != "f0" ]; then 
	echo -e "ERROR\nfiles differ!"	
	clean_up
	exit 1
else 
	echo "files are equal" 
fi
rm $TEMP_DIR/res_1*

# ***************************************
# * 1 server - 1 client                 *
# *  send file in 2 transactions        *
# ***************************************
echo "===== 2 server - 1 client ====="
echo "=====  send request to old first  server"

#calculating size of each transaction
TOTAL_SIZE=$(stat --printf="%s" $TEMP_DIR/tmp_1)
FIRST_TRANS_SIZE=$(($TOTAL_SIZE/2))
SECOND_TRANS_SIZE=$(($FIRST_TRANS_SIZE+($TOTAL_SIZE%2)))
echo "TOTAL_SIZE=$TOTAL_SIZE FIRST_TRANS_SIZE=$FIRST_TRANS_SIZE SECOND_TRANS_SIZE=$SECOND_TRANS_SIZE"

#write first part of test data
echo "writing first part of data..."
CMD="../example/example -i 22222222 -a 127.0.0.1:1111:2 -r 127.0.0.1:1025:2 -T jhash \
		-W $TEMP_DIR/tmp_1 -I $FILE_ID_1 -l $TEMP_DIR/client_log -m $LOGMASK -O 0 -S $FIRST_TRANS_SIZE"
echo "$CMD" >> $RUN_STACK
$CMD >> $RUN_STACK
TMP=$?
if [ "f$TMP" != "f0" ]; then
	echo "ERROR $TMP"
	echo -e "LOG: \n\n"
	cat $TEMP_DIR/client_log
	clean_up
	exit 1	
fi

#write second part of test data
echo "writing second part of data..."
CMD="../example/example -i 22222222 -a 127.0.0.1:1111:2 -r 127.0.0.1:1025:2 -T jhash \
		-W $TEMP_DIR/tmp_1 -I $FILE_ID_1 -l $TEMP_DIR/client_log -m $LOGMASK -O $FIRST_TRANS_SIZE -S $SECOND_TRANS_SIZE"
echo "$CMD" >> $RUN_STACK
$CMD >> $RUN_STACK
TMP=$?
if [ "f$TMP" != "f0" ]; then
	echo "ERROR $TMP"
	echo -e "LOG: \n\n"
	clean_up
	exit 1	
fi

#read test data
echo "reading data..."
CMD="../example/example -i 22222222 -a 127.0.0.1:1111:2 -r 127.0.0.1:1025:2 -T jhash \
		-R $TEMP_DIR/res_1 -I $FILE_ID_1 -l $TEMP_DIR/client_log -m $LOGMASK"
echo "$CMD" >> $RUN_STACK
$CMD >> $RUN_STACK
TMP=$?
if [ "f$TMP" != "f0" ]; then
	echo "ERROR $TMP"
	echo -e "LOG: \n\n"
	clean_up
	exit 1	
fi

#compare test data and reading results
cmp $TEMP_DIR/tmp_1 $TEMP_DIR/res_1
if [ "f$?" != "f0" ]; then 
	echo -e "ERROR\nfiles differ!"	
	clean_up
	exit 1
else 
	echo "files are equal" 
fi
rm $TEMP_DIR/res_1*


# ***************************************
# * 2 server - 1 client                 *
# *  send request to new second server  *
# ***************************************
echo "===== 2 server - 1 client ====="
echo "=====  send request to new second server"

#start second server
echo "starting second server..."
echo -n > $TEMP_DIR/server2_log
CMD="../example/example -i $SERVER_ID_2 -a 127.0.0.1:1030:2 -r 127.0.0.1:1025:2 -d $TEMP_DIR/server2 -j \
		-l $TEMP_DIR/server2_log -m $LOGMASK $SERVER_FLAGS"
echo "$CMD" >> $RUN_STACK
$CMD & 
sleep 5
if [ "f$(ps -p $! --no-headers -o comm)" = "f" ]; then
	echo "ERROR"
	echo -e "LOG: \n\n"
	clean_up
	exit 1
fi
SERVER2_PID=$!

#read test data
echo "reading data..."
CMD="../example/example -i 22222222 -a 127.0.0.1:1111:2 -r 127.0.0.1:1030:2 -T jhash \
	       -R $TEMP_DIR/res_1 -I $FILE_ID_1 -l $TEMP_DIR/client_log -m $LOGMASK"
echo "$CMD" >> $RUN_STACK
$CMD >> $RUN_STACK
TMP=$?
if [ "f$TMP" != "f0" ]; then
	echo "ERROR $TMP"
	echo -e "LOG: \n\n"
	clean_up
	exit 1	
fi

#compare test data and reading results
cmp $TEMP_DIR/tmp_1 $TEMP_DIR/res_1
if [ "f$?" != "f0" ]; then 
	echo -e "ERROR\nfiles differ!"	
	clean_up
	exit 1
else 
	echo "files are equal" 
fi
rm $TEMP_DIR/res_1*


# ***************************************
# * 2 server - 1 client                 *
# *  send request to old first  server  *
# ***************************************
echo "===== 2 server - 1 client ====="
echo "=====  send request to old first  server"

#read test data
echo "reading data..."
CMD="../example/example -i 22222222 -a 127.0.0.1:1111:2 -r 127.0.0.1:1025:2 -T jhash \
		-R $TEMP_DIR/res_1 -I $FILE_ID_1 -l $TEMP_DIR/client_log -m $LOGMASK"
echo "$CMD" >> $RUN_STACK
$CMD >> $RUN_STACK
TMP=$?
if [ "f$TMP" != "f0" ]; then
	echo "ERROR $TMP"
	echo -e "LOG: \n\n"
	clean_up
	exit 1	
fi

#compare test data and reading results
cmp $TEMP_DIR/tmp_1 $TEMP_DIR/res_1
if [ "f$?" != "f0" ]; then 
	echo -e "ERROR\nfiles differ!"	
	clean_up
	exit 1
else 
	echo "files are equal" 
fi
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

kill $SERVER1_PID
SERVER1_PID=

#read test data
echo "reading data..."
CMD="../example/example -i 22222222 -a 127.0.0.1:1111:2 -r 127.0.0.1:1030:2 -T jhash \
		-R $TEMP_DIR/res_1 -I $FILE_ID_1 -l $TEMP_DIR/client_log -m $LOGMASK"
echo "$CMD" >> $RUN_STACK
$CMD >> $RUN_STACK
TMP=$?
if [ "f$TMP" != "f0" ]; then
	echo "ERROR $TMP"
	echo -e "LOG: \n\n"
	clean_up
	exit 1	
fi

#compare test data and reading results
cmp $TEMP_DIR/tmp_1 $TEMP_DIR/res_1
if [ "f$?" != "f0" ]; then 
	echo -e "ERROR\nfiles differ!\Join isn't correct!"	
	clean_up
	exit 1
else 
	echo -e "files are equal\nJoin is correct" 
fi
rm $TEMP_DIR/res_1*


#cleanup 
clean_up
rm -rf $TEMP_DIR

echo -e "\n\nSUCCESSFUL!"
exit 0
