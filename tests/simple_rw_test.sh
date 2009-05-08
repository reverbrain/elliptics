#!/bin/bash 

#options
TEMP_DIR=temp
GENERATING_TIME=1 #working time for cat /dev/urandom > some_test_file


echo "Simple read/write test"

#creating test directories
mkdir -p $TEMP_DIR
mkdir -p $TEMP_DIR/server1
mkdir -p $TEMP_DIR/server2

#cleaning resources on a fail or on the end
function clean_up() {
	if [ "$SERVER1_PID" ]; then
		kill $SERVER1_PID
	fi
	if [ "$SERVER2_PID" ]; then
		kill $SERVER2_PID
	fi
	rm -rf $TEMP_DIR
}

#generating random file 
echo "Generating test file..."
cat /dev/urandom > $TEMP_DIR/tmp_1 &
sleep $GENERATING_TIME
kill $!

# ***************************************
# * 1 server - 1 client                 *
# ***************************************

#start first server
echo "starting first server..."
../example/example -i 123456789 -a 127.0.0.1:1025:2 -d $TEMP_DIR/server1 -j -l $TEMP_DIR/server1_log & 
sleep 1 
if [ "f$(ps -p $! --no-headers -o comm)" = "f" ]; then
	echo "ERROR"
	echo -e "LOG: \n\n"
	cat  $TEMP_DIR/server1_log
	clean_up
	exit 1
fi
SERVER1_PID=$!

#write test data
echo "writing data..."
echo -n > $TEMP_DIR/client_log
../example/example -i 22222222 -a 127.0.0.1:1111:2 -r 127.0.0.1:1025:2 -T jhash -W $TEMP_DIR/tmp_1 -I 12345 -l $TEMP_DIR/client_log > /dev/null
TMP=$?
if [ "f$TMP" != "f0" ]; then
	echo "ERROR $TMP"
	echo -e "LOG: \n\n"
	cat  $TEMP_DIR/client_log
	clean_up
	exit 1	
fi

#read test data
echo "reading data..."
echo -n > $TEMP_DIR/client_log
../example/example -i 22222222 -a 127.0.0.1:1111:2 -r 127.0.0.1:1025:2 -T jhash -R $TEMP_DIR/res_1 -I 12345 -l $TEMP_DIR/client_log > /dev/null
TMP=$?
if [ "f$TMP" != "f0" ]; then
	echo "ERROR $TMP"
	echo -e "LOG: \n\n"
	cat  $TEMP_DIR/client_log
	clean_up
	exit 1	
fi

#compare test data and reading results
if [ -n "$(diff $TEMP_DIR/tmp_1 $TEMP_DIR/res_1)" ]; then 
	echo -e "ERROR\nfiles differ!"	
	clean_up
	exit 1
else 
	echo "files is equal" 
fi
rm $TEMP_DIR/res_1 

# ***************************************
# * 2 server - 1 client                 *
# *  send request to new second server  *
# ***************************************

#start second server
echo "starting second server..."
../example/example -i 987654321 -a 127.0.0.1:1030:2 -r 127.0.0.1:1025:2 -d $TEMP_DIR/server2 -j -l $TEMP_DIR/server2_log & 
sleep 1 
if [ "f$(ps -p $! --no-headers -o comm)" = "f" ]; then
	echo "ERROR"
	echo -e "LOG: \n\n"
	cat  $TEMP_DIR/server1_log
	clean_up
	exit 1
fi
SERVER2_PID=$!

#read test data
echo "reading data..."
echo -n > $TEMP_DIR/client_log
../example/example -i 22222222 -a 127.0.0.1:1111:2 -r 127.0.0.1:1030:2 -T jhash -R $TEMP_DIR/res_1 -I 12345 -l $TEMP_DIR/client_log > /dev/null
TMP=$?
if [ "f$TMP" != "f0" ]; then
	echo "ERROR $TMP"
	echo -e "LOG: \n\n"
	cat  $TEMP_DIR/client_log
	clean_up
	exit 1	
fi

#compare test data and reading results
if [ -n "$(diff $TEMP_DIR/tmp_1 $TEMP_DIR/res_1)" ]; then 
	echo -e "ERROR\nfiles differ!"	
	clean_up
	exit 1
else 
	echo "files is equal" 
fi
rm $TEMP_DIR/res_1 



#cleanup 
clean_up
exit 0
