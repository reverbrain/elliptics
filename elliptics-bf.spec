%{!?python_sitelib: %global python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")}
%{!?python_sitearch: %global python_sitearch %(%{__python} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib(1))")}

Summary:	Distributed hash table storage
Name:		elliptics
Version:	2.26.10.2
Release:	1%{?dist}

License:	GPLv2+
Group:		System Environment/Libraries
URL:		http://www.ioremap.net/projects/elliptics
Source0:	%{name}-%{version}.tar.bz2
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:	python-devel
BuildRequires:	libcocaine-core2-devel >= 0.11.2.0
BuildRequires:  cocaine-framework-native-devel >= 0.11.0.0
BuildRequires:	eblob-devel >= 0.23.11
BuildRequires:  libblackhole-devel = 0.2.4
BuildRequires:	libev-devel libtool-ltdl-devel
BuildRequires:	cmake msgpack-devel python-msgpack
BuildRequires:	handystats >= 1.10.2

%define boost_ver %{nil}

BuildRequires:	boost%{boost_ver}-devel
BuildRequires:	python-virtualenv

Obsoletes: srw

%description
Elliptics network is a fault tolerant distributed hash table
object storage.


%package devel
Summary: Development files for %{name}
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}


%description devel
Elliptics network is a fault tolerant distributed hash table
object storage.

This package contains libraries, header files and developer documentation
needed for developing software which uses the cairo graphics library.

%package client
Summary:	Elliptics client library (C++/Python bindings)
Group:		Development/Libraries


%description client
Elliptics client library (C++/Python bindings)

%package -n cocaine-plugin-elliptics
Summary: Elliptics plugin for Cocaine
Group: Development/Libraries
Requires: %{name} = %{version}-%{release}

%description -n cocaine-plugin-elliptics
cocaine-plugin-elliptics


%package client-devel
Summary:	Elliptics library C++ binding development headers and libraries
Group:		Development/Libraries
Requires:	%{name} = %{version}-%{release}
Requires:	libblackhole-devel = 0.2.4


%description client-devel
Elliptics client library (C++/Python bindings), devel files

%prep
%setup -q

%build
export LDFLAGS="-Wl,-z,defs"
export DESTDIR="%{buildroot}"
%{cmake} -DWITH_COCAINE=on .

#make %{?_smp_mflags}
make

#make test

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}
rm -f %{buildroot}%{_libdir}/*.a
rm -f %{buildroot}%{_libdir}/*.la

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig

%post client -p /sbin/ldconfig
%postun client -p /sbin/ldconfig

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc README
%{_bindir}/dnet_ioserv
%{_libdir}/libelliptics.so.*
%{_mandir}/man1/*

%files devel
%defattr(-,root,root,-)
%{_bindir}/dnet_run_servers
%{_libdir}/libelliptics.so

%files -n cocaine-plugin-elliptics
%defattr(-,root,root,-)
%{_libdir}/cocaine/elliptics-extensions.cocaine-plugin

%files client
%defattr(-,root,root,-)
%{_bindir}/dnet_iterate
%{_bindir}/dnet_iterate_move
%{_bindir}/dnet_find
%{_bindir}/dnet_ioclient
%{_bindir}/dnet_index
%{_bindir}/dnet_notify
%{_bindir}/dnet_ids
%{_bindir}/dnet_balancer
%{_bindir}/dnet_recovery
%{_bindir}/dnet_client
%{_libdir}/libelliptics_client.so.*
%{_libdir}/libelliptics_cpp.so.*
%{python_sitelib}/elliptics/core.so.*
%{python_sitelib}/elliptics_recovery/*
%{python_sitelib}/elliptics/*.py*
%{python_sitelib}/elliptics*.egg-info

%files client-devel
%defattr(-,root,root,-)
%{_includedir}/*
%{_libdir}/libelliptics_client.so
%{_libdir}/libelliptics_cpp.so
%{_datadir}/elliptics/cmake/*
%{python_sitelib}/elliptics/core.so


%changelog
* Sat Mar 05 2016 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.10.2
- dc recovery: fix skipping keys when a whole server-send is failed
- server-send: add client address to 'sending response' log
- cmake: add option to disable long tests
- iterator-copy: stop eblob iterator if write error has been occurred
- server-send: move the check of write error occurence
- Fix status in ack for request failed with -ENXIO
- server_send: add tests for bad cases
- Fix hanging of backend initialization
- route: do not spam logs with debug route table content every time route table is requested
- binding: added cflags_checksum & cflags_nocache to python binding
- Fixed data size in write response:
- python: added `set_delay` method
- fixed trans number in a result in case of timeout
- spec: fixed version string comparison

* Sat Jan 23 2016 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.10.1
- trans: remove transaction from timer tree in network thread to allow IO thread to run long callbacks and this would not affect 'real' timing for transaction in question
- set blackhole-dev' version to `0.2.4-1`
- trans: update transaction's timestamp just after it has been received right in the network thread. This allows to account for long unavailability of the IO thread, but yet do not complete transaction with timeout error
- dc_recovery: fixed extra 'recovered_keys' stats update on timeout
- trans: fixed race between timeout scanning thread and completion callback invocation, the latter does not remove transaction from the timer tree and transaction may be grabbed and freed by timeout checking thread
- dc_recovery: updated recovery/recovery.qdoc
- dc_recovery: added option --no-server-send
- build: Removed `EBLOB_LOG_SPAM`
- dc_recovery: processing of uncommitted keys in server-send recovery
- dc_recovery: retries of timeouted remove & server-send operations
- dc_recovery: explicitly remove corrupted keys
- dc_recovery: optimization: use server-send for small/medium keys

* Sun Jan 10 2016 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.9.4
- session: added new server_send() method which works with vector of elliptics::key. This is the most generic method, others use it internally.

* Thu Dec 10 2015 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.9.3
- package: depend on eblob 0.23.11+, which contains new iterator flag to verify checksum
- session: extended error message when dnet_mix_states() fails, include ioflags, key and number of groups
- recovery: Iterator class refactoring
- recovery: added description of ServerSendRecovery class & its methods
- merge recovery: optimization: use copy-iterator & server-send for small/medium keys
- tests: recovery: check that merge recovery removes moved keys from the source backend
- tests: added test which writes data into cache with small lifetime/sync timeout, previously cache overwrote user's timestamp with current time, this test checks that timestamp is still valid
- local_session: do not overwrite valid user's timestamp with current time
- binding: python: added server_send & start_copy_iterator session methods
- server_send: print queue size when sending write request
- server_send: set larger write timeout if node's wait timeout is less than 60 seconds
- iterate_move: example application should use zero iterator flags to prevent confusion (when no-meta flag is set, all timestamps are zeroed)
- server_send: implemented dynamic size of the queue of pending writes
- iterate_move: added wait timeout option
- server_send: broadcast write error to all blocked thread
- tests: cmake's add_custom_target() is unreliable with setting envvars
- tests: instruction on how to add new c++ test and additional cleanup
- iterate: set EBLOB_ITERATE_FLAGS_VERIFY_CHECKSUM for start_copy_iterator() (requires 0.23.11+ eblob)

* Wed Nov 25 2015 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.9.2
- fixed crash caused by using freed memory
- tests: server-send tests operate with 2 sessions
- tests: server_send tests now check response status
- server_send: set response status to reflect possible write/remove errors
- ioclient: use dnet_print_time() to print modification time
- server_send: filters and checkers should only work for aggregated result
- basic_handler: added comment desribing set_total() method
- trans: added error debug into common transaction allocation path when we've failed to find a state
- ioclient: print group id when lookup succeeds
- ioclient: fixed lookup info dump, allow to use raw ID specified via -I option

* Fri Nov 13 2015 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.9.1
- tests: set iterator flags to zero in read-one-range test
- tests: added simple mix-states test which tests that reads and writes succeed, it doesn't check whether groups are actually mixed or not, this is done in weights test, where global node's mix states flags is tested
- iterator: automatically set key-range flag if there is at least one range in the request
- recovery: fixed hanging up when there is no key which should be recovered
- config: added new options into example config
- ioflags: added mix-states flag, which forces groups to be mixed according to state weights

* Sat Oct 24 2015 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.9.0
- io: added timestamp compare-and-swap flag, it allows to write data only when on-disk timestamp is less than to be written data timestamp, or when there is no data on disk.
- backends: remove filesystem and module backends
- srw: added ability to reply via response stream
- package: put iterator examples into client package

* Tue Oct 06 2015 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.8.0
- cleanup: stop all node thread pools, then destroy monitor, then cleanup node thread pools
- net: correctly set socket option to the proper socket
- Indent fixes
- session: implemented server-send method, which sends given keys from one server node to multiple remote groups
- iterator: implemented server-send iterator, which sends all iterated keys to multiple remote groups
- package: depend on eblob 0.23.5+, where chunk_dir option has been added
- trans: fixed possible NULL pointer dereference
- config: read_only option for backend
- route: fixed ids update possible unintialized pointer free
- small fix: use variable after checking that it isn't null
- atomic: sub/add should return new value like inc/dec do
- atomic: all atomics are actually long, not int
- Updated debug logs, fixed minor bug with server socket prio setting. Fixed BE/LE issues when sending ID container
- backend: fixed ponential NULL pointer dereference
- tests: added small delay and big description for simultaneously started servers
- route: fixed JOIN command with zero enabled backends
- id: refactor and fix backend id container handling
- state: extended a bit state reset debug
- trans: fixed dnet_trans_iterate_move_transaction(), it must delete transaction from any list where it might live via trans_list_entry
- route: fixed route list validation
- packet: added comments about new commands and relation to dnet_cmd_needs_backend()
- config: 'datasort_dir' option in backend section
- session: read_data() comment update
- Added more connection debug
- iterator: added example iterator which runs over specified group and copies/moves data to requierd destination point
- dnet: if there was any error - send ACK to notify client with error code and destroy transaction. Previously transaction would stuck and timeout if there is checksum error.
- trans: if IO transaction can not be allocated, do not call completion twice
- crypto: fixed invalid processing of data block larger than buffer in sha512_file()/sha512_file_ctx()
- timeout: accurately check timeouted transactions using microseconds

* Wed Aug 19 2015 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.7.0
- state: split backend weight into cache/disk pair and update them separately according to IO flags
- eblob: fixed write commit log - have to write correct commit size
- io: new blocking request queue instead of dnet_oplock()
- tests: added test for checking that dnet_opunlock() unlocks key
- tests: added dnet_locks_test: testing of oplocks in backend request queue
- measure points: io.cmd.{}.lock_time erased; pool.{}.{}.search_trans_time added

* Mon Jul 27 2015 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.6.2
- recovery: zero-sized keys are actually valid
- eblob: write ext header when committing record (if it hasn't been written already for this IO request)
- eblob: when doing prepare, perform plain write with ext header right after prepare
- eblob: fixed integer overflow for uncommitted records during iteration
- iterator: added --no-meta option to example cpp iterator code

* Wed Jul 15 2015 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.6.1
- recovery: monitor: fixed metrics: 'local_read_bytes', 'remote_written_bytes' etc
- recovery: recover keys by window not by batch - closes
- 	Previous logic - recovery gets batch of keys, recovers them in parallel,
- 	wait until all recovers are finished and goes to next batch of keys
- 	Current logic - recovery starts to recover batch of keys in parallel,
- 	as soon as recovering of any key is finished, succeessfuly or not,
- 	it starts to recover next key
- recovery: removed 'filtered_keys' from logs and stats - it is always equal to iterated_keys
- recovery: monitor: fixed set_counter for 0
- recovery: removed unused code and fixed comments
- test: cleanup logger after each recovery - fixed mixing logs from different recoveries
- recovery: use '-L' option for all recovery logs
- recovery: decreased level of stderr logs to WARNING
- recovery: added '-T/--trace-id' option to dnet_recovery - allows to mark servers' logs connected with recovery
- python: added `trace_bit` to elliptics.Session
- build: fixed build on rhel
- oplocks: use dnet_id instead of dnet_raw_id for taking into account group_id

* Thu Jul 09 2015 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.6.0
- iterator: fixed segfault on start_iterator without specified groups
- eblob: updated eblob version
- recovery: added using record_flags from read, lookup and iterator results for correct recovering of keys checksummed by chunks
- eblob: added support of new eblob checksums

* Wed Jun 24 2015 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.5.5
- iterator: force reading header of uncommitted records

* Mon Jun 15 2015 Kirill Smorodinnikov <shaitkir@gmail.com> - 2.26.5.4
- backend: added parsing backend_id by eblob_backend
- compilation warning fix on precise (undefined UINT64_MAX)

* Thu Jun 04 2015 Kirill Smorodinnikov <shaitkir@gmail.com> - 2.26.5.3
- logs: changed level of 'Failed to get VFS statistics' to NOTICE because it spams log and isn't caused by critical error.
- network: sockets are lost from node's reconnect list after dropped connection to net state (after stall_count timeout)
- tests: added description of backend weights test
- recovery: allowed to use string value for '-L/--log-level'
- recovery: moved gathering of route list into get_routes() at main process - made temporary node/session be freed after the route list is received.
- tests: new backend weights test
- more comments
- logs: changed format of backend_id
- renamed dnet_idc_insert -> dnet_idc_insert_nolock
- fixed incorrect releasing of resources
- logs, optimization: use dnet_log instead of dnet_log_error after error on pthread_* & some malloc+memset -> calloc
- network: calculate & use connection weight by backend
- backends: used const pointers for key/value arguments of dnet_config_entry callback - remove useless copying of value.
- backend: eblob: made `eblob_backend_cleanup` to call `eblob_cleanup` only if eblob was initialized
- monitor: fixed memory leaks of `dnet_config_backend` internals - added calling `cleanup()`.
- fix: moved checking c->eblob into `dnet_blob_config_cleanup` - `eblob_backend_cleanup` should not be called if the backend wasn't proper initialized.
- docs: added description to dnet_blob_config_cleanup().
- updated missed module_backend functions.
- eblob: when using prepare+plain_write+commit flags, commit number of written bytes, not number of allocated bytes on disk
- session: added prepare/write/commit tuple description
- tests: added simultaneous prepare/write/commit test

* Wed May 06 2015 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.5.2
- package: depend on 0.22.22+ eblob which brings defrag stop command
- network: fixed bug with when total_count < failed_count in dnet_socket_connect_new_sockets()
- dnet_client, ioclient: added stop_defrag command

* Tue Apr 28 2015 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.5.1
- network: fixed bug with negative route_list_count

* Mon Apr 27 2015 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.5.0
- network: don't use dnet_node_state_num() to estimate number of ready events in epol
- pytests: added tests that checks new flag elliptics.record_flags.uncommitted:
-      * serial of write_prepare, write_plain and write_commit with checking data accessibility
-      * new tests of merge and dc recovery with mixing uncommitted keys into recovering keys.
- core: added common for all backends flag DNET_RECORD_FLAGS_UNCOMMITTED which is set for record is uncommitted and can't be read
- iterator: made iterator collects uncommitted records
- recovery: added handling uncommitted records, added options prepare-timeout which specifies timeout for uncommitted records after which such records should be deleted
- recovery: fixed hanging on pool.close() - there is a bug in multiprocessing
- package: depend on 0.22.21+ eblob, it contains defrag adn prepare/commit changes needed by elliptics
- ioclient: added more description of defrag modes
- network: refactored dnet_addr_socket & dnet_connect_state related resource handling logic
- logs: added error logs at places where iterator can fail
- ioclient: added description of 'compact' defragmentation mode
- core: used timedwait for waiting condition variable - fixed hanging on exit
- iterator: added checking that the backend supports iterator before run iterator
- python: allow to use all basestrings for elliptics.Id initialization not only str
- network: dnet_addr_socket is class now, thus handling its resources. sockets container is std::map instead of c-style intrusive list (of sockets)
- session, backend: added new defragmentation level & command 'compact' - datasort heavy-fragmented blobs only
- network: use stall_count from node instead of hard-coded constant
- network: fixed possible deadlock and double resource release in dnet_check_all_states()
- network: send ping command to remote node if transactions stall count reaches its limit instead of resetting net_state
- recovery: fixed typo and merged disabling checksums for all but the first chunk
- recovery: use close to elliptics' log format in recovery logs
- recovery: fixed  statistics calculation
- build: fixed build on rhel 6 with boost v1.41.0-25

* Fri Mar 27 2015 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.4.4
- config: fixed bug when invalid remote (e.g. whose net address couldn't be resolved) from config leads to dnet_ioserv termination during initialization step
- pool: fixed crash on working with invalid evs[i].data.ptr (dnet_net_state) after releasing of this net_state on EPOLLERR at previous iteration over evs[i]

* Fri Mar 27 2015 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.4.3
- package: depend on 0.22.20+ eblob because of API changes

* Fri Mar 27 2015 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.4.2
- network io handler iterates only single event, where epoll_wait() may return more than one
- added top events settings to monitoring/top provider
- net stats in procfs provider: rx/tx bytes, packets, error count for net interfaces
- removed unused sha384 functions and unification with eblob cryptolib
- mmap elimination - mmap() replaced with pread(). Corrupted filesystem may return -EIO for some reads, while
- 	trying to access that data via mmap ends up with SIGBUS signal, which kills whole eblob user.

* Mon Mar 23 2015 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.4.1
- json: fixed crash on generating statistics for disabled at startup backends
- Used local node address for state in local_session: fixed invalid address at logs.
- net: connection between servers with different number of addresses is not allowed.
- 	If connected node has different number of addresses fail its socket processing.
- core: use rbtree to store groups list
- recovery: fixed error logging format in dc recovery
- tests: refactored tests for event statistics
- Added TOP statistics implementation - it returns set of keys which generate the most amount of traffic

* Thu Mar 12 2015 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.3.37
- Get rid of autogenerated typedefs file
- recovery: dc: do not check checksum while reading on all but the first chunk
- statistics: moved adding `group` to `backend::config` or `backend::config_template` into fill methods
- statistics: provided `to_json` methods for eblob and filesystem config templates

* Wed Jan 28 2015 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.3.36
- package: depend on 0.22.15+ eblob
- logs: fixed printing trace_id at logs while receiving/sending packets
- iterator: made iterators with `no-meta` flag to return zero timestamp.
- 	Now if iterator faces a record with corrupted exteded header it will return a key with empty extended header.

* Sat Jan 17 2015 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.3.35
- logger: let file logger to watch to its sink file and allow file to be moved/rotated
- Indent cleanup

* Tue Dec 23 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.3.34
- recovery: fixed recovering keys which have several alive copies at one backend
- tests: updated description of test_session_iterator cases
- python: limited types of object that can be used for elliptics.Id initialization
- stat: do not fill in backend::config object for non-enabled backends, it contains strings only, but it must be parsed instead.
- 	Use backend::config_template object for those backends.
- recovery: used total_size instead of size for determining record size.
- recovery: escaped dumping keys that allready consistent in all groups
- recovery: added recovery_speed to merge stats
- iteration: removed double checking of ranges - keys is already filtered in eblob
- iteration: added new iteration flag: DNET_IFLAGS_NO_META which turns off reading extended header from blob and speedups,
- 	but all keys that will be returned by such iteration will have empty metadata (timestamp and user_flags).
- recovery: added '-M' option to dnet_recovery which speedups iteration phases of recovery but sacrifices checking metadata.
- 	Recovery with this option will not check metadata, will not replace old records by new ones and
- 	will only copy some available replica of keys to groups which do not have these keys.
- pytests: added case to test_session_iterator that check iterating with no_meta flag
- recovery: added 'recovery_speed' and 'iteration_speed' to statistics. Both values are mesuared in records per second.
- python: made elliptics.Id to be initialized by any iterable object and group
- recovery: replaced cPickle by msgpack for packing intermediate results
- recovery: added 'total_keys' statistics that shows how much keys should be recovered/processed
- python: fixed gil_guard
- bindings: added start_time and end_time methods for async_result: both for C++ and Python bindings.
- 	They return timestamps when async result was created and finished.
- 	Fixed calculation tnsec of elapsed_time.
- config: use uint32_t for parsing group from config - disallow setting negative group.
- Pytests: added iterator tests.
- Pytests: moved  fixture to global conftests. Disabled srw for test cluster in test_specific_cases. Cleaned up pytests code.
- Made dumping key enabled by default, to disable it introduced new option -> -u
- don't add option for key dumping in dc_recovery
- Added option for dumping into text file all iterated keys
- Fixed code indent
- config: do not reparse config at each backend init - only if config was modified.
- 	Removed useless copying of an array at config methods.
- Disable only non-disabled backends at cleanup.

* Mon Nov 10 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.3.33
- lookup: extended lookup address to return dnet_addr, not address string
- pytests: fixed broken index tests - use common cluster for all test and isolated cluster for test_special_cases

* Fri Oct 24 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.3.32
- tests: created config struct for create_nodes method and moved all argument to it
- pytests: added test case for checking correct handling situation when 2 backends from different nodes has equal group and ids
- pytests: made server node isolated - now server nodes do not know about each other
- core: reset state if dnet_idc_update_backend has been failed.

* Thu Oct 23 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.3.31
- session: get rid of handmade address-to-string conversion, use dnet_addr_string() and friends helpers
- addr: use getnameinfo() to properly determine family and automatically dereference sockaddr
- addr: new thread-safe helpers to print address strings
- Fixed remove_on_fail implementation

* Tue Oct 21 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.3.30
- recovery: removed odd increasing of iterations
- recovery: fixed memory leak at merge recovery
- python: removed wrapping address method at result entries that inherited from CallbackResultEntry
- recovery: Moved code from dnet_recovery to recovery.py for using/testing it from pytests.
-     Added 'portable' method to Ctx that returns lightweight copy of the context that can be used by multiprocessing.
-     Removed monitor from context, left only stats - proxy object for sending updates to monitor from different processes/threads.
-     Removed using global context, use portable context insead of.
-     Moved process pool initialization and destruction into common recovery.py - removed duplicating code.
- Recovery: Use cached route-list for speedup recovering
- recovery: implemented one-node recovery for merge from dump
- recovery: cleanups global reference to context
- recovery: correctly close and join process pool
- recovery: correctly stops monitor threads
- test: decreased number of backends and nodes at pytests - decreased number of threads and processes used from tests
- cmake: added blackhole headers lookup
- recovery: used threading.Event for waiting complete
- recovery: decreased log level of log that looking up key from dump fail failed
- tests: reduce number of io/net threads
- eblob: allow small leters in size modificators M,m are for megabyte and so on

* Tue Oct 14 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.3.29
- package: depend on 0.22.9+ eblob where init errno code was introduced
- route: do not request route list if node flags includes DNET_CFG_NO_ROUTE_LIST
- recover: do not print error on lookup fail while recovering keys from dump - fail is an ok situation
- recover: skips keys that are missed on all nodes
- python: use dict if OrderedDict is not available
- recover: fixed  and  recovery from dump. Added test case for recovering keys from dump.
- python: added 'backend_id', 'trace_id' and 'trans' to callback_result_entry
- python: removed duplicated calls - use bp::bases for inheritance between different result_entry and base callback_result_entry
- backend: eblob_init sets errno on fail - use it for returning correct error code
- backends: do not process commands aimed to uninitialized backend
- python: added set_backend_ids method to elliptics.Session.
- dnet_balancer: added option '-u/--update' that turns no remote update ids on backends after balancing.
- dnet_balancer: added outputing final dht spread between nodes/backends.
- recovery: added  output format for statistics.
- recovery: skipping on iteration key with zero size of data.
- Python: fixed missing _node at cloned session.
- api: added resetting namespace by setting empty namespace.
- logs: added log that net thread has been finished.
- ioclient: backend status messages whitespace cleanup
- addr: added dnet_create_addr_str() helper which parses string and fills dnet_addr structure
- package: depend on 0.10.2+ handystats
- backend: added possibility to delay execution of every backend command by X ms
- init: fixed IO pool initialization

* Wed Oct 08 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.3.28
- python: fixed TypeError on some python version
- blackhole: enabled blackhole log rotation. Blackhole reopens log file if the original file has been moved or removed.
- spec: handystats dependency updated to 0.10
- auth: check client version at first and send self version only to client with right version.
- dc_recovery: Fix variable name: it was undefined name
- python: Fix some PEP8 warnings. Bad identation is fixed.
- spec: fixed bogus dates
- monitor: update to handystats 1.10
- example: monitoring-stats.txt lists measured values
- example: added sample config file for handystats
- monitor: io input/output/commands stats fixed and improved
- monitor: added support for formatted metrics names
- monitor: complete replacement of react
- monitor: using handystats library to gather runtime statistics
- srw: removed dumping @info result to the log
- rapidjson: correctly handle NaN values, small double values
- srw: added log-output: true into application's profile top level to dump crashlog into log
- test: monitor: open json dump file for writing
- test: write_cas: do not use lambda, use plain function instead (checking RHEL6 issue)
- run_servers: added 2 seconds sleep to wait for server/app initialization
- file: do not chroot to root dir, since with multuple backends there are multuple roots in the same process context
- state: dnet_state_create() reference counter fix/change
- backend: moved object size calc (getting into account total size and io->size/io->offset) into common header from eblob.
- find: set DNET_FLAGS_DIRECT_BACKEND flag which will force client code to set backend ID
- session: when using send-to-all-backends set backend id via dnet_session_set_direct_backend() call.
- fixed check for gcc version: support for noexcept on class constructor available only since gcc 4.6
- monitor: use one lock_guard for both: checking backend state and dumping backend json.
- monitor: Monitor uses almost all others, so it should be stopped at first.

* Sun Oct 05 2014 BogusDateBot
- Eliminated rpmbuild "bogus date" warnings due to inconsistent weekday,
  by assuming the date is correct and changing the weekday.
  Sun Jul 26 2010 --> Sun Jul 25 2010 or Mon Jul 26 2010 or Sun Aug 01 2010 or ....
  Sun Jul 28 2010 --> Sun Jul 25 2010 or Wed Jul 28 2010 or Sun Aug 01 2010 or ....
  Thu Nov 30 2010 --> Thu Nov 25 2010 or Tue Nov 30 2010 or Thu Dec 02 2010 or ....
  Thu Nov 23 2011 --> Thu Nov 17 2011 or Wed Nov 23 2011 or Thu Nov 24 2011 or ....
  Sun Mar 13 2012 --> Sun Mar 11 2012 or Tue Mar 13 2012 or Sun Mar 18 2012 or ....
  Sat Apr 27 2012 --> Sat Apr 21 2012 or Fri Apr 27 2012 or Sat Apr 28 2012 or ....
  Sun Apr 28 2012 --> Sun Apr 22 2012 or Sat Apr 28 2012 or Sun Apr 29 2012 or ....
  Thu Jul 28 2014 --> Thu Jul 24 2014 or Mon Jul 28 2014 or Thu Jul 31 2014 or ....

* Tue Sep 30 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.3.27
- recovery: added another one (last) fix for compatibility with python2.6 which doesn't support multiple open with one with
- recovery: fixed multiple open at one with (python2.6)
- Pytests: if procfs statistics: vm, io or stat; contain nonzero error - do not asserts internal statistics
- monitor: added 'error' and 'string_error' to procfs statistics: vm, io and proc
- file: fixed file_info timestamp reading
- trans: when destructing transaction, write not only state, but also backend
- monitor: clear dnet_vm_stat at dnet_get_vm_stat
- Recovery: fixed circular references in dc recovery. Fixed static analysis and memory profiler warnings.
- Pytests: fixed vfs statistics test - zero value for some metrics is valid.
- file: fixed metadata blob initialization
- lookup: there are 2 lookup stages: cache and disk, do not send ack if we succeeded searching for the key
- forward: cleanup forward path, put transaction allocation into forward function
- file: fixed lookup command and lookup timestamp for missed metadata

* Sun Sep 28 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.3.26
- net: put state in dnet_connect_route_list_complete
- connect: add_remote() must always return error when failed to connect to any remote node
- fs: set default directory-bit-numnber to 16, otherwise backend doesn't work if appropriate config option is not specified
- balancer: print correct message if remote hasn't been specified
- pytest: more comments
- Pytest: set tests timeout to 300 sec
- Pytests: added test for recovering corrupted data
- Recovery: removed duplicates from list of groups with outdated data. Fixed crash after failed iteration.
- Recovery: changed default logging level for dnet_recovery
- Backends: added new backend state: DNET_BACKEND_UNITIALIZED for backends that have not been specified in config file.
- 	Do not include status of unitialized backends to monitor statistics and backends status of unitialized backends to monitor statistics and backends status response.
- Core: do not recalculate state weight after commands without data

* Thu Sep 18 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.3.25
- net: setup state epoll_fd before sending AUTH
- Python: added comments to route.py
- Python: speeded up elliptics.RouteList initialization

* Thu Sep 18 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.3.24
- route: fixed deadlock in routes.cpp
- Block dependency from next major version of elliptics
- stats: provide backend directly from cmd processing, do not try to find it using cmd->backend_id
- session: roughly exit on 'impossible' condition
- stat: do not dereference incorrect (negative or too large) backend_id
- route: Reset state if JOIN fails by any reason	b0a8c47
- library: Use copy addresses at state_move_to_dht
- Build-Deps: blackhole-dev (>= 0.2.1-1)
- find: Add backend_id to dnet_find output

* Tue Sep 16 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.3.23
- stats: implemented per-backend command counters
- log: returned back extended io command log
- stats: only print commands which have non-zero counters
- ioclient: added options to change backend status (enable, disable, ro, writable)
- cache: slru destruction debug
- stats: get rid of histograms

* Wed Sep 10 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.3.22
- net: Surround state->node_entry changes by state_lock

* Wed Sep 10 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.3.21
- net: Use list_splice_init correctly
- monitor: compress returned data via both http and elliptics protocols

* Tue Sep 09 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.3.20
- monitor: compress every possible json reply from server to client including error jsons
- monitor: static function in headers must be inlined
- net: Fixed race condition of route-list counter
- net: Fixed parsing of route list for dual stack
- server: Set not-null address for accepting state
- net: Fixed debug output for route lists
- library: Added session::request_single_cmd
- trans: Fixed trans_id at transactions' destruction

* Tue Sep 02 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.3.19
- Pytest: added checking requesting all categories.
- monitor: add 'group' to 'backend->config' only if it was requested

* Tue Sep 02 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.3.18
- reconnect: always add address into reconnection queue until it is EEXIST, ENOMEM or EBADF error

* Tue Sep 02 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.3.17
- Python: fixed make_writable

* Tue Sep 02 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.3.16
- monitor: restored 'group' at 'backend->config'
- python: added make_readonly and make_writable to elliptics.Session
- monitor: removed commands history

* Wed Aug 27 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.3.15
- elliptics: Fixed handler::total at several places
- monitor: forced deflate of the transmitted json
- recovery: now if dc couldn't read the newer version of the key - it skips it and use next one by timestamp and so on
- Monitor: moved config of disabled backend to 'backend->config'
- Pytest: marked each test case by unique trace_id
- Pytests: added monitor statistics to log
- monitor: now monitor listen the same net family as the node does
- merge recovery: added user-friendly log when group has only one node with one backend
- tools: added '-n/--check_nodes' option to dnet_balancer for printing only nodes spread without route-list
- Python: completely removed old interface elliptics.Session.get_routes and used new elliptics.Session.routes wherever needed
- package: depend on blackhole 0.2.0-2 and higher

* Tue Aug 26 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.3.14
- server: Fixed io queue limits
- client: Throw -EPROTO if we connected to wrong addr
- client: Fixed checkers at merge_indexes
- client: Recover files on read also for -EILSEQ
- client: Don't lose trace_id at timeout

* Mon Aug 25 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.3.13
- session: implemented bulk_remove() method
- tests: since timeouts are now long, fix its overflow test
- config: fixed misleading config error exception message
- timeouts: all timeouts are long
- config: only try to add new nodes if remotes() vector contains some addresses
- trans: extended timeout transaction log
- client: Explicitly link with boost-system
- package: depend on blackhole 0.2.0-0rc10

* Fri Aug 22 2014 Ruslan Nigmatullin <euroelessar@yandex.ru> - 2.26.3.12
- Logs: removed '\n' from the end of logs - blackhole adds '\n'
- example: Added backend_id to example config
- balancer: changed usage removed spread by percentages
- server: Don't check for forward if direct request
- backends: Write duration of backend's init
- backends: set correct error if missed backend_id
- Monitor: wrapped json generation by try/catch
- backends: Make unique log for every backend
- node: EEXIST for state is 'good' error

* Thu Aug 21 2014 Ruslan Nigmatullin <euroelessar@yandex.ru> - 2.26.3.11
- Logger: Write logs in local time

* Thu Aug 21 2014 Ruslan Nigmatullin <euroelessar@yandex.ru> - 2.26.3.10
- Python: removed using of dropped elliptics.log_level.data
- Log: fixed typo and fixed spaces
- backends: Added mandatory field backend_id

* Wed Aug 20 2014 Ruslan Nigmatullin <euroelessar@yandex.ru> - 2.26.3.9
- dnet_client: Fixed default log level
- server: Add backend_id to every log at io pool

* Wed Aug 20 2014 Ruslan Nigmatullin <euroelessar@yandex.ru> - 2.26.3.8
- logger: Log io/c/indexes/cfg flags with names
- node: Print cfg flags on start

* Wed Aug 20 2014 Ruslan Nigmatullin <euroelessar@yandex.ru> - 2.26.3.7
- client: Added ability to construct session from dnet_node
- server: Make possible to send request yourself
- cocaine: added read_latest to elliptics service
- server: Added option.parallel option
- dnet_client: Return non-zero code on fail
- thread: Changed name pattern for threads

* Tue Aug 19 2014 Ruslan Nigmatullin <euroelessar@yandex.ru> - 2.26.3.6
- backend: Read config at backend's start
- logger: Removed useless premature optimization

* Tue Aug 19 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.3.5
- logger: do not even try to process logging if log level is small enough

* Mon Aug 18 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.3.4
- Get rid of foreign/blackhole include dir which can contain old/obscure version of the package

* Mon Aug 18 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.3.3
- Rebuild with the proper blackhole-dev package

* Sun Aug 17 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.3.2
- state: minor cleanups, optimizations and fixes
- stack: print minimum stack size (1M) if current stack size is less than that

* Fri Aug 15 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.26.3.1
- monitor: stat fixes
- backends: added ability to make backends readonly
- monitor: added config stats

* Thu Aug 14 2014 Ruslan Nigmatullin <euroelessar@yandex.ru> - 2.26.3.0
- cache: Added ability to configure backend's cache
- client: Added send_to_each_node
- client: Drop direct_backend flag at set_direct_id
- client: monitor_stat should accept address, not id
- config: Make possible to set io thread num per backend
- config: options.*_thread_num is required field
- example: Removed out-to-dated ioserv.conf
- logger: Don't print destruction packets
- Monitor: Added 'procfs' stats that includes 'vm', 'io' and 'stat'
- monitor&statistics: moved stat_log and stat_log_count statistics to monitoring statistics
- Python: fixed lookup_address and doc strings
- Python: removed session.get_routes()
- Python: removed session.update_status by elliptics.Id
- Python: replaced elliptics.Id by elliptics.Address at session.monitor_stat

* Mon Aug 11 2014 Ruslan Nigmatullin <euroelessar@yandex.ru> - 2.26.2.0
- API: Changed signature of "complete" methods
- backends: Make possible to start several backends per time
- cache: Don't send 2 packets as lookup reply
- callback: Write to log about each processed packet
- client: Added optimization for key's transformation
- client: Added parallel_lookup
- client: Added quorum_lookup
- client: Moved read/write_file logic to c++ binding
- client: Refactored implemenation of handling replies from server
- client: Removed unused client's methods
- client: Returned error from add_state with more sense
- cpp: data_buffer should consider size of counter
- dnet_balancer: fixed error exit when one of real route matches with 00..0 or ff..f
- eblob: Fixed log levels between eblob & elliptics
- Monitor: reorganized monitor statistics from different backends
- protocol: Changed DNET_TRANS_REPLY to DNET_FLAGS_REPLY
- Pytests: added prepare/plain/commit test when it rewrites key from closed blob by bigger data
- Recovery: wrapped os.rename by try/except for catching os.rename exception
- run_servers: added generating monitor section in ioserv config
- run_servers: Write pid of dnet_ioserv's to log
- tests: Added 3 more tests about lookup results
- tests: Generate random trace_id for each test case
- weights: increase temporal selection-only (not state) weights (multiply by 10 on each step) until they sum up into large enough number for random selection

* Mon Aug 04 2014 Ruslan Nigmatullin <euroelessar@yandex.ru> - 2.26.1.1
- logger: Use blackhole's level's formatter
- server: Connect to remotes asynchronously
- net: Fixed race at converting node to server one

* Mon Aug 04 2014 Ruslan Nigmatullin <euroelessar@yandex.ru> - 2.26.1.0
- Python: implemented elliptics.Node.add_remotes which has replaced old elliptics.Node.add_remote
- Pytests: added waiting for appearance enabled backends in route list at test_recovery
- Tools: fixed dnet_recovery
- cocaine: Connect to all remotes simultaneously
- indexes: Fixed shard id & count values in secondary indexes
- backends: Added more logs about init/cleanup
- net: Fixed connection to server with big ids files

* Sun Aug 03 2014 Ruslan Nigmatullin <euroelessar@yandex.ru> - 2.26.0.4
- library: Fixed race of creating dht states
-

* Sun Aug 03 2014 Ruslan Nigmatullin <euroelessar@yandex.ru> - 2.26.0.3
- route: Add states after join_request to dht_list
- library: Added really asynchonous add_remote_state
- library: Reimplemented reconnection thread
- * Now it makes reconnection and route list requests simultaneously, which gradually decreasis time of this operations with low-latency network
- net: Removed autodiscovery support
-

* Fri Aug 01 2014 Ruslan Nigmatullin <euroelessar@yandex.ru> - 2.26.0.2
- Fixed version

* Fri Aug 01 2014 Ruslan Nigmatullin <euroelessar@yandex.ru> - 0.6.0.2
- client: Added is_final field to result_entry
- client: Added new filters for entry::is_final
- client: Fixed bulk operations
- client: Fixed time formatting in file_logger
- dnet_client: Long live, dnet_client
- indexes: Fixed set_indexes in multibackend systems
- linking: Fixed linking errors at Fedora 20 and Ubuntu Lucid
- logger: Updated for blackhole-0.2.0-0rc2
- Monitor: made monitor section in config for dnet_ioserv and added new history_length and call_tree_timeout to the section.
- pytests: Fixed test for existen filters
- python: Fixed signature of Logger.log
- server: Do not kill own state because of timeout

* Wed Jul 30 2014 Ruslan Nigmatullin <euroelessar@yandex.ru> - 2.26.0.1
- config: Moved to usage of dynamic_t
- logger: Fixed segfault
- srw: Really, don't send exec to every backend
- protocol: Moved trace_id to dnet_cmd from dnet_id
- * Added trace_bit as command flag instead of special trace_id's bit

* Tue Jul 29 2014 Ruslan Nigmatullin <euroelessar@yandex.ru> - 2.26.0.0
- backends: Ability not to enable backends at start
- backends: Added ability to change backend's ids
- backends: Added API for enable/disable/status backends
- backends: Added defrag API, added fields to status
- backends: Added DNET_CMD_CONTROL_BACKEND command to enable and disable backends
- backends: Added field to know current defrag state, added fields to know about
- backends: Generate ids from /dev/urandom
- backends: Only return defrag_state if possible
- backends: Set direct flag for control and status
- backends: Store current backends' states
- client: Added node::from_raw API
- client: Changed ger_routes signature
- client: Introduced address structure
- Core: made update_status used address for addressing to node.
- Eblob: removed iterate_thread_num specification at eblob_backend.
- elliptics: Added multi-backend support in route lists
- ioclient: Moved to new defrag API
- logger: Moved to Blackhole as logging system
- logger: changed trace_id output to hex.
- monitor: added raw function for removing statistics provider by name. Removed duplicated code.
- monitor: Link with elliptics_client
- node: Fixed more conflicts
- pool: Introduce thread-local queue
- pool: Make io-thread init log more verbose
- Pytest: Added tesing dnet_recovery with all modes.
- Pytest: Added parameters for specifying number of nodes and number of backends that should be run in test cluster.
- Python: Added new interface for supporting multibackends. Used elliptics.Address where it can be used and removed duplicating interfaces. Added new abilities to elliptics.RouteList for working with backend_id.
- Python: Added support backend_id to route list.
- Python: Fixed dnet_balancer and for working with new multibackends route list.
- Python: Removed group_id from elliptics.
- Recovery: made dnet_recovery works with new multibackends route list. Added ability to specifies backend_id (via '-i') when dnet_recovery runs for one node ('--one-node')
- routelist: Added support for DNET_CMD_UPDATE_IDS
- routelist: Don't send ack for route-list request
- routelist: Send only addresses at route tables
- run_servers: Added 'backends' option support
- server: Removed node::id
- server: Separated backend to external structure
- statistics: Added ability to remove providers
- tests: Added sleep in recovery test
- tests: Added test for backend's control
- tests: Apps should write logs to different files

* Mon Jul 28 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.25.6.4
  Thu Jul 28 2014 --> Thu Jul 24 2014 or Mon Jul 28 2014 or Thu Jul 31 2014 or ....
- reconnect: reconnect to addresses which were timed out during connection

* Mon Jul 28 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.25.6.3
  Thu Jul 28 2014 --> Thu Jul 24 2014 or Mon Jul 28 2014 or Thu Jul 31 2014 or ....
- recv: do not dereference data stored in state, since to that moment it can be overwritten by the next command from the same client(socket)
- route: let regular route table update also get route table from nodes explicitly added via dnet_add_state() and helpers
- state: print error if no state has been found for given ID
- version: added check/read functions

* Thu Jul 24 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.25.6.2
- weight: print full weight change, not only first 3 digits
- Logs: changed trace_id output to hex

* Wed Jul 23 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.25.6.1
- state: when (re)creating state after recevied reverse lookup we must copy received address array into this new state
- route: cleaned up debug messages
- trans: cache transaction reply flags to make processing bulletproof against callback which can change cmd->flags

* Tue Jul 22 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.25.6.0
- package: depend on 0.22.0+ eblob which provides range iterators
- iterate: output more useful info about iterated keys
- iterate: added option to parse dnet_balance output file and select ranges which DO NOT belong to selected node and request those ranges from remote node
- dnet_add_state: if we failed to add any remote addr because they already exist in the route table, return 0 to indicate success
- iterator: switched to new iterator scheme where ranges and ctl structure are provided directly into backend. Eblob uses this data to skip ranges in indexes if they are sorted.Eblob: removed iterate_thread_num specification at eblob_backend.
- cmake: install timer.hpp with other headers
- tests: stop after the first test failure

* Fri Jul 18 2014 Kirill Smorodinnikov <shaitkir@gmail.com> - 2.25.5.1
- Recovery: fixed merge index mismatch if some of merging shards have unfilled shard_id and shard_count
- Pytests: turned on exit on first fail to make it easer to find the problem. Used separated log files for all node and client
- IOClient: fixed checking dnet_add_state result

* Sun Jul 13 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.25.5.0
- Let's use Travis-CI to check every commit
- route: new batch request completion logic
- Pytests: added group_id check in result entries
- Added batch connect/listen mechanism
- addr: switched C API to dnet_addr structure
- There is no required() at boost::program_options on lucid

* Wed Jul 09 2014 Kirill Smorodinnikov <shaitkir@gmail.com> - 2.25.4.21
- Python: fixed address group_id in result entries.
- srw-test: fixed signed-unsigned warning
- tests: cleaned up srw timeout test: removed misleading debug output when everything is ok, voided unused variable
- config: removed comment about unused 'do-not-update-metadata' flag
- srw: use full namespace name for ioremap::elliptics::lexical_cast() function
- indexes: Handle failed parsed indexes metadata from msgpack …
- index_perf: added index performance tool
- utils: moved common functions to utils header
- timer: added elapsed timer
- srw-test: moved thread-watchdog class outside timeout test function for older compilers happiness

* Fri Jun 27 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.25.4.20
- trans: ascending transaction number order instead of descending
- trans: new timeout transaction completion logic

* Tue Jun 24 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.25.4.19
- Pytests: fixed test_session_indexes - wait set_indexes/remove_indexes results
- submodule: removed react, started to use git:// instead of http://

* Mon Jun 23 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.25.4.18
- Core: Added unmapping IPv4 from mapped IPv6 address
- client: Added session::recovery_index method
- client: Introduced merge_indexes method
- tests: Docs for test_index_metadata added
- index: More docs for get_index_metadata helper function
-

* Wed Jun 18 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.25.4.17
- Pytests: added testing of index interface: set/update/remove
- Recovery: Added dumping iterated keys to dump file(s) that could be used for resuming recovery after some issues
- Recovery: Fixed splitting ranges in small pieces for merging them in different processes.
-     Replaced pickle with CPickle
-     fixed 'zero length field name in format' bug on Python2.6
-     Added traceback print to exception log
- Python: used one argument for id and context at exec_, made src_key last argument
- Core: fixed hanging up iteration on cond_wait.
-     There was race condition: after successful dnet_send_reply another thread removes the state and before original thread stucks on waiting condition variable.
-     After that no one thread will wake up original thread via broadcasting conditional variable
- Documentation: added docs how merge works with -f/--dump-file
- Recovery: fixed stats group name in merge. Show all key at read/write/merge/remove failures. Fixed exit code in dc.
- Recovery: Added merge recovering the list of keys from dump file
- Monitor: clear m_cmd_info_current after swap
- Recovery: Enabled -r reusable (so you can specify several remotes). -o should be followed by adress of node that should be processed

* Fri Jun 06 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.25.4.16
- spec: do not require boost libraries, they will be populated from devel package version
- debian: do not install libelliptics_cocaine.so.*, it is being built statically now
- Don't link with json
- spec: added libtool-ltdl-devel dependency for cocaine
- spec: added libev dependency for cocaine

* Thu Jun 05 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.25.4.15
- srw: Added commentary about event's naming
- library: made dnet_request_cmd() non-blocking
- rpm: Enable build with Cocaine
- srw: Removed app@ part from Cocaine event
- tests: Check status code for every entry in bulk_write
- tests: Don't use ports from ip_local_port_range

* Tue May 20 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.25.4.14
- build: depend on 0.21.40+ eblob to force double eblob size reservation
- io: do not proceed IO command to backend if cache-only IO flag has been set
- ioserv: exit with negative error status if ioserv could not start because of config error
- config: updated blob flags doc
- build: remove generated pyversions at clean
- build: removed deprecated XB-Python*. Updated url at setup.py.

* Thu May 15 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.25.4.13
- state: new weight adjusting mechanism

* Tue May 13 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.25.4.12
- rpm: fixed msgpack for python package name.
- core: request route list from node after reconnect.
- debian: fixed build on lucid: there is no dh_python here and we have to use python-central.
- debian: dh-python instead of python-support
- Core: fixed requesting route list always from the same node per group.
- Recovery: Added msgpack-python to dependencies.
- Recovery: disabled csum when reading pieces of object.
- cocaine: Improved elliptics-storage configs
-     You can set timeouts for read, write, remove and find
-     You can set success-copies-num to any, quorum or all
- trans: when filling local-io before read completion, we should check transaction allocation size
- monitor: Data race during printing of react_aggregator fixed

* Thu May 01 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.25.4.11
- tests: Add random seed to dnet_run_servers

* Wed Apr 30 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.25.4.10
- build: depend on 0.21.37+ eblob
- Recovery: updated recovery.qdoc: added merge/dc examples.
- debian: react version 2.3.1 update
- Python: turned on srw tests. Removed setting group_id in Session.transform
- stat: react_stat_provider and react_aggregator refactored
- state: change state weight according to io size. do not change weight if it was cache IO
- log: increased format buffer size
- config: example config bool values fixed
- Tests: provide LD_LIBRARY_PATH into execve child
- Cache: added setting n->need_exit before stopping cache: it is used by life_check thread. Tests: fixed moving group into backend section.
- Recovery: added dc_recovery.py - build-in custom recovery function for dc. Added recovery.qdoc.
- Recovery: replaced dc by sdc. Added ability to split big files while merge recovery (dc recovery will get it soon).
- session: when creating new session setup wait-ts from the node
- config: Fixed config example
- config: Reimplemented configuration parser
- route: lower final route reply message log level
- tests: Pass envs directly to executable

* Fri Apr 25 2014 Ruslan Nigmatullin <euroelessar@yandex.ru> - 2.25.4.9
- tests: Configure run_servers by envvars
- rpm: Add dependency on libblackhole

* Fri Apr 25 2014 Ruslan Nigmatullin <euroelessar@yandex.ru> - 2.25.4.8
- Don't set rpath for dnet_run_servers

* Fri Apr 25 2014 Ruslan Nigmatullin <euroelessar@yandex.ru> - 2.25.4.7
- Upped elliptics version

* Fri Apr 25 2014 Ruslan Nigmatullin <euroelessar@yandex.ru> - 2.25.4.6-1
-
- Fixed package details

* Tue Apr 22 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.25.4.6
- Core: stops threads before joining them in case we got some error while creating node.
- tests: Added fork and monitor options to dnet_run_servers
- API: Removed most of const_cast's uses. Added move semantic to async_result
- package: Places binaries to correct packages

* Thu Apr 17 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.25.4.5
- Python: fixed pickling elliptics.Id

* Wed Apr 16 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.25.4.4
- Core: added broadcasting send_wait on state removing.

* Fri Apr 11 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.25.4.3
- trans: only log IO transactions if it was correctly allocated and initialized

* Wed Apr 09 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.25.4.2
- debian: elliptics-dev should depend on react-dev

* Fri Apr 04 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.25.4.1
- route: added route update timing
- doc: Added documentation for secondary indexes
- client: Add headers to sources list
- rpm: depend on react-devel instead of react-dev
- log: Fixed removing of last char if it's not \n
- cmake: get rid of the rest of react static build
- cmake: elliptics_react is compiled into elliptics_monitor
- tests: Fixed data sent to dnet_start_servers
- log: trace_id_t typedef added for easy editing trace_id type
- Iterator: added resetting skipped_keys if it founds proper key.
- Python: added ability to use dict with bulk_write. Pytests: separated test_session into several test_session_* tests that covers subfeatures. Added bone for testing indexes, iterator and monitor&statistics.
- Iterator: added sending keepalive iterator response with status=1 when 10K keys are skipped in a row.
- Iterator: added total and iterated keys counters to iterator response.
- Python: added push and reply.
- cache: setting total_size
- Python: Replaced inheritance elliptics_id from key by dnet_id aggregation that simplifies using elliptics.Id.
- build: depend on 0.21.32+ eblob
- Python: Added add_to_capped_collection to python binding. Added logging Handler that outputs logs into ellitpics.Logger.
- client: added documentation for indexes
- react: Error handling on react creation in dnet_process_cmd_raw changed.
- Do not request route list in reconnect thread if node flags contains DNET_CFG_NO_ROUTE_LIST. Added ability to set node flags in dnet_ioclient by '-f'.
- log: finally made dnet_id loggers thread-safe - allocate per-thread temporary buffers instead of plain static
- spec: turn off cocaine support, there is no cocaine core RHEL RPM yet
- python: CMake fixed to use the same version of python
- tests: python Overflow test boundary for trace_id changed to 2**64
- core: trace_id migrated to uint64_t
- tests: Elliptics in python tests migrated to json.
- foreign: React is now shared library.
- tests: Check the value of srw in run_servers

* Thu Mar 27 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.25.4.0
- spec: get rid of <=5 rhel, added cocaine depend
- tests: use only bindable ports for test servers
- Pytests: restored copying required libraries from build to pytests.
- cmake: elliptics client must be linked as c++ object because of monitoring support
- core: fixed compilation errors on lucid/precise
- Fixes: deletes scope after lock_guard is destroyed. Turned off srw tests in pytests.
- Tests: decreased number of threads for each server node. Fixed checking number of init exec's results.
- Monitor: fixed memory corruption in histogram.
- react: Fixed memory corruption/leak
- tests: Added monitor_port to json output
- client: Fixed reading outside of vector on debug
- config: Added pretty output on parsing error
- pytest: do not try to destroy server object if it failed to start
- run_servers: init application at all nodes
- foreign/react: moved reacrt into foreign dir
- foreign/blackhole: updated to master
- config: updated example ioserv config
- cocaine: Fixed parsing of remote nodes list
- Tests: fixed generating srw config.
- react: Checks in react for turned off monitoring added
- dnet_ioserv: changed configuration format to json
- cocaine: Added ability to set list of remotes
- Pytest: used dnet_run_servers at pytests.
- Core: Actions monitoring added
- Monitor: react_stat_provider for exporting react call tree into monitoring added
- trans: also print total size for IO commands when transaction has been processed on server and destroyed on client

* Wed Mar 19 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.25.3.0
- trans: added IO debug into dnet_process_cmd_raw() and to transaction destruction
- common: get rid of years unused history maps. Convert IO time in dnet_convert_io_attr()
- client: Don't throw exceptions on log errors
- tests: Added run_servers binary
- Build: added libelliptics_monitor.so to client files in spec.
- Session: added checking groups list for emptiness at iterator operation.
- Log: removed duplicating log from monitor.cpp. Added dnet_log_raw_log_only and dnet_log_raw_internal. Made dnet_log_raw to use dnet_log_raw_internal.
- Pytests: Turn off pytest recurse discover for tests.
- Tests: added generating monitor ports.
- Monitor: Added printing error message when monitor initialization is failed.
- Build: fixed build on rhels - made elliptics_monitor shared library
- node: get rid of unused is_valid() method
- Pytest: specified python path at calling virtualenv.
- blob: removed unneeded compression check
- build: Compilation fixes. Missing define added. 'source' not found in sh
- Code: added python binding references to code.
- Pytests: renamed WITHOUT_COCAINE to PYTESTS_FLAGS.
- Monitor: removed duplicated code of requesting statistics, monitor statistics and common dnet_request_cmd. Temporarily disabled srw test in pytest.
- monitor: added category safety checks
- build: depend on 0.21.31+ eblob - it adds proper backend statistics
- monitor: fixed packing
- Monitor: added to elliptics protocol ability to request monitor statistics. Added appropriate methods to C++ and Python bindings.
- cache: Redundant monitoring actions removed
- Monitor: Moved io statistics provider to c++ code. Added per state statistics to io statistics.
- Monitor: added projet root dir to include directories. Hid monitor initialization into dnet_node_alloc.
- Monitor:
-     Added monitor to export for using it with elliptics-client
-     Added status of io pool: blocked or not
-     Added statistics about output queue: current size and total count
-     Removed monitor dependency from node
-     Added statistics provider for io pools and output queues
-     Removed rwlock from monitor
-     Used timestamp of statistics request instead of elapsed time from previous request
-     Removed clearing commands history after each statistics request
- Monitor: Changed name 'io_queue' to 'io'
- CMake: fixed indent in some CMakeLists files.
- Pytests: removed exception strings from checking because they depend on the boost python version.
- Pytests: added dependency from python-virtualenv.
- Pytests: used virtualenv for installing and runnig pytest.
- Pytests: fixed runtime property in cocaine config.
- Pytests: Used pip for pytest installation because python-pytest is not available on pure precise, lucid and rhel 5/6.
- core: added possibility to set tcp keepalive parameters to client connections
- Pytests: added comparing set of flags known and provided by module.
- foreign: react submodule updated
- Core: provided address to sph, Pytests: fixed fails on checking address from ExecContext.
- cache: only log constructor/lock/unlock if times spent is more than 1 ms
- Python: fixed calling final handler for AsyncResult.
- Pytests: fixed executing cocaine-tool app upload.
- Pytests: Merge current Python API tests with ijon test_exec. Added starting Elliptics node with srw and uploading and starting test app in it.
- Python: Added ability to set data=None with exec_.
- stall: changed default reset-stall-count from 5 to 3
- stall: fixed stall counter reset. Decrease timed out state weigth by 10 instead of 2.
- stall: reset stall counter in transaction destructor if transaction hasn't timed out
- cache: added comment about zero-sized lookup reply
- Cache: Lookup in cache is always going to disk.
- IOClient: provided cflags in READ io command created by read_file.
- Recovery: Added to merge statistics 'local_remove_old*' counters that contains information about keys which were removed without copying because they contain old data of krmation about keys which were removed without copying because they contain old data of keys.
- tests: Cache lru eviction test doxygen description added
- tests: check of correct test configuration added
- tests: Test for lru eviction scheme added
- cmake: Project root added to include directories.

* Tue Feb 18 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.25.2.0
- build: depend on 0.21.30+ eblob where react monitoring support added
- Monitor: Backend statistics provider added.

* Fri Feb 14 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.25.1.1
- tests: Don't run srw tests if srw is disabled
- client: Fixed log output for amd64 platform
- client: Fixes for x86 platform
- tests: Fixed compilation error
- client: Fixed read_latest policy
- cache: decrease log level if cache is not enabled
- tests: added missing header
- cache: define _GLIBCXX_USE_NANOSLEEP to enable sleep_for()
- test: added server library to test-common itself, since it uses them
- indexes: there is no nullptr on older compilers

* Thu Feb 13 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.25.1.0
- pool: added comment on how client handles replies in multiple IO threads
- tests: Don't make artifacts if test is successfull
- docs: Don't try to install documentation
- cpp: get rid of get_node calls
- Added forgotten doc/Doxy*.in files
- cpp: Changed mix_states behaviour
- file_logger: do not accept default log-level, force client to provide correct one
- Tests: running run_tests.py with proper python.
- logger: logger construction from the interface must *NOT* set default log-level, users should not be tricked here and potentially find out later, that their logging is being done only on INFO and ERROR level
- Monitor&Doxygen: Added doxygen code documentation to monitor.
- read-callback: only run read recovery when we have read the whole object. Added read recovery dbug.
- dnet_io_attr: added total_size field (without ABI changes), which contains total size of the read record.
- reconnect: fixed groups array allocation. limit group array for random selection by 4096 groups
- core: added socket close debug
- client: Added capped collections
- Core: Missed error notification added
- client: Make aggregated to handle empty sequence
- cache: Stop lifecheck thread at node->need_exit
- Monitor: Added extra check that monitor is still alive after acquiring rwlock.
- Core: added checking epoll_events
- Cache: Elements that were removed while being in sync queue don't sync now.
- Cache: Resize page optimization.
- Core: Limited size of io queues to the number of io threads * 1000. Added building iterate.cpp from example to main build without installation.
- Cache: fixed size stats counting for deleting objects
- Monitor: json allocator for dynamic string added
- Cache: syncing to disk during requests to cache removed
- Cache: Append optimization added
- Cache: concurrent_time_tree, erase from page, time_tree difference
- Cache: Life check sleep time adjusts to system load
- Cache: Action names refactored. New actions added.
- Cache: Actions set added.
- Cache: time_stats doxygen documentation added
- Cache: Copy of data before sync added
- Cache: multiple bugfixes

* Fri Jan 24 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.25.0.0
- Python: Fixed typo in docstrings.
- Python: added ability to clone session.
- Python: Fixed pep8 warnings in setup.py. Added dnet_balancer to elliptics-client package.
- Python: added keeping node inside python elliptics.Session to insure that session will be deleted after node.
- Python: added (re)balancing ids script
- trans: randomize route table update: select 5 random groups and read table from one random node from each selected group
- Python: bugfixes
- rpm: added make test
- doc: Added documentation generation by doxygen
- Utils: Introduce argument_data
- tests: Add data_buffer test case
- Utils: Optimized data_pointer behaviour
- tests: Moved API checks to external test file
- Monitor: Added ability to extend monitor statistics via custom statistics providers.
- srw: Don't call cocaine::app_t::stop on stopped apps
- Monitor: Made elliptics_monitor as shared library.

* Wed Dec 25 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.15.0
- cache: treap implementation, cache distribution changes
- monitor: initial implementation
- python: filters and checkers
- index: remove implementation
- tests: new srw test, moved to new testing framework

* Thu Dec 19 2013 Ruslan Nigmatullin <euroelessar@yandex.ru> - 2.24.14.36
- cache: Improved hash function in cache
- * Use last 8 bytes in addition to first one. Otherwise all keys for specific shard comes to single cache object.
- Python: Fixed accepting IoAttr instead of Id in read/write operations. Fixed overriding write_data by write_data_by_chunks.
- Python: Provided Error, NotFoundError and TimeoutError directly from elliptics module. Removed hiding elliptics.core module.

* Wed Dec 11 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.35
- socket: alot of debug and double-close checks

* Wed Dec 11 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.34
- python: Acquire GIL in python binding in async_result::get()
- config: update reserved fields to maintain proper ABI structure size
- Python: Updated docstrings for binding
- Merge recovery: changed statistics name to clearly separate remote and local request counters
- Recovery: fixed removed_bytes in statistics for keys which hasn't been copied because proper node already has newer keys datas
- Recovery: fixed removed_bytes in statistics for key which hasn't been copied because proper node already has newer key data

* Thu Dec 05 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.33
- Recovery: Added -o option to merge which limits it to one node.
- Recovery: Replaced merge by deep_merge with removing of the last. Used FileHandler without rotation for dnet_recovery logs.

* Thu Dec 05 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.32
- Filters: Fixed filters::all filter
- IDS: Added config flag which turns on saving and recovering ids from elliptics cluster.

* Wed Dec 04 2013 Kirill Smorodinnikov <shaitan@yandex-team.ru> - 2.24.14.31
- Recovery: Added clearing AsyncResults in handlers to prevent cross-links to objects. Minimized sending statistics.
- Python: fixed memory leak and GC problem with using connect to AsyncResult.
- Recovery: fixed inverting node ranges in deep_merge.
- Recovery: Updated logs for deep_merge. Added parameter '-z' for setting one log file size which would be rotated.
- Recovery: Extended logs for deep_merge.

* Mon Dec 02 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.30
- Recovery: added handling safe flag which turns off removing key from unproper node.
- Recovery: added returning result from deep_merge.
- Recovery: added attempts to lookup/read/write/remove.
- Recovery: Rewrited deep_merge. Now deep_merge is synchronization keys within group all nodes at once. More details: http://doc.reverbrain.com/elliptics:replication.
- Python: Removed debug code.
- Python: Removed elliptics.Data and uses python string instead of. Fixed specifying object method as callback for elliptics.AsyncResult.connect.
- Python: elliptics.Data added to_string and __repr__ methods which returns string representation of internal data
- Python: changed counters output to dict.
- Build: Fixed compilation errors on Lucid

* Wed Nov 27 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.29
- Python: fixed counters in stat_log_counter. Core: Added const to input parameter in dnet_server_convert_dnet_addr
- Python: Fixed crash on requesting address/group_id from result entries.
- session: transform() should accept const session, since it doesn't modify it
- cache: scream loudly if cache operations with lock taks more than 100 ms
- Test: Use random ports for servers
- Python: fixed typo.
- cache_pages_number param added
- slru_cache refactored
- Caches_number configuration param added.

* Sat Nov 23 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.28
- state: fill state with 0xff prior its freeing for debug
- state: guard dnet_schedule_recv() with st->send_lock. dnet_schedule_send() is already guarded.
- state: s/need_exit/__need_exit. Prevent socket shutdown if __need_exit is set.
- state: when adding new state check reverse-lookup data, fail to add new state if wildcard address (like 0.0.0.0) has been received
- state: added more debug into just-connected-to address and its route table
- state: do not copy n->addrs -> st->addrs for joining but not listening states
- Python: added method for getting name of command.
- Build: Added egg-info files to rpm spec.
- Build: Fixed build on RHEL5/6.
- Python: provided group_id in address returned by some result entries. Restored counters in AddressStatistics.
- CMake: Don't export Elliptics package

* Tue Nov 19 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.27
- debian: do not depend in runtime on source-version
- CMake: Include Targets file from Config.cmake
- Build: fixed copying python scriptcs on RHEL5/6

* Mon Nov 18 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.26
- spec: depend on 0.21.26+ eblob for statistics
- Build: Moved redifining of __python at the top of spec file for rhel < 6.
- Build: Fixed build on RHEL5 and restored recovery and python bindings scripts in rpms.
- stat: added DNET_CNTR_NODE_FILES_REMOVED counter. It is only filled in eblob backend.
- cmake: export ELLIPTICS_LIBRARY_DIRS
- License: Change license from GPL to LGPL
- Core: Added public dnet_digest_*transform methods

* Sat Nov 16 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.25
- core: forbid route table update with 0.0.0.0 addresses

* Fri Nov 15 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.24
- core: added route/address debug
- Python: Use ${PYTHON_EXECUTABLE} in cmake scripts

* Wed Nov 13 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.23
- io_client: Call wait() to async_remove_result
- Stat: In eblob statistics used DNET_CNTR_NODE_FILES for number of available records in eblob.
- Client: Some fixes connected with move semantic

* Wed Nov 13 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.22
- net: copy all addresses into joining state
- Cocaine: Don't link with eblob
- CMake: Added EllipticsConfig.cmake
- Client: Add valid logging to bulk callbacks
- Indexes: Use enum for versions instead of raw ints
- Cocaine: Fixed duplication of files' in find result
- Server: Fixed segfault at exit
- crypto: fixed undefined dnet_offsetof macros usage
- Recovery: Added deep_merge recovery type. Updated docs for recovery.
- Build: Fixed missing python wrapper around elliptics.core.
- Indexes: Added comments to flags
- Indexes: Comments for remove_index_callback
- Indexes: Added session::remove_index_internal
- Indexes: Added ability to remove objects from indexes
- Indexes: Send bulk request only if server knows it
- Use data_pointer::allocate in callback_p.h
- Core: Add \n to end of message at logger
- indexes: Added bulk-behavior to find_indexes
- Python: Fixed get_address_ranges
- Python: Fixed __init__.py
- Python: provided python level log based on logging.
- Cpp: Extended comments and notes about write_prepare, write_plain and write_commit.
- Cpp: fixed write_data by chunks.
- Relicense Elliptics under LGPL

* Mon Oct 21 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.21
- Added more debug info for cache requests.
- Fixed bulk_read request.
- Fixed bug on cache overflow.
- Client: fixed write_data by chunks.
- Python: got data_pointer inside python binding as elliptics.Data. Removed restrict of using bp::list - now you can use any iterable object for those purpose.
- Added example script and c++ code for iterating specified nodes or all nodes in specified groups
- Removed useless code.

* Tue Oct 15 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.20
- Put man pages into packages
- Do not schedule network IO if state is in need-exit state
- Use correct session::remove() method
- Build: Fixed prefix in executing setup.py
- Do not write timestamp for read requests, it is meaningless in request.
- Added dnet_send_read_data() timings
- Python: Set default timeouts in elliptics.Config
- Python: Unlock GIL inside synchronous calls

* Tue Oct 08 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.19
- Recovery: fixed skipping equals objects in diff
- Recovery: Fixed sorting and diffing objects.
- Python: fixed bulk_write

* Tue Oct 08 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.18
- Minor python binding cleanups

* Mon Oct 07 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.17
- Added size to dnet_iterator_response
- Python: if both key and timestamp is equal then size will be checked and larger object will be restored.
- Python: fixed is_none() for boost v1.40 compatibility.

* Mon Oct 07 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.16
- Python binding rewrite

* Fri Sep 27 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.15
- Return EXFULL from srw->process() if srw/cocaine enqueue/write throws an exception.
- State reset should cleanup all transactions.
- Added elliptics tool man pages. Removed obsoleted documentation.

* Thu Sep 26 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.14
- ioclient must return non zero on exec (and other commands) error
- Stall check debug code

* Thu Sep 26 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.13
- Added cocaine-elliptics service stub
- Little optimization for raw_data_pointer comprasion
- Removed debug check read in update_indexes_internal

* Tue Sep 24 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.12
- Added commentary about sync_element usage in life thread
- Added locks around sync block in life check thread
- Improved update_indexes_internal perfomance
- Comment out unused method parameters.
- Made dnet_state_reset() log high enough not to spam in default cleanup path

* Wed Sep 18 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.11
- Add reconnection address if connection has been reset
- session::push must clear reply flags
- Added bulk read support for module backend
- Fixed test_iterator.py: fixed error with IteratorRange initialization
- config: improved documentation
- config: added new knobs and their description
- eblob: added defrag_time and defrag_splay knobs
- debian: bump eblob dependency

* Sat Sep 14 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.10
- Added stall/timed out transctions check
- Added callback machinery debug
- Print trace id as part of thread-id/pid chunk
- Moved trace_id into TLS
- dnet_usage() text cleanup
- Initialize err before dnet_add_state_socket() call

* Thu Sep 12 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.9
- Moved stall transaction processing into dnet_io_process(), where it can be done without races.

* Thu Sep 12 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.8
- Fixed incorrect state used in timed out transactions cleanup
- Returned back state reset in auth/reverse lookup

* Thu Sep 12 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.7
- Do not reset state in auth/reverse lookup commands

* Wed Sep 11 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.6
- We have to use list_for_each_entry_safe() when moving object from list being iterated.

* Wed Sep 11 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.5
- Put/complete stalled/timedout transactions on error not under state_lock
- Revert "Merge pull request #217 from shaitan/trace"
- Get rid of libelliptics_module_backend_cpp.so in elliptics spec

* Tue Sep 10 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.4
- Added trace_id to dnet_backend_log. Added DNET_TRACE_BIT for ignoring current log level for traced request.
- Added printing begin and end of id in dnet_dump_id_len
- Made elliptics compatible with current eblob version.
- Added comments to eblob compatibility solution.
- Renamed back dnet_trace* to dnet_log.

* Fri Sep 06 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.3
- Destroy timed out transactions in checking thread.
- Correctly kill state with errors in it.

* Tue Sep 03 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.2
- Cleanup dnet_state_reset() calls - generally it is not allowed to 'put' state's refcnt from arbitrary place
- Use char * in open() call

* Fri Aug 30 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.1
- Forced rpath option for dnet_cpp_test
- Do not set read/write sockets to -1 until they are closed
- Added clearing syncset and lifeset in cache_t destructor

* Wed Aug 28 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.14.0
- LTS release

* Tue Aug 27 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.35
- Added tests for lookup and prepare_latest
- Fixed prepare_latest command
- Added support for cache lookup command
- Added local_session::lookup
- Fixed session::clone in case of empty groups

* Tue Aug 27 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.34
- Instead of resetting network state just close its sockets
- Get rid of unneeded code in stall transaction check thread
- Split check/reconnect logic into two separate threads
- Added update_indexes and update_indexes_internal to python binding
- Do not spam logs if cache is not turned on
- group description update
- Added basic dnet_print_time() helper (not thread-safe)
- Long line/whitespace cleanups

* Sun Aug 18 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.33
- Added new map typedefs
- Added iterate.py. Script for counting legal/hidden records on elliptics node by iterator
- Added iterator support for module backend
- auth_cookie documentation update

* Wed Aug 14 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.32
- Do not use already removed 'id_range' in debug messages

* Tue Aug 13 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.31
- Fixed getting recovering node group id from routes when groups is specified. Added ability to specify groups for recovering.
- Restored lost mk_container_name import

* Mon Aug 12 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.30
- Fixed unexpected exit after iteration stage if local node is empty
- Proper support for session::exec in python binding
- src_key and quiet options for exec (-c) command
- Use log-level DNET_LOG_DATA instead of special 'quiet' log output mode
- Initialize convert_usecs to prevent unintialized usage

* Wed Aug 07 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.29
- Updated dependencies

* Tue Aug 06 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.28
- Restored get_address_group_id
- Removed eid and id_range from IteraterResult. Used sha256 from address instead of id_range@eid.

* Tue Aug 06 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.27
- tests: added more append tests
- Send srw reply on upstream::close() to client.
- Reset connection on server's side if versions mismatch
- Provide error into dnet_state_reset()

* Thu Aug 01 2013 Ruslan Nigmatullin <euroelessar@yandex.ru> - 2.24.13.26
- Fixed zero data for indexes_internal in case of no changes

* Thu Aug 01 2013 Ruslan Nigmatullin <euroelessar@yandex.ru> - 2.24.13.25
- Added dnet_indexes_reply for internal commands

* Thu Aug 01 2013 Ruslan Nigmatullin <euroelessar@yandex.ru> - 2.24.13.24
- Added session::update_indexes method
- Fixed groups mix in case of key generated from id

* Thu Aug 01 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.23
- Use pointer logic in indexes. Only drop lock (and do not unlock at the end of dnet_process_cmd_raw()) if we are not going to send ack right now.
- Use 0xHEX string instead of just HEX
- Use dnet_time structure in dnet_time_before/after functions

* Thu Aug 01 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.22
- Moved dnet_time_before/after into public header

* Wed Jul 31 2013 Ruslan Nigmatullin <euroelessar@yandex.ru> - 2.24.13.21
- Fixed using of mix_states for DNET_CFG_MIX_STATES

* Tue Jul 30 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.20
- Added reconnection logic debug
- Fixed invalid error for read in case if there is no state
- Do not mess with command flags, instead unlock/lock key
- Added little optimization for cache

* Tue Jul 30 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.19
- recovery: fix container creation in merge
- recovery: removed unused get_address_ranges()
- recovery: merge: do not fail on single error
- recovery: fixed computation of recovery ranges
- recovery: actualize comments

* Tue Jul 30 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.18
- Optimization for append to cache

* Tue Jul 30 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.17
- Fixed endless syncing to disk the same file

* Tue Jul 30 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.16
- Run low-level backend commands without cache lock

* Mon Jul 29 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.15
- Fixed removing from disk if cache is empty
- Added more debug info to cache
- Added delayed sync to disk in cache
- Use nonblocking pool for the appropriate commands

* Mon Jul 29 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.14
- Added checksum and timestamp to write result for cache
- Fixed returning of lookups on IO_CACHE requests

* Sat Jul 27 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.13
- Fixed error codes for bulk_read and read commands

* Fri Jul 26 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.12
- Added metadata support to cache
- Refactored cache support, added offset/append support
- Return offset within fd in write reply structure
- Do not try to redefine O_LARGEFILE
- libcocaine-plugin-elliptics should depend on elliptics client's source version
- Do not turn on cocaine support in RHEL builds
- Use ~0ULL instead of ULLONG_MAX, otherwise it is broken on rhle5
- Moved local_session to separate file
- Do not use randomized states by default, use sequential groups order

* Wed Jul 24 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.11
- Optimized merge algorithm in dc recovery

* Tue Jul 23 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.10
- Inherited elliptics_id from key. Fixed places where elliptics_id is used.
- Removed boost python class declaration for remove_result_entry.

* Mon Jul 22 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.9
- Set timestamp to -1/-1 on session creation;
- Copy timestamp on session clone;
- Get timestamp from mtime when writing via write_file;
- Use half-open interval for key range intervals;
- Added test for APPEND|PREPARE case;
- Improved logging in eblob backend write path;
- Comment improvements.

* Sun Jul 21 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.8
- recovery: monitor: add IPv6 support
- recovery: remove entries after successful recovery
- python: added async remove()
- it: remove file based implementation
- it: more robust dnet_iterator_create()
- it: fix leak if destroyed via dnet_iterator_free()
- it: cancel all running iterators on exit
- it: added even more sanity checks
- it: limit number of send replies in queue
- recovery: added 'safe' mode for use in cron
- Refactor version check into separate function. Check version on client too.

* Thu Jul 18 2013 Ruslan Nigmatullin <euroelessar@yandex.ru> - 2.24.13.7
- Fixed compilation error

* Thu Jul 18 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.6
- Fixed aborting in case of receiving garbage from server
- Fixed typo at port assignment in dnet_socket_create()
- New automatic tests
- Fixed error code in multigroups requests
- Fixed memory free for dnet_config_data
- Added ability to run several servers in one process
- Used IndexEntry in python bindings for find indexes

* Wed Jul 10 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.5
- Depend on 0.21.2 eblob.
- Use 141 boost.
- Big tests update
- misc: column cleanups
- fs: use PATH_MAX for path size
- fs: use EBLOB_AUTO_DATASORT for metadata blob
- Input io queue stats collection and periodic logging
- Restored localhost in test_index.py
- eblob: reformatted range requests
- recovery: added doc link
- recovery: fixed recovery script description
- dnet: simplified dnet_iterator_start()
- recovery: Added waiting writes in after each batch

* Tue Jul 09 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.4
- Fixed permanent "connection refused" server coma condition
- Use 153 boost in spec. Depend on 0.21.1 eblob.
- Fixed handling of errors in multigroup callback

* Mon Jul 08 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.3
- Fixed sending server's shard count to client
- Added "inline" attribute to debug ostream methods
- Renamed async_update_* to async_set_*. Renamed python methods
- Added more logs in find_indexes_functor
- Added logger::print method for printf-like logging
- Changed algorithm for generating indexes id

* Mon Jul 08 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.2
- Changed algorithm for generating indexes id
- Added receiving of indexes shard count from server
- Fixed timeout on error during indexes processing

* Sat Jul 06 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.1
- Added shard count into config file

* Fri Jul 05 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.13.0
- New shared secondary indexes

* Thu Jul 04 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.12.0
- elliptics: Use eblob's new BLOB_DISK_CTL_EXTHDR flag and writev()-like API.
-   This moves most of metadata complexity from elliptics backend to libeblob
-   NB! This is very complex change - needs excessive testing;
- elliptics: Removed leveldb backend along with snappy dependency;
- elliptics: Fixed read with offset/size specified;
- elliptics: Cleaned up leftovers from compression removal;
- elliptics: Added tests for reads/writes with offset and size specified;
- recovery: Simplified output for most counters;
- recovery: Fixed python 2.6 compatibility;
- recovery: Usability improvements;
- recovery: Added computation of hash ring % in merge mode;

* Wed Jul 03 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.11.0
- Added percentage dump, help and other params to route table stats script
- Fixed bytes in recovery statistics. Removed old 'dc' script and renamed 'dc2' to 'dc'.
- Fixed merge
- Added time finished to stats after merge
- Encode server's version in reverse lookup command. Print it if server returned error.
- Introduced elliptics version in the initial handshake. If major versions mismatch (like 2.24 vs 2.23), then connection fails.

* Mon Jul 01 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.10.5
- Temporarily disable module backend build on rhel6
- Added `remove_on_fail` error handler
- Removed debug print from IteratorResult.merge

* Sun Jun 30 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.10.4
- Explicitly stop engine upon dnet_app_t destruction
- Expose fine-tuning knobs in Cocaine extensions
- Use generic cocain::error_t instead of removed cocaine::configuration_error_t

* Thu Jun 27 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.10.3
- Major recovery update: cleanups, performance, fixes
- Minor API extensions
- Python API extensions

* Tue Jun 25 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.10.2
- Fixed data corruption due to indexes workflow

* Mon Jun 24 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.10.1
- Uncomment module backend in rhel builds
- Fixed error handling in case of invalid indexes internal data
- Changed error codes to errno in elliptics service
- Added elapsed time to async_result. Cleaned up code.

* Mon Jun 24 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.10.0
- backends: fixed compatibility with new blob APIs
- Fixed compatibility with cocaine
- Depend on 0.10.5-5+ cocaine

* Fri Jun 21 2013 Ruslan Nigmatullin <euroelessar@yandex.ru> - 2.24.9.4
- Added json format to monitor
- Added generic AsyncResult to python binding
- Fixed memory leak on write/lookup
- Fixed dc2. Added skipped keys while reading into monitor statistics

* Fri Jun 21 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.9.3
- When using named workers add unique name to them, so that they are cluster-wide unique
- Fixed cache destructor

* Wed Jun 19 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.9.2
- Fixed python_read_result_get

* Wed Jun 19 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.9.1
- Get rid of blob_cache_size unsupported config option
- Get rid of last column/type appearance in elliptics python binding
- Added missed monitor.py. Optimized monitor output: leave only important counters and timers.
- New exec() variant which gets id and src_key from existing exec_context.
- New method in exec_context to retrieve src_key from underlying sph.
- Fixed friend and forward declarations of exec_context_data
- Whitespace cleanup and indentation fixes
- Added bulk_read_async and write_data_async and added iterating ability to returned results. Fixed bugs
- Fixed errors handling in async_result_handler::complete
- Added ready for async_result. Added extra write_data
- Added recovery type to monitor statistics output. Changed apply_async to imap_unordered.
- added backends.h to install(FILES ...) in CMakeLists.txt
- Fixed output for stats: increased width. Added sending monitor info from dc script
- Added comment and record to log when interrupting iterator.
- Added generic monitoring and dc2 monitoring impl.
- Added interrupting iterator execution on server-side if client connection has been closed.
- Added empty C++ merge method. Fixed run_iterator in dc2
- python: major update to remove type/column
- Returned 2.20.*.* namespace behaviour
- Added session::find_any_indexes
- Fixed BULK_READ server implementation
- python: s/boost::python::/bp::/g
- python: removed unnedded 'using namespace'
- recovery: cleanup after type removal
- recovery: dc: dc2: fixed exception on container load
- dnet: use proper error code on empty route table
- recovery: use lock by default
- recovery: dc: dc2: use proper direct API
- Removed meta methods from module_backend
- Removed sync read and write methods
- Removed dnet_id.type. It was legacy
- Removed DNET_ATTR_DELETE_HISTORY and DNET_ATTR_META_TIMES
- Removed example/hparser
- Removed legacy meta/check/recovery/iterate support
- Fixed typo in cocaine storage service exception
- Added handling Ctrl+C in dc2
- ioserv: unblock SIGQUIT and SIGTSTP
- recovery: remove lru_cache from node and session
- dnet: fix DNET_FLAGS_DIRECT flag behavior
- recovery: added posix_fadvise to sort
- Added skipping equal keys while computing differeneces.
- Added support for the writing chunk by chunk
- recovery: properly catch SIGINT
- recovery: renamed collisions with python builtins

* Tue Jun 04 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.8.1
- Correct service protocol must be derived from extension class

* Mon Jun 03 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.8.0
- Added cache and bulk methods to elliptics service
- Depend on cocaine >= 0.10.5, not counting prereleases
- Added note about timeout option for write_cache
- Fixed indentations
- Optimized dc.py. Added 'no-exit' parameter.

* Mon Jun 03 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.7.9
- Fixed srw/ctx destruction issues

* Mon Jun 03 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.7.8
- Speed up server stop, by setting need-exit flag for all cache threads bfore joining them one after another.
- Fixed state destruction, which happened befor context_t destruction, which in turn calls logger.

* Sun Jun 02 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.7.7
- Fixed n->io thread control initialization race
- Fixed IO thread selection logic
- Get rid of unneeded code and variables

* Sat Jun 01 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.7.6
- Fixed several leaks on close/destruction path

* Sat Jun 01 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.7.5
- added elliptics_module_backend_cpp.so to elliptics-dev package
- moved backends.h to include/elliptics, changed CMakeLists.txt to make module backend function properly
- Added recovered_bytes to dc2 statistics. Added wait at the end of recovering.
- Added append_rr method to IteratorResultContainer - added response to container. Swapped processName and levelname in recovery logs.
- Added file name to iterator. Optimized get_local_ranges_by_address(). Fixed dc2 for multi-range single-result-file iteration.
- Added forgotten adding NOLOCK flag
- Simplified oplocks implementation

* Fri May 31 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.7.4
- Recovery update:
-   recovery: removed statement that have no effect
-   recovery: do not automatically cache node and session
-   recovery: fixed log message
-   recovery: more useful statistics
-   recovery: do not use __wrapped__ method of lru_cached objects
-   recovery: do not propagate elliptics exceptions from subprocess
-   recovery: added dry-run support to merge
-   recovery: merge: use many ranges in single iterator
- eblob: do not call blocking function under mutex, get rid of whole page cache drop for given fd
- Module backend updates

* Thu May 30 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.7.3
- Revert "Temporarily disable srw build and downgrade cocaine dependency"
- Trying to fix oplock deadlock
- Implemented BULK_READ by several READ calls

* Wed May 29 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.7.2.nosrw
- Changed namespace usage

* Wed May 29 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.7.1.nosrw
- Temporarily disable srw build and downgrade cocaine dependency
- Update honest_command_handler_adaptee.cpp
- Update honest_command_handler_adaptee.hpp
- Fixed timeouts in indexes updates
- Update registration.cpp
- Fix typo in printf format for session.cpp
- Fixed remove method in cocaine storage
- Removed acks replies after transaction is completed
- Added --fake parameter to run without recovering.
- Added method for loading iterator results from files. Completed basic logic of dc2 script.
- Do not commit what was already committed by EBLOB_OVERWRITE_COMMITS bit and when size+offset match what should be committed
- Use session's ioflags in bulk operations and when calling find_indexes()
- Updated ioserv config doc. Patch by Sergey Shtykov <bayonet@yandex-team.ru>
- Added dc2 - another variant of data center recovery.
- Separated iterator results by ranges

* Mon May 27 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.7.0
- Use round-robin sph->src_key assignment.
- Added new exec() method which assigns sph->src_key from its parameter
- Get rid of old/unused exec/push - locked/unlocked, use plain exec/push and lock flag from session.cflags
- Save sph->src_key and use it when calculating named worker index, since it will be overwritten for blocked events
- Use src_key as index within array or started (via start-multiple-task) named workers
- Removed dependency on cocaine-framework-native
- Write correctly nulled error string in c++ binding if cmd failed

* Fri May 24 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.6.2
- Do not track cocaine/plugins/elliptics-extensions.cocaine-plugin
- Updated to the latest upstream cocaine version

* Fri May 24 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.6.1
- Added support of multirange iteration. Updated C++ interface for iterator.
- Get rid of number of oplocks config variables.
- Made dnet_parse_numeric_id() accessible to others

* Thu May 23 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.6.0
- Revert "v2.25.1.0", please note that this still breaks ABI compatibility with pre-2.24.6 clients
- Fixed usage of session's wait timeout
- Recovery improvements
- ext: lookup now supports extended format
- ext: optimized blob_read()
- Moved ID locks implementation to RBTree

* Tue May 21 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.5.0
- Dump to stderr if logger interface failed to write data
- Added alpha version of dc recovery
- Added bulk_read and bulk_write methods which provides timestamp and user_flags.
- Update of recovery scripts
- ext: fixed update of extension header

* Mon May 20 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.4.4
- Fixed timestamp bug - do not assign io.num without need - it prevents timestamp to be set correctly.
- Use eblob_read_data_nocsum() instead of eblob_read_data(), since if we wanted, we already checked csum in eblob_read_return()
- Fixed typo

* Mon May 20 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.4.3
- Simplify eblob read/write calls. Get rid of unused elist casts

* Sun May 19 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.4.2
- Depend on cocaine-framework-native-dev (>= 0.10.3~pre1)
- Sync index application to up-to-date framework

* Sun May 19 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.4.1
- Idle 0 means 'never stop' timeout for cocaine workers
- Use local json-trait helper instead of cocaine/detail/traits/json.hpp, which is private

* Sun May 19 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.4.0
- Added named workers support
- Get rid of zeromq
- Do not perform json serialization under lock
- Fixed timestamp in dnet_write_file_id_raw
- Added printing lookup file info in ioclient by parameter -L.
- Added timestamp into session (get/set methods). Copy user flags from session, if it was not set in ctl.io
- Used common method for copying timestamp and user_flags from elist to io_attr.
- Added indexes profile and manifest
- Fixed response() assignment and warnings
- Added set-timestamp() session method
- Added looking for cocaine-framework-native and libev include dirs
- Changed cocaine storage api to second version
- Only set timestamp if it is zeroed
- Depend on cocaine-framework-native-dev

* Wed May 15 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.3.0
- Fill ctl.io.timeout during write
- Added user flags property to session
- Build fix for gcc 4.4
- Returned tags to ellitics cocaine storage
- Moved update indexes implementation to serverside
- Added elliptics service
- ext: eblob: threat old-format records same as non-existent.
- recovery: new subsystem
- Fixed prepare-size with new ext headers
- Added eblob config flag comment
- Added bulk_write to python binding
- Fixed number of bugs found by coverity
- Replace boost::mutex with std::mutex

* Tue May 07 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.2.1
- Fixed IPv6 server addr creation
- Added SRW counters statistics
- Added ipv6 MCAST_JOIN_GROUP socket option.
- Switch multicast autodiscovery from IP_ADD_MEMBERSHIP to MCAST_JOIN_GROUP

* Mon Apr 29 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.2.0
- Link libelliptics like c++ library, since cache and srw are c++
- Always read data (in lookup call path) without checking csum, instead check it in dnet_send_file_info() if special flag is set
- Added cmake option to enable/disable external shared lib (module backend) build
- it: really important note about GC
- it: verify state transitions
- cpp: do not lock key on iteration
- cpp: use proper size on prepare
- Fixed cocaine-to-elliptics loglevel mapping, info level now unified between two systems
- it: python: simplified code
- history: fixed return value handling
- features: bump _XOPEN_SOURCE to 600
- Fixed app@info handler.
- rbtree: clang defines offsetof in stddef.h
- it: prettify comments
- it: added sanity and comments
- it: move flow control to separate subroutine
- it: improve logging
- it: allow flow control of iterators
- test: rework iterator test, added flow control
- it: improved logging
- test: set data flag on iteration
- it: python: formatted IteratorRequest
- it: python: exported id and action
- it: python: added symbolic constants
- it: manage iterator state in elliptics
- it: init iterator_list at start
- it: moved dnet_iterator_list_next_id_nolock
- it: filled dnet_iterator_set_state stub
- it: simplified list mgmt routines
- it: added stubs for iterator actions
- it: added subrotines for iterator state mgmt
- Get rid of static builds

* Thu Apr 25 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.1.0
- Written test for cas.
- Fixed checksum calculation for extended format records used by CAS.
- Fixed append test - now it vefifies result.
- Fixed append of records in extended format.
- Re-introduced missed lock in defrag.
- Grammar nazzism.
- Fixed rhel5 build.
- Reworked RPM packages.

* Tue Apr 23 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.0.0
- Fixed write_cas by adding session::clone()
- ext: check result of dnet_ext_hdr_write()
- blob: use new flag name
- ext: added ext version for future use
- Changed indexes API, separated header to several files
- dnet_ioclient -D should honor size
- Secondary indexes implementation moved from functors to object methods
- Moved to delete declaration of non-copyable objects
- Module backend
- New data iterators
- No need to set size to 0 in dnet_read_file_raw()

* Fri Apr 19 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.23.6.0
- Changed write error report logic
-  Only return wait error (usually -ETIMEOUT/-110) if wait internal
-  status (assigned in write completion handler) was set to something
-  except -ENXIO.
-
-  -ENXIO is set by default and means no transactions were sent
- dnet_schedule_io() should wakeup only one thread when new packet has been queued

* Thu Apr 18 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.23.5.0
- Added data_buffer class that provides possibility to write into data_pointer
- Moved dnet_raw_id logical operations to public_header
- Added raw transform interface. Use it in session class to hash dnet_raw_id.
- Fixed segfault is empty data on cas is OK.
- Changed behaviour of find_indexes. If no result found don't throw an exception, but provide empty list

* Thu Apr 11 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.23.4.2
- Revert module-backend

* Wed Apr 10 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.23.4.1
- Fixed write_cas.
- Fixed reporting about the error if data is already actual

* Wed Apr 10 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.23.4.0
- Added write IO flag, which forces backends not to send file info on write completion
- Added DNET_FLAGS_CHECKSUM cflag - when set, lookup command will send object checksum
- Use functor name in indexes_unpack() to debug exceptions
- session_indexes.hpp cleanup - hide private msgpack kitchen
- Added cache parallelism
- Made cache exception-free
- Changed behaviour of write_cas request.
- Use stack-allocated local cmd struct holder when calling transaction's complete() handler without creating transaction
- Fixed potential NULL-pointer dereference in dnet_lookup_object()

* Tue Apr 09 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.23.3.0
- Fixed memory leak at async_result aggregator connection
- postpone upstream creation after we know application exists
- write-cas should restart when receiving -EBADFD not -EINVAL
- Added a bit more documentation
- Use real error reply in async_result_handler::check(). Headers/lines cleanup.
- Write text command name, not its number
- Moved namespace/definitions/declarations from cpp file to separate index header.
- Get rid of unused typedefs
- use appropriate printf code for uint64_t variable (fixes warnings on 32bit systems)
- removed unused zmq.hpp include
- Fixed dnet_parse_addr() - no need to free addr
- Fixed building with gcc-4.4

* Fri Apr 05 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.23.2.0
- Do not spam error log-level with unsuccessful partial reads
- Put cocaine plugin into libcocaine-plugin-elliptics package
- More cmake cleanups
- Added msgpack-devel
- Corrected used include paths
- Use instantiated class in constructor
- Added zeromq3-devel into spec

* Thu Apr 04 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.23.1.0
- Added cocaine-extension package
- Some bulletproof default parameters for recovery tool
- Changed API (Introduced async_result, iterators and more flexible callbacks)
- Added verbosity to exec of ioclient
- dnet_stat must use correct group ID when ids are specified in command line
- Fixed dnet_parse_addr() back - it modifies provided address string for purpose
- Get rid of cocaine-worker-generic
- Implemented random read detection. Drop cache via posix_fadvice() and set appropriate dnet_io_req flag if random access is detected.
- Allow to set various flags for dnet_io_req structure, which may affect its cleanup behaviour
- Added ability to hold data in secondary indexes
- Recover old signal mask in main thread, block all signals in spawned threads
- Fixed cache write-cas
- Added defragmentation status. Depend on eblob 0.18.3+
- Do not include statically build cache into rpm
- Use correct sources in ELLIPTICS_CLIENT_SRCS/ELLIPTICS_CLIENT_SRCS
- New waiter implementation. Moved to public
- '-' route table ID delimiter must be placed after reverse-first (last) ':' family/port/addr delimiter
- Get rid of heavy unused part of dnet_file_info structure

* Wed Apr 03 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.23.0.0-rc1
- dnet_stat must use correct group ID when ids are specified in command line
- Fixed dnet_parse_addr() back - it modifies provided address string for purpose
- Get rid of cocaine-worker-generic
- Implemented random read detection. Drop cache via posix_fadvice() and set appropriate dnet_io_req flag if random access is detected.
- Allow to set various flags for dnet_io_req structure, which may affect its cleanup behaviour
- Added ability to hold data in secondary indexes
- Recover old signal mask in main thread, block all signals in spawned threads
- Fixed cache write-cas
- Added defragmentation status. Depend on eblob 0.18.3+
- Do not include statically build cache into rpm
- Use correct sources in ELLIPTICS_CLIENT_SRCS/ELLIPTICS_CLIENT_SRCS
- New waiter implementation. Moved to public
- '-' route table ID delimiter must be placed after reverse-first (last) ':' family/port/addr delimiter
- Get rid of heavy unused part of dnet_file_info structure

* Sat Mar 23 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.22.6.3
- Fixed typo

* Sat Mar 23 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.22.6.2
- Fixed cache write CAS for nonexisting records

* Sat Mar 23 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.22.6.1
- Fixed write CAS for nonexisting records

* Fri Mar 22 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.22.6.0
- Added DNET_IO_FLAGS_CHECKSUM flag - return data checksum from server in io->parent. Refactor checksumming code.
- Implemented per-session namespaces.
- Added cmake/Elliptics into devel rpm package
- ENOENT/ENXIO cleanup, run read recovery only if ENOENT or EBADFD is returned and only in groups which failed
- ENOENT/ENXIO cleanup - use ENXIO when there is no address in route table.
- Fix RPATH handling
- Move headers to corresponding place. Now backends.h can be included as standalone header.
- Update .gitignore
- Get rid of leveldb append lock - key should be locked by elliptics here, otherwise we do not care if one write will overwrite another one

* Thu Mar 21 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.22.5.1
- Fixed read_latest in case of no metadata

* Wed Mar 20 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.22.5.0
- Added start_iterator to python binding
- Added server-side iterator flags/type defines
- Introduce server-side iteration control structure
- Do not return error from dnet_db_list_iter() - this error will be propagated to all iterating threads and stop them
- Added start_iterator API
- Fixed bulk_read for empty request

* Tue Mar 19 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.22.4.0
- Depend on 0.10.0-rc5 cocaine

* Fri Mar 15 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.22.3.1
- Guard leveldb's append/offset writes, since they are actually read-modify-write cycles

* Fri Mar 15 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.22.3.0
- Added leveldb offset and append write support
- Return error for CAS write if ->checksum() is not supported
- Added leveldb checksum function
- Connection refused error message cleanup

* Wed Mar 13 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.22.2.0
- Return status of defragmentation request
- Return node's address, not client's one.
- Added leveldb->lookup()
- finder::parse_lookup() should not drop dnet_file_info if no filename provided
- Changed exec async API
- Moved groups to dnet_session
- Moved cflags/ioflags to dnet_session
- Added wait timeout to session

* Tue Mar 12 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.22.1.2
- Skip route table entries without addr list

* Tue Mar 12 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.22.1.1
- Simplify dnet_cmd_route_list() - allocate and send under state_lock route replies
- If log levels match, log it
- Do not use modern for (type &var : container) loop, use old-school iterators, since the former is not supported in gcc 4.4
- Use std::exeption_ptr() check instead of NULL cast, which is not supported in gcc 4.4

* Mon Mar 11 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.22.1.0
- Always request stats with DNET_ATTR_CNTR_GLOBAL flag set to grab global node's counters
- dnet_log_raw() should use <= for log-level comparison
- Added secondary indexes
- Added msgpack dependency
- Moved dnet_ioclient to new exec API
- Added new client exec API
- Fixed connection to 2.22 servers
- Let's all exec commands block if they do not have sph
- Updated cocaine config
- Fixed segfault at connection to elder servers

* Mon Mar 04 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.22.0.0
- Added high-level write_cas method
- Fixed memory leak
- Started exception refactoring
- Added convience methods for data_pointer
- Fixed bulk_read
- Added support for several io threads for client
- Added logical route groups to support multiple addresses in config.
- Do not try to initialize srw if no config specified. Otherwise fail whole node initialization if srw init failed.
- Send discovery at startup
- Use bp=boost::python namespace

* Mon Feb 25 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.21.4.3
- Use poll() in autodiscovery. Socket must be bound to recv data.
- Python test files update
- Added leveldb metadata write() error description

* Sat Feb 23 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.21.4.2
- Depend on 0.10.0-rc3+ cocaine

* Sat Feb 23 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.21.4.1
- Depend on 0.10.0-rc2+ cocaine
- elliptics-dev should depend on eblob - there is no eblob-dev package
- IO flags comment update
- Remove ack flag if write to cache-only is successful
- Added file_info reply to cache-only write requests

* Mon Feb 18 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.21.4.0
- Temporarily depend elliptics-dev on eblob-dev
- Fixed dnet_find
- Fixed remove method
- Fixed bulk_read

* Fri Feb 15 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.21.3.3
- Depend on 0.10.0-rc1 cocaine and 0.18.2 eblob
- Get rid of eblob metadata from leveldb

* Mon Feb 11 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.21.3.2
- Fixed read_latest method
- Added wireshark dissector
- Fixed cmake package config directory name
- Fixed packages depends
- Install cmake package config with elliptics-dev package
- Create cmake package config

* Wed Feb 06 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.21.3.1
- Fixed statistics behaviour in cpp module
- array_result_holder should return vector of templated types, not ints
- prepare_latest_callback() should break after it found entry in sorted array with dnet_id->group_id and swapped it with the first one

* Sat Feb 02 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.21.3.0
- Sync error codes used in other backends.
- elliptics-dev/dbg must depend on elliptics with the same version
- Get rid of smack backend in favour of leveldb
- Updated leveldb backend config

* Wed Jan 30 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.21.2.2
- Added signal blockers per threads
- Do not collect reply messages in srw, send reply to client as soon as it was received by server.
- Depend on 0.18.1+ eblob

* Sat Jan 26 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.21.2.1
- New eblob dependency
- Do not build older elliptics versions

* Sat Jan 26 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.20.2.1
- New eblob dependency

* Wed Jan 23 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.21.2.0
- Speed up read commands - use 1 data packet instead of data + ack
- Fixed multigroup callback
- Fixed groups iterating in cpp binding
- Added overload for node::add_remote
- Put reply/enqueue outside of the lock and use shared_ptr instead of iterator->shared_ptr
- Fixed 0-byte position in dnet_dump_id_len_raw()

* Fri Jan 18 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.21.1.0
- Send reply back to blocked client not from upstream destructor, but when final reply message is received.
- Optimize string split and digit-to-string conversion
- Fixed segfault at Logger delete
- Bugfixes, removed random freeze on remove request
- ioclient must setup ID if it wants blocked request
- Removed unneeded debug

* Tue Jan 15 2013 Ruslan Nigmatullin <euroelessar@yandex.ru> - 2.21.0.0
- Added asynchronous client API to C++ binding
- Introduced high-level result types in C++ binding
- Removed synchronous client API from C core
- Moved to C++ binding to C++11
- Use std classes instead of boost one where possible

* Sat Jan 05 2013 Evgeniy Polyakov <zbr@ioremap.net> - 2.20.2.0
- Removed app_watcher class
- Do not use app_watcher blocking helper - enqueue directly.
- Fixed failure path in pool growing route. Do not grow non-blocking IO pool at all
- proper srw command split in  dnet_ioclient
- Better id logs in srw
- Use correct ID in dnet_send_cmd_single()
- Do not mess with rpath
- Fixed bug in leveldb backend.

* Fri Dec 28 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.20.1.9
- Added snappy dep

* Fri Dec 28 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.20.1.8
- Elliptics must install 0.17.8+ eblob in this version

* Thu Dec 27 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.20.1.7
- Do not auto-recover keys when timeout happens

* Thu Dec 27 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.20.1.6
- Depend on 0.17.8+ eblob

* Tue Dec 25 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.20.1.5
- Fixed lookup_addr in python
- Added _XOPEN_SOURCE define to cleanup build on lucid

* Thu Dec 20 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.20.1.4
- Use atomic_t for sph::src_key

* Thu Dec 20 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.20.1.3
- Use client's provided ID when possible in dnet_send_cmd_single()

* Thu Dec 20 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.20.1.2
- Do not try to send data directly from dnet_io_req_queue() (calling thread context), queue request instead
- Remove unused package_dir
- Return error from dnet_send_request() and propagate it back to dnet_send*() calllers.

* Tue Dec 18 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.20.1.1
- Greatly reduce ACK latencies
- Fixed smack's sync-to-disk interval commit
- Added leveldb into default config

* Thu Dec 13 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.20.1.0
- Added index_block_bloom_length and index_block_size eblob config parameters
- Added blob_size_limit eblob parameter
- Depend on 0.17.7 eblob and higher
- Detect correct elliptics version in setup.py
- Added more informative IO errors to python binding
- Python binding update to new API
- Added exception transformation for python
- Fixed exception code for Item not found

* Tue Dec 11 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.20.0.1
- Async 'blocking' exec command.
- Export dnet_send_ack()
- More debug logs when sending reply
- Recover README

* Fri Dec 07 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.20.0.0
- Moved cflags, ioflags and typo into session from API
- Added compare-and-swap write
- Moved elliptics::session to separate file
- Callbacks redesign in cpp binding
- Use boost::thread instead of plain pthreads
- Added proper exceptions
- Logger and node redesign in C++ binding
- Fixed leveld initialization
- leveldb backend: DNET_CMD_DEL_RANGE
- leveldb backend: range read support

* Mon Nov 26 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.19.2.8
- dnet_remove_object_raw() must return positive number of transactions sent

* Thu Nov 22 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.19.2.7
- Fixed dnet_mix_states() when ID is null

* Wed Nov 21 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.19.2.6
- Tune nonblocking pool growing policy
- All dnet_remove*() functions should return error, if ack returned negative status.
- poll() uses msecs as timeout

* Mon Nov 12 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.19.2.5
- Added atomic number of available IO threads, only grow up pool if we have blocked sph and there are no threads available.

* Mon Nov 12 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.19.2.4
- Added atomic number of available IO threads, only grow up pool if we have blocked sph and there are no threads available.

* Wed Nov 07 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.19.2.4
- Added temoporary debug

* Tue Nov 06 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.19.2.3
- Only enlarge non-blocking pool when there is blocking sph in the pool.

* Fri Nov 02 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.19.2.2
- Fixed python installation in Lucid
- Remove signal setup in library. Do not block signals on ioserv exit
- Only write error message when real error occurs in leveldb_backend_read()

* Fri Oct 26 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.19.2.1
- Fixed precise build

* Fri Oct 26 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.19.2.0
- When creating new state we should not send auth/join commands to itself
- Return back periodic route table check
- Added LevelDB backend

* Thu Oct 25 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.19.1.0
- Depend elliptics-dev on elliptics with (>= ${Source-Version}) version
- Do not check for n->st when setting up new server node
-     When it is called from dnet_server_node_create()->dnet_state_create()
-     there is no n->st, and that's exactly the path where server

* Fri Oct 19 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.19.0.1
- Use autogenerated major/minor elliptics versions. Whole version is being read from debian/changelog file
- Fix CMake file with missing boost libraries
- Bump ABI version (missed from 2.18->2.19 upgrade)
- Drop site-packages from elliptics-client
- Depend on >= 0.9.4 cocaine

* Wed Oct 10 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.19.0.0
- Added sessions - this allows to configure and set per-request parameters (like groups)

* Wed Oct 10 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.18.3.2
- Fixed reply size calculation
- Unify srw log rules
- Fixed pool growing policy
- Updated debian package rules

* Mon Oct 08 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.18.3.1
- When running recovery-on-read do not write io attribute header

* Mon Oct 08 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.18.3.0
- Grow IO pools on demand
- Added automatic recovery on read command:
-      if object didn't exist in previously read group,
-      it will be written when read from the next group succeed
- Documentation update
- Added multicast autodiscovery
- If state is already exist, do not fail with error
- Fixed the ugliest debian python installation
- Added new python bindings
- Do not try to run command if srw was not initialized
- Populate cache on READ command when DNET_IO_FLAGS_CACHE ioflag is set

* Thu Sep 20 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.18.2.1
- Added c++/python bindings for cache write operations (including timeout)
- Added remove-from-disk cache operation: when such flag is set (at write time)"
-     if object is removed from cache, it is also removed from disk
- Increase example number of non-blocking io threads
- Added 'overwrite commits write' comment

* Mon Sep 17 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.18.1.2
- dnet_backend_log_raw() should use dnet_backend_check_log_level() to check log level
- Added startup stack size check
- Cocaine job has to be created only when it can be queued

* Fri Sep 14 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.18.1.1
- Update version num

* Thu Sep 13 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.18.0.1
- New interface for execution, reply and chaining
- Do not strip rpath
- Fixed server node cleanup bug when it destroyed locks first while IO threads could still use them
- dnet_send_cmd_raw() must always wait for ack
- Fixed thread creation bug in app_watcher when application does not exist
- Added -g flag to elliptics build
- Use weak symbols instead of stubs in client lib, since server also links to it and in Fedora it ends up using stubs from client lib
- Search for 0mq only of cocaine is enabled
- Update debian packaging
- Fixed build-depends

* Fri Aug 31 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.17.0.4
- elliptics-client must replace old-school elliptics-2.10

* Thu Aug 30 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.17.0.3
- Added python-support to dep list
- Use correct package name in shlibs

* Wed Aug 22 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.17.0.2
- Switch to cmake from autoconf

* Mon Aug 20 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.17.0.1
- Depend on eblob 0.17.1 and higher
- Use log level instead of log mask
- Depend on smack 0.5.0 and higher
- Added cdbs dep
- Added in-memory (optionally disk-backed) LRU cache
- Get rid of boost-filesystem
- Split code (and debian package) to client/server libs
- New unlink interfaces
- Added ioflags to ioclient
- If lookup returned error, proceed read-latest with default order
- Let DNET_CMD_DEL use dnet_io_attr structure too

* Wed Aug 08 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.16.0.1
- Added possibility to start defragmentation on demand
- Added reserved 'hostname' word for local address
- Added cleanup call into node destruction path, which fixes double free error in config error path
- Implemented blocking exec commands
- Refactor pools of workers
- Set cocaine log level based on elliptics log mask
- Completely created client library
- Fixed json example path

* Tue Jul 24 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.15.0.1
- Send correct answer in smack_write
- New bulk_read()
- New event string for application invocation
- Corrected changelog
- Depend on smack 0.4.0 and higher

* Mon Jul 02 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.14.1.4
- Log all client job errorrs into app/.log file in elliptics
- Set nocsum flags in io-attr when it is set in global node's config

* Wed Jun 27 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.14.1.3-1
- Depend on smack 0.3.0 and higher

* Tue Jun 26 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.14.1.2-1
- Use smack_total_elements() to get number of records

* Mon Jun 25 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.14.1.1-1
- Disable signals in library and enable in server and ioclient
- Added cocaine library documentation
- Added smack configuration
- Sync with upstream smack repo

* Fri Jun 22 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.14.0.7-1
- Fixed typo in smack config parser

* Fri Jun 22 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.14.0.6-1
- Sink srw log into app + ".log" object in elliptics

* Fri Jun 22 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.14.0.5-1
- Added SMACK backend depends

* Fri Jun 22 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.14.0.4-1
- Drop cocaine plugin dependencies

* Fri Jun 22 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.14.0.3-1
- Added new cocaine debian package deps
- Drop cocaine deps in RHEL/Fedora build

* Thu Jun 21 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.14.0.2-1
- Build srw fix (use weak symbol for dnet_log_raw())
- Added new eblob bit to config documentation, drop unused parameters
- Fixed write response generation

* Fri Jun 15 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.14.0.1-1
- Use cocaine workers for server-side
- Drop dnet_attr structure
- Optimize read (do not send ack if there is data)
- Use ioremap::elliptics namespace
- Added ::push() - nonblocking exec

* Sat Apr 28 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.13.0.9-1
  Sun Apr 28 2012 --> Sun Apr 22 2012 or Sat Apr 28 2012 or Sun Apr 29 2012 or ....
- Do not allow zero-sized reads
- Do not double-close python init file

* Fri Apr 27 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.13.0.8-1
  Sat Apr 27 2012 --> Sat Apr 21 2012 or Fri Apr 27 2012 or Sat Apr 28 2012 or ....
- Added new lookup() methods to c++/python bindings. Patch by Anton Kortunov <toshik@yandex-team.ru>
- If we fail to open log file, dup2() stdout/stderr to /dev/null in spawned worker process

* Fri Apr 27 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.13.0.7-1
- More mess with 012 file descriptors - dup them to /dev/null when going background, reopen to log file in srw worker
- Use correct F_SETFD/FD_CLOEXEC
- Use old-school fcntl() instead of accept4() and epoll_create1()
- Allow script execution without cmd-line

* Fri Apr 27 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.13.0.6-1
- Added srw config options
- Added O_CLOEXEC flags
- Added new configs (for nginx and fastcgi frontend) and python example
- Return sub data from smack_write() call - this is needed for fastcgi frontend
- Let dnet_ioclient write file by ID
- Added smack backend wrapper

* Fri Apr 6 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.13.0.5-1
- Build dependencies update
- Do not write metadata when appropirate bit is set in node->flags
- Update documentation about blob flags

* Fri Mar 23 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.13.0.4-1
- Updated state mixing algorithm
- Added defrag_timeout, defrag_percentage and blob_size options to file backend

* Mon Mar 19 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.13.0.3-1
- Allow ioclient to read/write data in different columns
- Hardlink script should overwrite data
- Fixed file read/write with different column
- Use correct pipe path, which includes pid
- Use correct structure size for dentries and extended logging
- Do not set name for main process

* Tue Mar 13 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.13.0.2-1
  Sun Mar 13 2012 --> Sun Mar 11 2012 or Tue Mar 13 2012 or Sun Mar 18 2012 or ....
- Use exactly specified in config socket family
- Obsolete srw by ellipitcs
- Revert "Use X bits from operation key to find a lock instead of random hashing"
- Added proper sigchild handling
- spec update - added libsrw.so* files
- Dropped srw dependency

* Sun Mar 11 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.13.0.1-1
- Added srw

* Wed Feb 29 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.12.0.1-1
- Depend on 0.15 eblob: added new defragmentation parameters into config
- Propagate prepare_write() and friends return values back to callers - changed API

* Sun Feb 19 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.11.1.7-1
- Get rid of virtually unused and unneded eblob generation tools. It can be replaced by trivial python scripts
- Updated python scripts to use new eblob class
- exec is reserved name in python, use exec_script for execution method name

* Thu Feb 16 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.11.1.6-1
- Added possibility to read metadata from file and dump to log
- Added remove_keys_from_storage_found_removed_in_eblob.py
- Added local merge iterator written in python. Is not optimal, but quite fast.

* Tue Feb 14 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.11.1.5-1
- Execute CHECK commands with NOLOCK flag

* Sat Feb 11 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.11.1.4-1
- Use correct eblob path for statvfs() request

* Mon Feb 8 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.11.1.3-1
- Set id.type to 0 where appropriate
- Request statistics with DNET_ATTR_NOLOCK flag set
- Fixed pohmelfs_rename.py

* Mon Feb 6 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.11.1.2-1
- Process checksum flags according to aflags and ioflags

* Wed Feb 1 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.11.1.1-1
- Added start/num parameters to iterate over selected number of blobs.
- Depend on 0.14.1 blob and higher where it is implemented.

* Thu Jan 26 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.11.0.15-1
- Added readdir script
- Dropped content length manipulation from srw/pohmelfs_inode_info_insert.py
- Use dnet_process_meta instead of dnet_process_cmd_raw to prevent deadlocks

* Tue Jan 24 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.11.0.14-1
- Reserve some space for directory content
- Added pohmelfs_read_latest_groups.py script
- Implemented prepare-latest helper, which returns timestamp sorted groups which contain requested id
- If we have more data to send, set only DNET_FLAGS_MORE flag, not erase others
- Rename cpp bindings
- Fixed range requests without limits

* Tue Jan 17 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.11.0.13-1
- Sort keys on server side in range requests
- Disable eblob_gen for now
- Address new binutils issues (gcc 4.6 compilation fixes)

* Wed Dec 21 2011 Evgeniy Polyakov <zbr@ioremap.net> - 2.11.0.12-1
- Trying to address new binutils issues
- Fill with zeroes all io threads structures
- Set io.num to content size+offset in write_data_wait() - it allows to use prepare/commit flags

* Tue Dec 20 2011 Evgeniy Polyakov <zbr@ioremap.net> - 2.11.0.11-1
- Implemented check for start/stop update timestamp
- Added cache tests in test.cpp

* Thu Dec 15 2011 Evgeniy Polyakov <zbr@ioremap.net> - 2.11.0.10-1
- Added configurable two-queue cache for read data by Anton Kortunov <toshic.toshic@gmail.com>

* Mon Dec 12 2011 Evgeniy Polyakov <zbr@ioremap.net> - 2.11.0.9-1
- Reopen log file on sighup

* Fri Dec 9 2011 Evgeniy Polyakov <zbr@ioremap.net> - 2.11.0.8-1
- Set DNET_FLAGS_NOLOCK for route/reverse lookup request/reply commands
- Added memory_test_pohmelfs() autotest
- Added gc calls into pohmelfs methods
- Fixed exception string generation for null ids
- Added small memory/leak test

* Fri Dec 2 2011 Evgeniy Polyakov <zbr@ioremap.net> - 2.11.0.7-1
- Use eblob_read_nocsum() if DNET_IO_FLAGS_NOCSUM is set

* Thu Dec 1 2011 Evgeniy Polyakov <zbr@ioremap.net> - 2.11.0.6-1
- Cleanup unused variables
- Fixed reply cmd->flags initialization
- Use boost::filesystem v2
- Fixes in bulk_read and bulk_write

* Mon Nov 28 2011 Evgeniy Polyakov <zbr@ioremap.net> - 2.11.0.5-1
- Implemented pool of non-blocking threads for recursive commands.
- Dropped metadata csum support in favour of eblob embedded checksums.
- Added bulk_write operation.
- Added sstable parser into python module

* Wed Nov 23 2011 Evgeniy Polyakov <zbr@ioremap.net> - 2.11.0.4-1
  Thu Nov 23 2011 --> Thu Nov 17 2011 or Wed Nov 23 2011 or Thu Nov 24 2011 or ....
- Added nolocking IO thread

* Wed Nov 23 2011 Evgeniy Polyakov <zbr@ioremap.net> - 2.11.0.3-1
  Thu Nov 23 2011 --> Thu Nov 17 2011 or Wed Nov 23 2011 or Thu Nov 24 2011 or ....
- Added oplock_num config parameter
- Added non-blocking thread checks

* Wed Nov 23 2011 Evgeniy Polyakov <zbr@ioremap.net> - 2.11.0.2-1
- Aflags/lock cleanups

* Wed Nov 23 2011 Evgeniy Polyakov <zbr@ioremap.net> - 2.11.0.1-1
- Added operations locks. Now all commands are processed with single-machine-atomicity
- Added server-side scripts

* Wed Nov 23 2011 Evgeniy Polyakov <zbr@ioremap.net> - 2.10.4.13-1
- Only perform blob write if io->size is not zero

* Tue Nov 22 2011 Evgeniy Polyakov <zbr@ioremap.net> - 2.10.4.12-1
- Initialize srw after node

* Tue Nov 22 2011 Evgeniy Polyakov <zbr@ioremap.net> - 2.10.4.11-1
- Do not chroot into history environment, since it is most likely incomplete

* Tue Nov 22 2011 Evgeniy Polyakov <zbr@ioremap.net> - 2.10.4.10-1
- Do not csum read when DNET_IO_FLAGS_NOCSUM ioflag is set
- When doing partial read, checksum whole file

* Sat Nov 19 2011 Evgeniy Polyakov <zbr@ioremap.net> - 2.10.4.9-1
- cpp tests update
- Return -ENOTSUP if srw is not initialized
- Do not reset join state to RECONNECT after it has been created
- Added stall_count as a configurable parameter
- Added BULK_READ command

* Tue Nov 15 2011 Evgeniy Polyakov <zbr@ioremap.net> - 2.10.4.8-1
- Fixed range counters
- Added ::remove() methods into python binding
- Remove all types if -1 as id->type is specified
- RHEL build must depend on eblob-devel >= 0.12.18 libsrw-devel >= 0.2.2

* Mon Nov 14 2011 Evgeniy Polyakov <zbr@ioremap.net> - 2.10.4.7-1
- Moved some objects from interface.h to packet.h
- Added range counters
- DNET_IO_FLAGS_PLAIN_WRITE must differ from DNET_IO_FLAGS_NOCSUM
- Use IP_TOS instead of SO_PRIORITY to set tos bits
- srw is called libsrw in rhel builds
- Depend on 0.12.18 eblob and 0.2.2 srw

* Thu Nov 3 2011 Evgeniy Polyakov <zbr@ioremap.net> - 2.10.4.6-1
- Depend on 0.2.1 srw and higher

* Thu Nov 3 2011 Evgeniy Polyakov <zbr@ioremap.net> - 2.10.4.5-1
- Added binary data support in srw

* Tue Nov 1 2011 Evgeniy Polyakov <zbr@ioremap.net> - 2.10.4.4-1
- Do not fail node initialization if srw is not initialized

* Mon Oct 31 2011 Evgeniy Polyakov <zbr@ioremap.net> - 2.10.4.3-1
- blob_send modified to send all columns if id.type == -1
- Do not depend elliptics build on libssl
- eblob/srw autoconf updates
- Do not return 1 from blob_write when data was compressed, return 0, since
	there was no error

* Tue Oct 25 2011 Evgeniy Polyakov <zbr@ioremap.net> - 2.10.4.2-1
- Added srw dependency
- Do not call dnet_convert_io_attr for DNET_CMD_DEL command

* Wed Oct 19 2011 Evgeniy Polyakov <zbr@ioremap.net> - 2.10.4.1-1
- Decreased WRITE latency
- Use CORK for write blocks

* Wed Oct 19 2011 Evgeniy Polyakov <zbr@ioremap.net> - 2.10.4.0-1
- Added ioprio call inside check
- More example ioserv.conf comments
- Added client/server network priorities (man 7 socket -> IP_PRIORITY)

* Sat Oct 15 2011 Evgeniy Polyakov <zbr@ioremap.net> - 2.10.3.9-1
- Fixed memory allocation in range-delete

* Tue Oct 11 2011 Evgeniy Polyakov <zbr@ioremap.net> - 2.10.3.7-1
- Only set BLOB_DISK_CTL_NOCSUM if DNET_IO_FLAGS_NOCSUM is set
- Added dnet_get_routes function
- Added server-side scripting support
- Example ioserv.conf update
- Spec update

* Thu Dec 9 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.5.2-1
- Implemented multiple read in elliptics core and FCGI frontend.
- Implemented very user-friendly C++/Python interface.
- Extended FCGI xml output for POST request: added data crc, size,
    per-group addresses and path to the destination object on file backend.

* Fri Dec 3 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.5.1-1
- Documentation update.

* Fri Dec 3 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.4.8-1
- Fixed fcgi reading with new groups URI.

* Fri Dec 3 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.4.7-1
- Implemented automatic groups selection by free space.
- Bug fixes.

* Thu Dec 2 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.4.6-1
- Fixed eblob_send().
- Use 50 check threads.

* Thu Dec 2 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.4.5-1
- Multi-threaded fsck.
- Bug fixes (including 2.9.4.4 version).

* Tue Nov 30 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.4.3-1
  Thu Nov 30 2010 --> Thu Nov 25 2010 or Tue Nov 30 2010 or Thu Dec 02 2010 or ....
- Implemented bdb fsck (both merge and copy check).

* Thu Nov 25 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.4.2-1
- Switched to random ids (1024 ids are generated at first start)

* Fri Nov 19 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.4.1-1
- Switched to new addressing model

* Tue Nov 9 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.3.14-1
- Remove direct object if it can not be uploaded to the storage.

* Tue Nov 9 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.3.13-1
- Remove empty/broken history objects during merge.

* Tue Nov 9 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.3.12-1
- Added more debug about processed objects in fsck tools.
- Delete directly read object if its history can not be mapped.
- Return error from dnet_merge_direct() when merge falls back to direct
	merge during common merge.

* Sat Nov 4 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.3.11-1
- Attempt to do direct merge when we can not parse non-direct history stored in main storage.

* Sat Nov 4 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.3.10-1
- Fixed bit directory generation in file_backend_get_dir_bits()

* Thu Oct 21 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.3.9-1
- Fixed state leak in lookup processing.

* Thu Oct 21 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.3.8-1
- Always use local address for succeeded local lookup.

* Thu Oct 21 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.3.7-1
- Kill state when check thread got error. (7)
- Extended fire time debug. (6)

* Thu Oct 21 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.3.5-1
- Update transaction fire time to include check timeout.

* Wed Oct 20 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.3.4-1
- Extend dnet_send_read_data() to get offset from parameters and do not abuse dnet_io_attr structure.

* Wed Oct 20 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.3.3-1
- Unmap history after selecting transaction with the last update time in dnet_merge_get_latest_transactions()

* Mon Oct 18 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.3.2-1
- Added full object ID dump and request error.
- Exit merge early if no id file was provided.
- Do not dereference state in dnet_read_complete() if it is NULL.
- Added -N (do not request ids and use prevously downloaded) option comment into fsck help.

* Mon Oct 18 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.3.2-1
- Extended alloc/free debug.
- Allow zero-sized writes.

* Wed Oct 13 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.3-1
- New minor release. No changes from 2.9.2.32.

* Mon Oct 11 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.2.32-1
- Added configurable value to check header for remote node IP address.
- Added joining client check: returned address must be reachable to be
    inserted into route table.

* Fri Oct 8 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.2.31-1
- Fixed LA sorting.

* Wed Oct 6 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.2.29-1
- Added id-by-LA generation and sorting.
- Debug cleanups.

* Wed Oct 6 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.2.28-1
- Added timed statistics request which also works as timed connection checker.
- Added seconds-only check time wait.

* Wed Oct 6 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.2.27-1
- Added keep-alive options.

* Mon Oct 4 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.2.26-1
- Unlink transaction and history after direct merge.
- Do not log error when state is NULL in completion callback.

* Sat Oct 2 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.2.25-1
- Added norequest flag to fsck util (will use existing file).
- Fixed remotes processing typo.

* Thu Sep 30 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.2.24-1
- Do not traverse the whole transaction tree after we found the
	first one which fire time has not yet elapsed.

* Thu Sep 30 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.2.23-1
- Remove io_thread_num and max_pending config parameters.
- Added stack size parameter to check tools.

* Mon Sep 20 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.2.22-1
- Moved transaction debug output into the place where it can not dereference stale data.
- Decrease debug level for allocations.
- Added addrinfo null check. Should be useless though.

* Mon Sep 20 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.2.21-1
- Do not dereference null state in dnet_fcgi_read_complete.

* Fri Sep 17 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.2.20-1
- Added thread stack size parameter.
- Added malloc mmap threshold config parameter. (19)

* Fri Sep 17 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.2.18-1
- Really fixed recv state transaction processing leak.

* Fri Sep 17 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.2.16-1
-Do not try to dereferece null state. Happens when transaction is completed
    on timeout.
- Use lineary (+60 seconds each turn) growing reconnection timeout. Added
    reconnection limit of 1 day.
- Fixed recv state transaction processing leak.

* Fri Sep 17 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.2.15-1
- Compilation typo fixed.

* Fri Sep 17 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.2.14-1
- Fill all allocated memory with zeroes.

* Thu Sep 16 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.2.13-1
- Put transaction after it was executed. Its refcnt was increased during
    search call.
- Do not try to dereference state when it can be null.
- Do not create unneded listening state when node does not join network. (12)
- Reset accept state on error.
- Do not join to states in state lists, since they can be freed in own
    threads. (11)
- Drop transaction resending support. (10)
- Extended local command processing log. (9)
- Also print pid in common logger. (8)
- Use pthread_self() instead of getpid() to get uniq thread id. (7)

* Tue Sep 7 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.2.6-1
- If DNET_IO_FLAGS_NO_HISTORY_UPDATE flag was set for read command, do not
    send data reply. Used in local stat command.
- Debug cleanup.
- From previous releases:
  Do not deal with NULL transactions.
  Start state IO thread after state initialization.
  Join to io state thread instead of freeing it directly.
  Do not exit from accept loop on error.
  Initialize state list entry prior other usage.

* Tue Sep 7 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.2-1
- Switched from libevent state machine to thread-per-client model.

* Fri Aug 13 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.1.1-1
- Added DNET_FCGI_PUT_REGION config option to optionally enable region tag
- Added wildcard direct download pattern (*)
- Force direct download patterns to be checked against ID ending and
  just by having this substring somewhere in the query.

* Tue Aug 10 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.1-1
- New elliptics network release: 2.9.1

* Tue Aug 10 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.0.31-1
- Logger cleanups.
- Fixed resend locking bug.

* Mon Aug 9 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.0.30-1
- Fixed lock/unlock typo in dnet_data_ready().

* Sat Aug 7 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.0.29-1
- Refactor fcgi logging (29)
- Return read error when key was not found. Use right config file options. (28)

* Thu Aug 6 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.0.27-1
- Added sanity checks for embedded reading.

* Thu Aug 6 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.0.26-1
- Disabled per-client statistics request in fcgi daemon.
- Added subtle timeout and data rewrite when FCGX_PutStr() returns error.

* Thu Aug 5 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.0.25-1
- Copy resolved address into buffer (later used for reconnection)
	before trying to connect.

* Thu Aug 5 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.0.24-1
- Refactor fcgi/check loggers to write pid/thread id into single log file.

* Thu Aug 5 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.0.23-1
- Added <region> tag into download-info XML output
- Changed sending locking.

* Wed Aug 4 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.0.22-1
- Guard multiple 'logical' xml writes against parallel write

* Wed Aug 4 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.0.21-1
- Implemented direct transaction merge.
- If reading size was set to 0 map ~0ULL size, i.e. the whole file.
- Remove object from the storage if its history log says so.
- Drop unused DNET_FCGI_EMBED_TIMESTAMP_PATTERN and change to use
	DNET_FCGI_EMBED_PATTERN option.

* Wed Jul 28 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.0.20-1
  Sun Jul 28 2010 --> Sun Jul 25 2010 or Wed Jul 28 2010 or Sun Aug 01 2010 or ....
  - Fixed several fd leaks.

* Wed Jul 28 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.0.19-1
  Sun Jul 28 2010 --> Sun Jul 25 2010 or Wed Jul 28 2010 or Sun Aug 01 2010 or ....
  - Unmap history file when failed to read transaction.

* Wed Jul 28 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.0.18-1
  Sun Jul 28 2010 --> Sun Jul 25 2010 or Wed Jul 28 2010 or Sun Aug 01 2010 or ....
- Guard OpenSSL_add_all_digests() and initialize it only once per thread
	group.
- Force dnet_check_process_request() to wait for all sent transactions, do
	not wakeup after receiving reply from the first one.

* Wed Jul 28 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.0.17-1
  Sun Jul 28 2010 --> Sun Jul 25 2010 or Wed Jul 28 2010 or Sun Aug 01 2010 or ....
- Fixed compilation warnings on 64bit platform (uint64_t to unsigned long
	long and void * to unsigned long)
- Try only requested transformation function, do not continue with the next
	one.
- Use errno to differentiate reconnection state.

* Wed Jul 28 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.0.15-1
  Sun Jul 28 2010 --> Sun Jul 25 2010 or Wed Jul 28 2010 or Sun Aug 01 2010 or ....
- Made elliptics depend on eblob
- Updated checker's logger.
- Increase example/check/common.c waiting timeout.
- Added logs into file io backend listing processor.

* Mon Jul 26 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.0.12-1
  Sun Jul 26 2010 --> Sun Jul 25 2010 or Mon Jul 26 2010 or Sun Aug 01 2010 or ....
- Let check applications to sleep longer waiting for replies.
- Reduce number of ids sent via DNET_CMD_LIST command to 1024 per reply.
- Mark states added via dnet_add_state() as reconnect-friendly.
- Do not add reconnection addresses which do not have joining flags.
- Updated to the latest eblob lib (moved blob code outside to libeblob).
- Reschedule transaction's fire time when (non-last) reply is received.
- Do not mess with dnet_fcgi_random_hashes outside of fcgi.c

* Sun Jul 25 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.0.11-1
- Added embedded URI parameter, which will force timestamp to be embedded
    with data. It is possible to embed other parameters too.

    post: wget -O /tmp/1111 -S --post-file=elliptics.spec
    "http://devfs1/test.mp3?name=qwerty.xml&embed&timestamp=123"

    get: wget -O /tmp/1111 -S --header="If-Modified-Since: Thu, 01 Jan 1970
    00:02:00 GMT"  "http://devfs1/test.mp3?name=qwerty.xml&embed&direct=1"
- fixed random hash selection in fcgi frontend.

* Fri Jul 23 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.0.10-1
-return back addressing magic^W logic in dnet_write_object_raw()

* Thu Jul 22 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.0.9-1
- return back virtual datacenters.

* Thu Jul 22 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.0.8-1
- BLOB IO backend updates (multiple threads, index, bug fixes).
- file IO backend fixes
- python bindings
- c++ binding fixes

* Mon Jul 19 2010 Arkady L. Shane <ashejn@yandex-team.ru> - 2.9.0.7-1
- initial build for Fedora
