%if %{defined rhel} && 0%{?rhel} < 6
%define __python /usr/bin/python2.6
%endif
%{!?python_sitelib: %global python_sitelib %(%{__python} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")}
%{!?python_sitearch: %global python_sitearch %(%{__python} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib(1))")}

Summary:	Distributed hash table storage
Name:		elliptics
Version:	2.24.15.7
Release:	1%{?dist}

License:	GPLv2+
Group:		System Environment/Libraries
URL:		http://www.ioremap.net/projects/elliptics
Source0:	%{name}-%{version}.tar.bz2
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%if %{defined rhel} && 0%{?rhel} < 6
BuildRequires:	python26-devel
BuildRequires:	gcc44 gcc44-c++
%else
BuildRequires:  python-devel
%endif
BuildRequires:	eblob-devel >= 0.21.26
BuildRequires:	cmake msgpack-devel

%if %{defined rhel} && 0%{?rhel} < 6
%define boost_ver 141
%else
%define boost_ver %{nil}
%endif

BuildRequires:	boost%{boost_ver}-devel, boost%{boost_ver}-iostreams, boost%{boost_ver}-python, boost%{boost_ver}-system, boost%{boost_ver}-thread, boost%{boost_ver}-filesystem

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


%package client-devel
Summary:	Elliptics library C++ binding development headers and libraries
Group:		Development/Libraries
Requires:	%{name} = %{version}-%{release}


%description client-devel
Elliptics client library (C++/Python bindings), devel files

%prep
%setup -q

%build
export LDFLAGS="-Wl,-z,defs"
export DESTDIR="%{buildroot}"
%if %{defined rhel} && 0%{?rhel} < 6
export PYTHON=/usr/bin/python26
export CC=gcc44
export CXX=g++44
CXXFLAGS="-pthread -I/usr/include/boost%{boost_ver}" LDFLAGS="-L/usr/lib64/boost%{boost_ver}" %{cmake} -DBoost_LIB_DIR=/usr/lib64/boost%{boost_ver} -DBoost_INCLUDE_DIR=/usr/include/boost%{boost_ver} -DBoost_LIBRARYDIR=/usr/lib64/boost%{boost_ver} -DBOOST_LIBRARYDIR=/usr/lib64/boost%{boost_ver} -DWITH_COCAINE=NO -DHAVE_MODULE_BACKEND_SUPPORT=no .
%else
%{cmake} -DWITH_COCAINE=NO -DHAVE_MODULE_BACKEND_SUPPORT=no .
%endif

make %{?_smp_mflags}

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
%{_bindir}/*
%{_libdir}/libelliptics.so.*
%{_libdir}/libelliptics_cocaine.so.*
%{_mandir}/man1/*

%files devel
%defattr(-,root,root,-)
%{_libdir}/libelliptics.so
%{_libdir}/libelliptics_cocaine.so

%files client
%defattr(-,root,root,-)
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
* Wed Feb 05 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.15.7
- Monitoring: Added rwlock on access to dnet_node::monitor
- Get rid of get_node calls
- client: Fixes for x86 platform
- Core: Limited size of io queues to the number of io threads * 1000. Added building iterate.cpp from example to main build without installation.

* Thu Jan 30 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.15.6
- debian: provide and replace *-2.24 package versions

* Thu Jan 30 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.15.5
- debian: elliptics/-dev provides elliptics/-dev-2.24 now

* Thu Jan 30 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.15.4
- debian: elliptics-client provides elliptics-client-2.24 now
- Tests: fixed indent in run_tests.py
- Tests: running run_tests.py with proper python
- Tests: fixed build on rhel 5
- Tests: Fixed pep8 warnings and indent
- Monitoring: fixed warning on build
- Monitor&Doxygen: Added doxygen code documentation to monitor
- read-callback: only run read recovery when we have read the whole object. Added read recovery debug.
- dnet_io_attr: added total_size field (without ABI changes), which contains total size of the read record. In particular useful when client asks for part of the object (by specifying size in read request).
- Monitor: fixed build on lucid.

* Fri Jan 24 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.15.3
- Python: Fixed typo in docstrings.
- Python: added ability to clone session.
- Python: added keeping node inside python elliptics.Session to insure that session will be deleted after node.

* Mon Jan 20 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.15.2
- trans: randomize route table update: select 5 random groups and read table from one random node from each selected group
- tests: fixed python formatting
- tests: fixed pyton indent
- test: Don't use inline if/else syntax
- Python: Fixed copy-paste in session.py docstrings
- Python: fixed writting out of memory
- Python: fixed None usage as Id in session.exec_()
- Monitor: Added REST-like api for getting monitor statistics

* Thu Jan 09 2014 Evgeniy Polyakov <zbr@ioremap.net> - 2.24.15.1
- prepare_latest fix
- tests: set stdout to sys.stdout instead of PIPE
- Monitor: Added ability to extend monitor statistics via custom statistics providers.
- Python: Fixed rebase conflicts.
- srw: Don't call cocaine::app_t::stop on stopped apps
- tests: Write artifacts to source directory
- tests: Fixed path to cocaine runtime
- Monitor: fixed losing elliptics_monitor.so via making elliptics_monitor static library with -fPIC
- Python: downgraded checking python objec on None for boost 1.40 which doesn't support is_none() method
- Monitor: Made elliptics_monitor as shared library

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

* Sun Apr 28 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.13.0.9-1
- Do not allow zero-sized reads
- Do not double-close python init file

* Sat Apr 27 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.13.0.8-1
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

* Sun Mar 13 2012 Evgeniy Polyakov <zbr@ioremap.net> - 2.13.0.2-1
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

* Thu Nov 23 2011 Evgeniy Polyakov <zbr@ioremap.net> - 2.11.0.4-1
- Added nolocking IO thread

* Thu Nov 23 2011 Evgeniy Polyakov <zbr@ioremap.net> - 2.11.0.3-1
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

* Thu Nov 30 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.4.3-1
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

* Sun Jul 28 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.0.20-1
  - Fixed several fd leaks.

* Sun Jul 28 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.0.19-1
  - Unmap history file when failed to read transaction.

* Sun Jul 28 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.0.18-1
- Guard OpenSSL_add_all_digests() and initialize it only once per thread
	group.
- Force dnet_check_process_request() to wait for all sent transactions, do
	not wakeup after receiving reply from the first one.

* Sun Jul 28 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.0.17-1
- Fixed compilation warnings on 64bit platform (uint64_t to unsigned long
	long and void * to unsigned long)
- Try only requested transformation function, do not continue with the next
	one.
- Use errno to differentiate reconnection state.

* Sun Jul 28 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.0.15-1
- Made elliptics depend on eblob
- Updated checker's logger.
- Increase example/check/common.c waiting timeout.
- Added logs into file io backend listing processor.

* Sun Jul 26 2010 Evgeniy Polyakov <zbr@ioremap.net> - 2.9.0.12-1
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
