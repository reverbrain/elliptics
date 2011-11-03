Summary:	Distributed hash table storage
Name:		elliptics
Version:	2.10.4.6
Release:	1%{?dist}

License:	GPLv2+
Group:		System Environment/Libraries
URL:		http://www.ioremap.net/projects/elliptics
Source0:	%{name}-%{version}.tar.bz2
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:	libtar-devel
%if 0%{?rhel} < 6
BuildRequires:	python26-devel, boost141-python, boost141-devel
%else
BuildRequires:  python-devel, boost-python, boost-devel
%endif
BuildRequires:	eblob-devel srw-devel >= 0.2.1
BuildRequires:	automake autoconf libtool

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

%package python
Summary:	Elliptics library Python binding
Group:		Development/Libraries
Requires:	%{name} = %{version}-%{release}

%description python
Elliptics Python Language bindings.


%package python-devel
Summary:	Elliptics library Python binding
Group:		Development/Libraries
Requires:	elliptics-python = %{version}-%{release}


%description python-devel
Elliptics Python Language bindings development headers and libraries.


%package c++
Summary:	Elliptics library C++ binding
Group:		Development/Libraries
Requires:	elliptics = %{version}-%{release}


%description c++
Elliptics library C++ language binding.


%package c++-devel
Summary:	Elliptics library C++ binding development headers and libraries
Group:		Development/Libraries
Requires:	elliptics-devel = %{version}-%{release}
Requires:	elliptics-c++ = %{version}-%{release}


%description c++-devel
Elliptics library C++ binding development headers and libraries
for building C++ applications with elliptics.

%prep
%setup -q

%build
export LDFLAGS="-Wl,-z,defs"
./autogen.sh
%if 0%{?rhel} < 6
export PYTHON=/usr/bin/python26
CXXFLAGS="-pthread -I/usr/include/boost141" LDFLAGS="-L/usr/lib64/boost141" %configure --with-boost-libdir=/usr/lib64/boost141
%else
%configure
%endif


make %{?_smp_mflags}

%install
rm -rf %{buildroot}

make install DESTDIR=%{buildroot}
rm -f %{buildroot}%{_libdir}/*.a
rm -f %{buildroot}%{_libdir}/*.la

%post -p /sbin/ldconfig
%postun -p /sbin/ldconfig


%post python -p /sbin/ldconfig
%postun python -p /sbin/ldconfig


%post c++ -p /sbin/ldconfig
%postun c++ -p /sbin/ldconfig


%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc AUTHORS AUTHORS COPYING README
%{_bindir}/*
%{_libdir}/libelliptics.so.*


%files devel
%defattr(-,root,root,-)
%{_includedir}/*
%{_libdir}/libelliptics.so

%files python
%defattr(-,root,root,-)
%{_libdir}/libelliptics_python.so.*


%files python-devel
%defattr(-,root,root,-)
%{_libdir}/libelliptics_python.so


%files c++
%defattr(-,root,root,-)
%{_libdir}/libelliptics_cpp.so.*


%files c++-devel
%defattr(-,root,root,-)
%{_libdir}/libelliptics_cpp.so


%changelog
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
