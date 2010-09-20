Summary:	Distributed hash table storage
Name:		elliptics
Version:	2.9.2.22
Release:	1%{?dist}

License:	GPLv2+
Group:		System Environment/Libraries
URL:		http://www.ioremap.net/projects/elliptics
Source0:	%{name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:	fcgi-devel
BuildRequires:	openssl-devel
BuildRequires:	python-devel
BuildRequires:	boost-python
BuildRequires:	boost-devel
BuildRequires:	eblob-devel
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
%configure 

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
