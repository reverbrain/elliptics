Summary:	Distributed hash table storage
Name:		elliptics
Version:	2.15.0.1
Release:	1%{?dist}

License:	GPLv2+
Group:		System Environment/Libraries
URL:		http://www.ioremap.net/projects/elliptics
Source0:	%{name}-%{version}.tar.bz2
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%if 0%{?rhel} < 6
BuildRequires:	python26-devel, boost141-python, boost141-devel
BuildRequires:  boost141-iostreams, boost141-filesystem, boost141-thread, boost141-python, boost141-system
%else
BuildRequires:  python-devel, boost-python, boost-devel, boost-iostreams, boost-filesystem, boost-thread, boost-python, boost-system
%endif
BuildRequires:	eblob-devel >= 0.16.0
BuildRequires:  smack >= 0.4.0
BuildRequires:	automake autoconf libtool

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
%{_libdir}/libelliptics_cocaine.so.*


%files devel
%defattr(-,root,root,-)
%{_includedir}/*
%{_libdir}/libelliptics.so
%{_libdir}/libelliptics_cocaine.so

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
- Dropped srw dependancy

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
