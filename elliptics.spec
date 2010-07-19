Summary:	Distributed hash table storage
Name:		elliptics
Version:	2.9.0.7
Release:	1%{?dist}

License:	GPLv2+
Group:		System Environment/Libraries
URL:		http://www.ioremap.net/projects/elliptics
Source0:	%{name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:	libevent-devel >= 1.3
BuildRequires:	fcgi-devel
BuildRequires:	openssl-devel
BuildRequires:	python-devel
BuildRequires:	boost-python
BuildRequires:	boost-devel
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
%{_libdir}/libelliptics_blob.so.*


%files devel
%defattr(-,root,root,-)
%{_includedir}/*
%{_libdir}/libelliptics.so
%{_libdir}/libelliptics_blob.so

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
* Mon Jul 19 2010 Arkady L. Shane <ashejn@yandex-team.ru> - 2.9.0.7-1
- initial build for Fedora
