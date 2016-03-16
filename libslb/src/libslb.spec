
%define ver %(echo $Version)
%define rel %(echo $Release)

Summary: SLB library
Name: libslb
Version: %{ver}
Release: %{rel}
License: GPL
Group: CCMA ITRI
Source: libslb-%{version}-%{release}.tar.gz
URL: http://www.itri.org.tw/
Buildroot: %{_tmppath}/%{name}-%{version}-%{release}
Provides: %{name}-%{version}-%{release}
Requires: chkconfig
AutoReqProv: no
%description
libslb is a library for other component using.
%define debug_package %{nil}
%define __strip /bin/true

%prep
%setup -n %{name}-%{version}
%build
make
%install
rm -rf %{buildroot}
make install BUILD_ROOT=%{buildroot}

%files
/usr/cloudos/slb/lib/libslb.so
/usr/cloudos/slb/include/libsock-ipc.h
/usr/cloudos/slb/include/libha.h
/usr/cloudos/slb/include/logger.h
/usr/cloudos/slb/include/signals.h
/usr/cloudos/slb/include/daemon.h
/usr/cloudos/slb/include/list.h
/usr/cloudos/slb/include/libslbipc.h
/usr/cloudos/slb/include/slb_communicator_message_type.h
/usr/cloudos/slb/include/timerThread.h
/usr/cloudos/slb/include/libslb-netif.h
/usr/cloudos/slb/include/uiciname.h
/usr/cloudos/slb/include/librs_c_session.h
/usr/cloudos/slb/include/librs_IEL.h
/usr/cloudos/slb/include/librs_L2.h
/usr/cloudos/slb/include/librs_SLB.h
/usr/cloudos/slb/include/librs_Monitor.h
/usr/cloudos/slb/include/librs_security.h

%post

%preun

%clean
rm -rf  %{buildroot}/%{name}
rm -rf  %{buildroot}

%postun
rmdir --ignore-fail-on-non-empty /usr/cloudos/slb/lib
rmdir --ignore-fail-on-non-empty /usr/cloudos/slb/include
rmdir --ignore-fail-on-non-empty /usr/cloudos/slb

%changelog
* Mon Mar 12 2012 Hogan Lee <s30011w@gmail.com>
- created for version 1.0
