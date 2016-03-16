
%define ver %(echo $Version)
%define rel %(echo $Release)

Summary: Utility in CloudOS project for High Availability cluster systems using
Name: ha-agent
Version: %{ver}
Release: %{rel}
License: GPL
Group: CCMA ITRI
Source: ha-agent-%{version}-%{release}.tar.gz
URL: http://www.itri.org.tw/
Buildroot: %{_tmppath}/%{name}-%{version}-%{release}
Provides: %{name}-%{version}-%{release}
Requires: chkconfig libslb
AutoReqProv: no
%description
ha-agent is a daemon run in CloudOS project to arrive the High Availability function
%define debug_package %{nil}
%define __strip /bin/true

%prep
%setup -n %{name}-%{version}
%build
%install
pwd
rm -rf %{buildroot}
make install BUILD_ROOT=%{buildroot}

%files
/usr/cloudos/slb/sbin/ha-agent
/etc/rc.d/init.d/ha-agent

%post
/sbin/chkconfig --add ha-agent
OS_VER=`head -n1 /etc/issue | awk '{print $3}'`
if [ "$OS_VER" == "5.5" ]; then
    if [ `cat /etc/syslog.conf |grep -c 'ha-agent.log'` == 0 ]; then
    /bin/echo "local5.*                        /var/log/ha-agent.log" >> /etc/syslog.conf
    service syslog restart
    fi
else
    if [ `cat /etc/rsyslog.conf |grep -c 'ha-agent.log'` == 0 ]; then
    /bin/echo "local5.*                        /var/log/ha-agent.log" >> /etc/rsyslog.conf
    service rsyslog restart
    fi
fi

%preun
/sbin/chkconfig --del ha-agent
if [ `ps ax |grep '/usr/cloudos/slb/sbin/ha-agent' |grep -v 'grep' -c` == 1 ]; then
service ha-agent stop
fi

%clean
rm -rf  %{buildroot}/%{name}
rm -rf  %{buildroot}

%postun
rmdir --ignore-fail-on-non-empty /usr/cloudos/slb/sbin
rmdir --ignore-fail-on-non-empty /usr/cloudos/slb

%changelog
* Mon Jul 07 2014 Simon Chuang <shangyichuang@itri.org.tw>
- update for SP4 package
* Fri May 11 2012 Hogan Lee <hogan_lee@itri.org.tw>
- created for version 1.0
