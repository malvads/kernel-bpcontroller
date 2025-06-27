%{?!module_name: %{error: You did not specify a module name (%%module_name)}}
%{?!version: %{error: You did not specify a module version (%%version)}}
%{?!kernel_versions: %{error: You did not specify kernel versions (%%kernel_versions)}}
%{?!packager: %define packager DKMS <dkms-devel@lists.us.dell.com>}
%{?!license: %define license GPL}
%{?!_dkmsdir: %define _dkmsdir /var/lib/dkms}
%{?!_srcdir: %define _srcdir %{_prefix}/src}
%{?!_datarootdir: %define _datarootdir %{_datadir}}
%define _unitdir %{_prefix}/lib/systemd/system

Summary:    %{module_name} %{version} DKMS package
Name:       %{module_name}-dkms
Version:    %{version}
Release:    %{release}
License:    %license
BuildArch:  noarch
Group:      System/Kernel
Requires:   dkms, kernel-headers, kernel-devel, make
BuildRequires: dkms, kernel-devel
BuildRoot:  %{_tmppath}/%{name}-%{version}-%{release}-root/

%description
DKMS-based kernel module for %{module_name} %{version}.

%prep
# Nothing needed

%install
# Install source module
mkdir -p $RPM_BUILD_ROOT/%{_srcdir}
cp -r %{_sourcedir}/%{module_name}-%{version} $RPM_BUILD_ROOT/%{_srcdir}/

# Install systemd service
mkdir -p $RPM_BUILD_ROOT%{_unitdir}
cp %{_sourcedir}/rb_bpwatcher.service $RPM_BUILD_ROOT%{_unitdir}/

%files
%defattr(-,root,root)
%{_srcdir}/%{module_name}-%{version}
%{_unitdir}/rb_bpwatcher.service

%post
dkms add -m %{module_name} -v %{version} || exit 1
dkms build -m %{module_name} -v %{version} || exit 1
dkms install -m %{module_name} -v %{version} --force || exit 1
depmod -a

if ! lsmod | grep -q bpctl_mod; then
    bpctl_start
    /sbin/modprobe %{module_name} || exit 1
fi

systemctl daemon-reexec
systemctl daemon-reload
systemctl enable rb_bpwatcher.service || true

%preun
# $1 == 0 means package removal (not upgrade)
if [ $1 -eq 0 ]; then
    systemctl stop rb_bpwatcher.service || true
    systemctl disable rb_bpwatcher.service || true
    systemctl daemon-reload
fi

dkms remove -m %{module_name} -v %{version} --all || true
