Name:             xdp-tools
Version:          0.0.2
Release:          1%{?dist}
Summary:          Utilities and example programs for use with XDP

License:          GPLv2
URL:              https://github.com/xdp-project/%{name}
Source0:          https://github.com/xdp-project/%{name}/releases/download/v%{version}/xdp-tools-%{version}.tar.gz

BuildRequires:    elfutils-libelf-devel
BuildRequires:    clang >= 9.0.0
BuildRequires:    llvm >= 9.0.0
BuildRequires:    make
BuildRequires:    gcc
BuildRequires:    pkgconfig

# find-debuginfo produces empty debugsourcefiles.list
# disable the debug package to avoid rpmbuild error'ing out because of this
%global debug_package %{nil}
%global _hardened_build 1

%description
Utilities and example programs for use with XDP

%package devel
Summary:          Development files for %{name}
Requires:         %{name} = %{version}-%{release}
Requires:         kernel-headers

%description devel
The %{name}-devel package contains libraries header files for
developing applications that use %{name}

%prep
%autosetup -p1 -n %{name}-%{version}


%build
export CFLAGS='%{build_cflags}'
export LDFLAGS='%{build_ldflags}'
export LIBDIR='%{_libdir}'
export PRODUCTION=1
./configure
make %{?_smp_mflags}

%install
export DESTDIR='%{buildroot}'
export SBINDIR='%{_sbindir}'
export LIBDIR='%{_libdir}'
export MANDIR='%{_mandir}'
export HDRDIR='%{_includedir}/xdp'
make install

%files
%{_sbindir}/xdp-filter
%{_mandir}/man8/*
%{_libdir}/bpf/*.o

%files devel
%{_includedir}/xdp/

%changelog
* Thu Nov 21 2019 Toke Høiland-Jørgensen <toke@redhat.com> 0.0.2-1
- Upstream update

* Fri Nov 8 2019 Toke Høiland-Jørgensen <toke@redhat.com> 0.0.1-1
- Initial release
