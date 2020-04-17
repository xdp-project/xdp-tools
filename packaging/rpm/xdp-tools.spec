Name:             xdp-tools
Version:          0.0.3
Release:          1%{?dist}
Summary:          Utilities and example programs for use with XDP

License:          GPLv2
URL:              https://github.com/xdp-project/%{name}
Source0:          https://github.com/xdp-project/%{name}/releases/download/v%{version}/xdp-tools-%{version}.tar.gz

BuildRequires:    libbpf-devel
BuildRequires:    elfutils-libelf-devel
BuildRequires:    zlib-devel
BuildRequires:    libpcap-devel
BuildRequires:    clang >= 10.0.0
BuildRequires:    llvm >= 10.0.0
BuildRequires:    make
BuildRequires:    gcc
BuildRequires:    pkgconfig
BuildRequires:    m4

# find-debuginfo produces empty debugsourcefiles.list
# disable the debug package to avoid rpmbuild error'ing out because of this
%global debug_package %{nil}
%global _hardened_build 1
# strip barfs on BPF files, override it as a workaround
%global __brp_strip_lto %{_bindir}/true
%global __brp_strip %{_bindir}/true

%description
Utilities and example programs for use with XDP

%package -n libxdp
Summary:          XDP helper library
Requires:         kernel-headers

%package -n libxdp-devel
Summary:          Development files for libxdp
Requires:         kernel-headers
Requires:         libxdp = %{version}-%{release}

%package -n libxdp-static
Summary:          Static library files for libxdp
Requires:         kernel-headers
Requires:         libxdp-devel = %{version}-%{release}

%description -n libxdp
The libxdp package contains the libxdp library for managing XDP programs,
used by the %{name} package

%description -n libxdp-devel
The libxdp-devel package contains headers used for building XDP programs using
libxdp.

%description -n libxdp-static
The libxdp-static package contains the static library version of libxdp.

%prep
%autosetup -p1 -n %{name}-%{version}


%build
export CFLAGS='%{build_cflags}'
export LDFLAGS='%{build_ldflags}'
export LIBDIR='%{_libdir}'
export PRODUCTION=1
export DYNAMIC_LIBXDP=1
export CLANG=%{_bindir}/clang
export LLC=%{_bindir}/llc
./configure
make %{?_smp_mflags}

%install
export DESTDIR='%{buildroot}'
export SBINDIR='%{_sbindir}'
export LIBDIR='%{_libdir}'
export MANDIR='%{_mandir}'
export HDRDIR='%{_includedir}/xdp'
make install

# Don't expose libxdp itself in -devel package just yet
rm -f %{buildroot}%{_includedir}/xdp/libxdp.h
rm -f %{buildroot}%{_libdir}/libxdp.so

%files
%{_sbindir}/xdp-filter
%{_sbindir}/xdp-loader
%{_sbindir}/xdpdump
%{_mandir}/man8/*
%{_libdir}/bpf/xdpfilt_*.o
%{_libdir}/bpf/xdpdump_*.o
%license LICENSE

%files -n libxdp
%{_libdir}/libxdp.so.0
%{_libdir}/libxdp.so.%{version}
%{_libdir}/bpf/xdp-dispatcher.o

%files -n libxdp-static
%{_libdir}/libxdp.a

%files -n libxdp-devel
%{_includedir}/xdp/*.h

%changelog
* Mon Apr 6 2020 Toke Høiland-Jørgensen <toke@redhat.com> 0.0.3-1
- Upstream update, add libxdp sub-packages

* Thu Nov 21 2019 Toke Høiland-Jørgensen <toke@redhat.com> 0.0.2-1
- Upstream update

* Fri Nov 8 2019 Toke Høiland-Jørgensen <toke@redhat.com> 0.0.1-1
- Initial release
