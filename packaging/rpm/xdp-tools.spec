Name:             xdp-tools
Version:          1.5.5
Release:          1%{?dist}
Summary:          Utilities and example programs for use with XDP
%global _soversion 1.5.0

License:          GPL-2.0-only
URL:              https://github.com/xdp-project/%{name}
Source0:          https://github.com/xdp-project/%{name}/releases/download/v%{version}/xdp-tools-%{version}.tar.gz

BuildRequires:    kernel-headers
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
BuildRequires:    emacs-nox
BuildRequires:    wireshark-cli
BuildRequires:    bpftool

ExcludeArch:      i386 i686

# Always keep xdp-tools and libxdp packages in sync
Requires:         libxdp = %{version}-%{release}

# find-debuginfo produces empty debugsourcefiles.list
# disable the debug package to avoid rpmbuild error'ing out because of this
%global debug_package %{nil}
%global _hardened_build 1

%description
Utilities and example programs for use with XDP

%package -n libxdp
Summary:          XDP helper library
License:          LGPL-2.1-only OR BSD-2-Clause

%package -n libxdp-devel
Summary:          Development files for libxdp
License:          LGPL-2.1-only OR BSD-2-Clause
Requires:         kernel-headers
Requires:         libxdp = %{version}-%{release}

%package -n libxdp-static
Summary:          Static library files for libxdp
License:          LGPL-2.1-only OR BSD-2-Clause
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
export RUNDIR='%{_rundir}'
export CLANG=$(which clang)
export PRODUCTION=1
export DYNAMIC_LIBXDP=1
export FORCE_SYSTEM_LIBBPF=1
export FORCE_EMACS=1
./configure
make %{?_smp_mflags} V=1

%install
export DESTDIR='%{buildroot}'
export SBINDIR='%{_sbindir}'
export LIBDIR='%{_libdir}'
export RUNDIR='%{_rundir}'
export MANDIR='%{_mandir}'
export DATADIR='%{_datadir}'
export HDRDIR='%{_includedir}/xdp'
make install V=1

%files
%{_sbindir}/xdp-bench
%{_sbindir}/xdp-filter
%{_sbindir}/xdp-forward
%{_sbindir}/xdp-loader
%{_sbindir}/xdp-monitor
%{_sbindir}/xdp-trafficgen
%{_sbindir}/xdpdump
%{_mandir}/man8/*
%{_libdir}/bpf/xdpfilt_*.o
%{_libdir}/bpf/xdpdump_*.o
%{_datadir}/xdp-tools/
%license LICENSES/*

%files -n libxdp
%{_libdir}/libxdp.so.1
%{_libdir}/libxdp.so.%{_soversion}
%{_libdir}/bpf/xdp-dispatcher.o
%{_libdir}/bpf/xsk_def_xdp_prog*.o
%{_mandir}/man3/*
%license LICENSES/*

%files -n libxdp-static
%{_libdir}/libxdp.a

%files -n libxdp-devel
%{_includedir}/xdp/*.h
%{_libdir}/libxdp.so
%{_libdir}/pkgconfig/libxdp.pc

%changelog
* Mon May 26 2025 Toke Høiland-Jørgensen <toke@redhat.com> 1.5.5-1
- Upstream version bump

* Mon Apr 28 2025 Toke Høiland-Jørgensen <toke@redhat.com> 1.5.4-1
- Upstream version bump

* Fri Mar 7 2025 Toke Høiland-Jørgensen <toke@redhat.com> 1.5.3-1
- Upstream version bump

* Wed Feb 19 2025 Toke Høiland-Jørgensen <toke@redhat.com> 1.5.2-1
- Upstream version bump

* Tue Jan 14 2025 Toke Høiland-Jørgensen <toke@redhat.com> 1.5.1-1
- Upstream version bump

* Thu Jan 9 2025 Toke Høiland-Jørgensen <toke@redhat.com> 1.5.0-1
- Upstream version bump

* Tue Aug 6 2024 Toke Høiland-Jørgensen <toke@redhat.com> 1.4.3-1
- Upstream version bump

* Tue Jan 30 2024 Toke Høiland-Jørgensen <toke@redhat.com> 1.4.2-1
- Upstream version bump

* Fri Oct 20 2023 Toke Høiland-Jørgensen <toke@redhat.com> 1.4.1-1
- Upstream version bump

* Thu Jul 6 2023 Toke Høiland-Jørgensen <toke@redhat.com> 1.4.0-1
- Upstream version bump

* Thu Feb 23 2023 Toke Høiland-Jørgensen <toke@redhat.com> 1.3.1-1
- Upstream version bump

* Tue Feb 7 2023 Toke Høiland-Jørgensen <toke@redhat.com> 1.3.0-1
- Upstream version bump

* Thu Jan 20 2022 Toke Høiland-Jørgensen <toke@redhat.com> 1.2.2-1
- Upstream version bump

* Thu Jan 13 2022 Toke Høiland-Jørgensen <toke@redhat.com> 1.2.1-1
- Upstream version bump

* Wed Jul 7 2021 Toke Høiland-Jørgensen <toke@redhat.com> 1.2.0-1
- Upstream version bump

* Wed Feb 3 2021 Toke Høiland-Jørgensen <toke@redhat.com> 1.1.1-1
- Upstream version bump

* Mon Jan 4 2021 Toke Høiland-Jørgensen <toke@redhat.com> 1.1.0-1
- Upstream version bump

* Thu Aug 20 2020 Toke Høiland-Jørgensen <toke@redhat.com> 1.0.1-1
- Upstream version bump

* Tue Aug 18 2020 Toke Høiland-Jørgensen <toke@redhat.com> 1.0.0-1
- Upstream version bump

* Wed Jul 15 2020 Eelco Chaudron <echaudro@redhat.com> 1.0.0~beta3-0.1
- Upstream version bump

* Fri Jul 10 2020 Toke Høiland-Jørgensen <toke@redhat.com> 1.0.0~beta2-0.1
- Upstream version bump

* Mon Jun 15 2020 Toke Høiland-Jørgensen <toke@redhat.com> 1.0.0~beta1-0.1
- Upstream version bump

* Mon Apr 6 2020 Toke Høiland-Jørgensen <toke@redhat.com> 0.0.3-1
- Upstream update, add libxdp sub-packages

* Thu Nov 21 2019 Toke Høiland-Jørgensen <toke@redhat.com> 0.0.2-1
- Upstream update

* Fri Nov 8 2019 Toke Høiland-Jørgensen <toke@redhat.com> 0.0.1-1
- Initial release
