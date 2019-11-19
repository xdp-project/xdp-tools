%global srcname xdp-tools

Name:             xdp-tools
Version:          0.0.1
Release:          1%{?dist}
Summary:          Utilities and example programs for use with XDP

License:          GPLv2
URL:              https://github.com/xdp-project/%{name}
Source0:          https://github.com/xdp-project/%{name}/releases/download/v%{version}/xdp-tools-%{version}.tar.gz

BuildArch:        x86_64
BuildRequires:    libbpf-devel
BuildRequires:    elfutils-libelf-devel
BuildRequires:    clang >= 9.0.0
BuildRequires:    llvm >= 9.0.0
BuildRequires:    make
BuildRequires:    gcc
BuildRequires:    pkgconfig

%global debug_package %{nil}

%description
Utilities and example programs for use with XDP

%prep
%autosetup -p1 -n %{name}-%{version}


%build
export CFLAGS='%{optflags}'
export LDFLAGS='%{build_ldflags}'
export LIBDIR='%{_libdir}'
export PRODUCTION=1
./configure
make %{?_smp_mflags}

%install
export DESTDIR='%{buildroot}'
export SBINDIR='%{_sbindir}'
export LIBDIR='%{_libdir}'
make install

%files
%{_sbindir}/xdp-filter
%{_libdir}/bpf/*.o


%changelog
* Fri Nov 8 2019 Toke Høiland-Jørgensen <toke@redhat.com> 0.0.1-1
- Initial release
