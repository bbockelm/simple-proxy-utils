
Name: simple-proxy-utils
Version: 0.1.0
Release: 1%{?dist}
Summary: Utilities for interacting with X509 proxy certificates.

Group: System Environment/Daemons
License: BSD
URL: https://github.com/bbockelm/simple-proxy-utils
# Generated from:
# git archive v%{version} --prefix=simple-proxy-utils-%{version}/ | gzip -7 > ~/rpmbuild/SOURCES/simple-proxy-utils-%{version}.tar.gz
Source0: %{name}-%{version}.tar.gz
BuildRequires: cmake
BuildRequires: voms-devel
# For Globus-based chain verification
BuildRequires: globus-gsi-credential-devel
BuildRequires: globus-gsi-cert-utils-devel
BuildRequires: globus-common-devel
BuildRequires: globus-gsi-sysconfig-devel
BuildRequires: globus-gsi-callback-devel

%description
%{summary}

%prep
%setup -q

%build

%if 0%{?el6}
echo "*** This version does not build on EL 6 ***"
exit 1
%endif

%cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo .
make VERBOSE=1 %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
# We keep the .so here (and not in a -devel subpackage) because it is actually
# a module.
%{_libdir}/libSimpleProxyUtils.so
%{python_sitelib}/simple_proxy_utils.py

%changelog
* Sat Oct 27 2018 Brian Bockelman <bbockelm@cse.unl.edu> - 0.1.0-1
- Initial version of the proxy utilities.

