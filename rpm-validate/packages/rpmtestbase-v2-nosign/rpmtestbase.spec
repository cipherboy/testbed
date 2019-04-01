Name: rpmtestbase
Version: 2
Release: 2
Summary: A test package for CC. Tests RPM validation.
License: AGPLv3
URL: http://neverssl.com
Source0: rpmtestbase

%prep
%build
%install
install -D -m 644 %{SOURCE0} %{buildroot}/usr/share/rpmtestbase

%files
/usr/share/rpmtestbase

%description
A test package for CC. Tests RPM validation.


%changelog
* Mon Dec 17 2018 Alex Scheel <ascheel@redhat.com> - 2-2
- Version 2 of the package. No signature; invalid.

* Mon Dec 17 2018 Alex Scheel <ascheel@redhat.com> - 1-1
- Version 1 of the package. Valid and signed.
