# rpmtestbase

Testing RPM signature validation.

## Dependencies

The `createrepo` package is required to create a local repository to test the
update procedure. Install it with:

	yum install createrepo

If you wish to rebuild the packages from scratch, please make sure `rpmbuild`
is installed:

	yum install rpm-build


## Overview

This demonstrates the signature validation of `yum` and `rpm`. This is done
using a separate package, `rpmtestbase` which places a file in
`/usr/share/rpmtestbase` containing the version number of the package as
currently installed.

The basic steps are as follows. Make sure script execution begins in this
directory and that all commands are run as root. All scripts are documented,
and explain more about what they do internally.

Please update your system before continuing. It is also recommend to disable
the default Red Hat repositories and perform the verification on a spare
machine. To disable enabled repositories:

    # sed 's/enabled[ ]*=[ ]*1/enabled  =  0/g' /etc/yum.repos.d/redhat.repo -i

To later enable the previously disabled repositories:

    # sed 's/enabled  =  0/enabled = 1/g' /etc/yum.repos.d/redhat.repo -i

Also, please make sure that all shell scripts are executable:

    # chmod +x ./*.sh ./packages/*/build.sh


## Testing package update mechanims

Before beginning, either rebuild the packages (covered later), or use the
existing packages provided in this distribution. First, use RPM to
validate all packages. Note that this isn't part of the update testing
procedure but provides diagnostic information. First, install the RPM
key:

    # ./install-valid-key.sh

To later uninstall that key (if desired):

    # ./uninstall-valid-key.sh

Then, run:

    # rpm --checksig -v <path>

on each `rpmtestbase` package under `packages/`. These are:

    packages/rpmtestbase-v1-good/rpmtestbase-1-1.x86_64.rpm
    packages/rpmtestbase-v2-nosign/rpmtestbase-2-2.x86_64.rpm
    packages/rpmtestbase-v3-wrongkey/rpmtestbase-3-3.x86_64.rpm
    packages/rpmtestbase-v4-badsign/rpmtestbase-4-4.x86_64.rpm
    packages/rpmtestbase-v5-valid/rpmtestbase-5-5.x86_64.rpm


### Installing a valid base package

To begin, we need a package we can ship updates for. This is `rpmtestbase` at
version 1. Start by creating a repo with this package version:

    # ./v1.sh

Then, install the package:

    # yum install rpmtestbase

Note that you'll be prompted to confirm the GPG key installation as this key
is new. The repo is set up to trust the following key:

    pub   4096R/B903B604 2018-12-18 [expires: 2023-12-17]
    uid                  RPMTestBase Valid <valid@rpmtestbase.com>
    sub   4096R/2DF86DA2 2018-12-18 [expires: 2023-12-17]

The following key is untrusted:

    pub   4096R/0D811EFA 2018-12-18 [expires: 2023-12-17]
    uid                  RPMTestBase Invalid <invalid@rpmtestbase.com>
    sub   4096R/D34E2131 2018-12-18 [expires: 2023-12-17]

Both of these keys are shipped in the `keys/` folder.

To validate that this package is installed correctly:

    # cat /usr/share/rpmtestbase

It should mention version 1.


### Updating to an unsigned package (case d)

To validate that `yum` will not let you update to an unsigned package, run:

    # ./v2.sh

Then, update normally:

    # yum upgrade

Press `y` to continue. Note that `yum` will not install the package, and
checking the `/usr/share/rpmtestbase` should still report version 1:

    # cat /usr/share/rpmtestbase


### Updating to a package signed by an unknown key (case c)

To validate that `yum` will not let you update to a package signed by an
unkown key, run:

    # ./v3.sh

Then, update normally:

    # yum upgrade

Press `y` to continue. Note that `yum` will not install the package, and
checking the `/usr/share/rpmtestbase` should still report version 1:

    # cat /usr/share/rpmtestbase


### Updating to a package with corrupt signature (case b)

To validate that `yum` will not let you update to an unsigned package, run:

    # ./v4.sh

Then, update normally:

    # yum upgrade

Press `y` to continue. Note that `yum` will not install the package, and
checking the `/usr/share/rpmtestbase` should still report version 1:

    # cat /usr/share/rpmtestbase


### Updating with a valid update (case a)

To validate that `yum` will let you update if the update is correctly signed,
run:

    # ./v5.sh

Then, update normally:

    # yum upgrade

Note that `yum` installs the package and version 5 is reported:

    # cat /usr/share/rpmtestbase


## Additional information

Note that we recreate the repository each time from `repos-testing.repo` in
this distribution. If you wish to experiment with `gpgcheck=0` and other
repository options, modify it here before calling one of the package
version scripts.

Note that `gpgcheck=0` disables all signature validation and is not
recommended or supported.
