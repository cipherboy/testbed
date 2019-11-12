# Requirements

System is in FIPS mode before continuing and has the necessary dependencies:

    dnf install -y nss-devel gcc pkg-config make git nss-tools
    fips-mode-setup --enable && reboot

# Testing

First clone this repository:

    git clone https://github.com/cipherboy/testbed && cd testbed/nss-fips-import-keys

Then run each test case:

    cd import-symkey && make all

This should give output like:

    fips-mode-setup --check
    FIPS mode is enabled.
    mkdir -p nssdb
    echo "" > nssdb/password.txt
    certutil -N -d sql:nssdb -f nssdb/password.txt
    ./a.out ./nssdb
    Succeeded in importing key.

You know that you're in FIPS mode by the line:

    FIPS mode is enabled.

You know that you're able to use this imported key by the line:

    Succeeded in importing key.
