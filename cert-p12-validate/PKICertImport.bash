#!/bin/bash

# Copyright (C) 2018 Red Hat

# PKICertImport performs a validate-then-import strategy for importing
# certificates into a NSS DB or HSM Token by wrapping both calls to
# certutil (`certutil -A` and `certutil -V`) such that the certificate
# will be removed if import fails (`certutil -D`). This helps to ensure
# that certificates are not used prior to validation.
function PKICertImport() {
    ## [ overview ] ##

    # This script has four major sections:
    #
    #   1. Globals -- the definitions of all script-global variables
    #   2. Helper functions -- functions which don't perform key operations
    #   3. Core commands -- functions which interact with the NSS DB via
    #                       certutil
    #   4. Program flow -- main flow of the program


    ## [ globals ] ##

    # Path to certificate; parsed from arguments.
    local CERT_PATH=""

    # User-given nickname for the certificate.
    local CERT_NICKNAME=""

    # Whether or not the certificate is in ASCII/PEM format.
    local CERT_ASCII="false"

    # Wehther or not the certificate is in PKCS12 format.
    local CERT_PKCS12="false"

    # What trust flags to use when importing the certificate.
    local CERT_TRUST=""

    # What usage flags to validate the certificate against.
    local CERT_USAGE=""

    # File containing password for PKCS12 certificate store, if present.
    local PKCS12_PASSWORD=""

    # Whether or not to validate the entire chain from a .p12 file, or just
    # the leaf certificate.
    local PKCS12_CHAIN="false"

    # Location of PKCS12's leaf certificate file
    local PKCS12_CERT_PATH=""

    # Intermediate certificate trust flags
    local PKCS12_CHAIN_TRUST=""

    # Intermediate certificate trust flags
    local PKCS12_CHAIN_USAGE=""

    # List of PKCS12 CA certificates.
    local PKCS12_NODES=()

    # When true, modify trust flags prior to verification (certutil -V). This
    # allows you to import new root CAs.
    local PKCS12_UNSAFE="false"

    # Location of the original NSS DB.
    local NSSDB=""

    # Type of the NSSDB.
    local NSSDB_TYPE=""

    # Location to the NSS DB Password file, if present.
    local NSSDB_PASSWORD=""

    # Name of the HSM token, if used.
    local HSM_TOKEN=""

    # Base location of temporary directory, when used.
    local TMPBASE=""

    ## [ helper functions ] ##

    # __e prints error messages, prefixing them with "e: " and writing the
    # output to stderr instead of stdout.
    function __e() {
        echo "e:" "$@" 1>&2
    }

    # __v prints debug messages in verbose mode; these also go to stderr.
    # Messages are only present if the environment variable VERBOSE is set.
    function __v() {
        if [ "x$VERBOSE" != "x" ]; then
            echo "v:" "$@" 1>&2
        fi
    }

    # __secure_mktmp fills the TMPBASE variable with the path to a directory
    # we can use that has permissions restricted to our current user. This
    # will be where we split the .pk12 to.
    #
    # Failures are fatal, so use exit instead of return.
    function __secure_mktmp() {
        local tmpdir="$TMPDIR"
        local ret=0

        # Prefer /dev/shm over /tmp: /dev/shm is less frequently backed by
        # a physical disk than /tmp. However, if TEMPDIR is explicitly set,
        # respect it.
        if [ "x$tmpdir" == "x" ] && [ -d "/dev/shm" ]; then
            tmpdir="/dev/shm"
        elif [ "x$tmpdir" == "x" ] && [ -d "/tmp" ]; then
            tmpdir="/tmp"
        elif [ "x$tmpdir" == "x" ]; then
            tmpdir="$HOME"
        fi

        TMPBASE="$(mktemp --directory --tmpdir="$tmpdir" 2>&1)"
        ret="$?"

        if (( ret != 0 )); then
            __e "Return from mktemp was non-zero: $ret"
            __e "$TMPBASE"
            __e "Perhaps specify TMPDIR in the environment?"
            exit 1
        elif [ ! -d "$TMPBASE" ]; then
            __e "Return from mktemp was zero but invalid directory:"
            __e "$TMPBASE"
            __e "Perhaps specify TMPDIR in the environment?"
            exit 1
        fi

        # We've validated that TMPBASE is now a valid directory. Since
        # we created it, we have ownership. Restrict access to only this
        # user as the original NSS DB might have private keys which we want
        # to keep secure when copying.

        local user=""
        local group=""

        # Acquire current username.
        user="$(id --user --name 2>&1)"
        ret=$?
        if (( ret != 0 )); then
            __e "id exited with non-zero result: $ret"
            __e "Unable to get current user's name."
            __secure_rmtmp
            exit 1
        fi

        # Acquire current primary group.
        group="$(id --group --name 2>&1)"
        ret=$?
        if (( ret != 0 )); then
            __e "id exited with non-zero result: $ret"
            __e "Unable to get current user's name."
            __secure_rmtmp
            exit 1
        fi

        # Restrict permissions from
        chown "$user:$group" -R "$TMPBASE"
        ret=$?
        if (( ret != 0 )); then
            __e "Return from chown on $TMPBASE was non-zero: $ret"
            __secure_rmtmp
            exit 1
        fi

        chmod 700 -R "$TMPBASE"
        ret=$?
        if (( ret != 0 )); then
            __e "Return from chmod on $TMPBASE was non-zero: $ret"
            __secure_rmtmp
            exit 1
        fi

        return 0
    }

    ## __secure_rmtmp removes the temporary directory if present. If the shred
    ## command is present, removes files with shred.
    function __secure_rmtmp() {
        if [ -d "$TMPBASE" ]; then
            if command -v shred >/dev/null 2>&1; then
                find "$TMPBASE" -type f -print0 | xargs -0 shred -f -n 2 -z
            fi
            rm -rf "$TMPBASE"
        fi
    }

    ## [ core commands ] ##

    # Parse the command line arguments and set the appropriate global
    # variables. Return status of non-zero indicates a fatal error; help
    # should be displayed. Return status of zero indicates no error and help
    # should not be displayed.
    function _parse_args() {
        # Use a read-and-shift approach to parse both "<option>" and
        # "<option> <value>" forms.
        while (( $# > 0 )); do
            local arg="$1"
            shift

            # Sorted alphabetically by short option.
            if [ "x$arg" == "x--ascii" ] || [ "x$arg" == "x-a" ]; then
                # If specified, the -a flag is passed when the certificate is
                # imported.
                CERT_ASCII="true"
            elif [ "x$arg" == "x--chain" ] || [ "x$arg" == "x-c" ]; then
                # If specified, validate the entire PKCS12 chain.
                PKCS12_CHAIN="true"
            elif [ "x$arg" == "x--database" ] || [ "x$arg" == "x-d" ]; then
                # Always required; path to the original NSS DB. Note that this
                # differs from certutil in that we detect the NSSDB type here,
                # versus taking a prefix:path combination.
                NSSDB="$1"

                if [ -e "$NSSDB/cert8.db" ] && [ ! -e "$NSSDB/cert9.db" ]; then
                    NSSDB_TYPE="dbm:"
                elif [ ! -e "$NSSDB/cert8.db" ] && [ -e "$NSSDB/cert9.db" ]; then
                    NSSDB_TYPE="sql:"
                else
                    __e "Unknown NSS DB type for directory: $NSSDB"
                    __e "Please ensure only one of cert8.db or cert9.db exist"
                    return 1
                fi

                shift
            elif [ "x$arg" == "x--password" ] || [ "x$arg" == "x-f" ]; then
                # If specified, path to a file containing the NSS DB password.
                NSSDB_PASSWORD="$1"
                shift
            elif [ "x$arg" == "x--hsm" ] || [ "x$arg" == "x-h" ]; then
                # If specified, name of the HSM Token.
                HSM_TOKEN="$1"
                shift
            elif [ "x$arg" == "x--certificate" ] || [ "x$arg" == "x-i" ]; then
                # Always required; path to the original certificate.
                CERT_PATH="$1"
                shift
            elif [ "x$arg" == "x--nickname" ] || [ "x$arg" == "x-n" ]; then
                # Always required; nickname for the certificate.
                CERT_NICKNAME="$1"
                shift
            elif [ "x$arg" == "x--pkcs12" ] || [ "x$arg" == "x-p" ]; then
                # If specified, the certificate file is in pkcs12 format.
                CERT_PKCS12="true"
            elif [ "x$arg" == "x--chain-trust" ] || [ "x$arg" == "x-r" ]; then
                # If specified, trust to apply to intermediate certificates.
                PKCS12_CHAIN_TRUST="$1"
                shift
            elif [ "x$arg" == "x--chain-usage" ] || [ "x$arg" == "x-s" ]; then
                # If specified, usage to validate intermediate certificates with.
                PKCS12_CHAIN_USAGE="$1"
                shift
            elif [ "x$arg" == "x--trust" ] || [ "x$arg" == "x-t" ]; then
                # Always required; certificate trust flags.
                CERT_TRUST="$1"
                shift
            elif [ "x$arg" == "x--usage" ] || [ "x$arg" == "x-u" ]; then
                # Always required; certificate usage flags.
                CERT_USAGE="$1"
                shift
            elif [ "x$arg" == "x--pkcs12-password" ] || [ "x$arg" == "x-w" ]; then
                # If specified, password file for the .p12 file.
                PKCS12_PASSWORD="$1"
                shift
            elif [ "x$arg" == "x--unsafe-trust-then-verify" ]; then
                # If specified, apply nss trust flags prior to verification
                # (certutil -V). This allows a .p12 to contain a root CA, and that
                # root CA to be trusted.
                __e "Warning --unsafe-trust-then-verify has been specified."
                __e "This option allows compromised .p12 to inject trusted root certificates."
                PKCS12_UNSAFE="true"
            elif [ "x$arg" == "x--help" ] || [ "x$arg" == "xhelp" ]; then
                return 2
            else
                # We print help whenever the return code is 1, so we don't
                # need to explicitly parse a --help flag, but we will get
                # an extraneous but harmless unknown argument message.
                __e "Unknown argument: $arg"
                __e "Check your option syntax; perhaps a prior argument is" \
                     "missing a value?"
                return 1
            fi
        done

        # Ensure that we've seen the required arguments and that our
        # combination of arguments makes sense.
        if [ "x$NSSDB" == "x" ]; then
            __e "Missing NSS Database location: specify --database/-d"
            return 1
        elif [ "x$CERT_PATH" == "x" ]; then
            __e "Missing certificate location: specify --certificate/-i"
            return 1
        elif [ "x$CERT_NICKNAME" == "x" ]; then
            __e "Missing certificate nickname: specify --nickname/-n"
            return 1
        elif [ "x$CERT_TRUST" == "x" ]; then
            __e "Missing certificate trust: specify --trust/-t"
            return 1
        elif [ "x$CERT_USAGE" == "x" ]; then
            __e "Missing certificate usage: specify --usage/-u"
            return 1
        elif [ "$CERT_ASCII" == "true" ] && [ "$CERT_PKCS12" == "true" ]; then
            __e "Can't specify both --ascii/-a and --pkcs12/-p"
            return 1
        elif [ "$CERT_PKCS12" == "false" ] && [ "x$PKCS12_PASSWORD" != "x" ]; then
            __e "Can't specify --pkcs12-password/-w without --pkcs12/-p"
            return 1
        elif [ "$CERT_PKCS12" == "false" ] && [ "$PKCS12_CHAIN" == "true" ]; then
            __e "Can't specify --chain/-c without --pkcs12/-p"
            return 1
        elif [ "$CERT_PKCS12" == "false" ] && [ "x$PKCS12_CHAIN_TRUST" != "x" ]; then
            __e "Can't specify --chain-trust/-r without --pkcs12/-p"
            return 1
        elif [ "$CERT_PKCS12" == "false" ] && [ "x$PKCS12_CHAIN_USAGE" != "x" ]; then
            __e "Can't specify --chain-usage/-s without --pkcs12/-p"
            return 1
        elif [ "$CERT_PKCS12" == "false" ] && [ "$PKCS12_UNSAFE" == "true" ]; then
            __e "Can't specify --unsafe-trust-then-verify without --pkcs12/-p"
            return 1
        elif [ "$PKCS12_CHAIN" == "true" ] && [ "x$PKCS12_CHAIN_TRUST" == "x" ]; then
            __e "Can't specify --chain/-c without --chain-turst/-r"
            return 1
        elif [ "$PKCS12_CHAIN" == "true" ] && [ "x$PKCS12_CHAIN_USAGE" == "x" ]; then
            __e "Can't specify --chain/-c without --chain-usage/-s"
            return 1
        fi

        # All good to go.
        return 0
    }

    # Show help and usage information.
    function _print_help() {
        if (( $1 == 1 )); then
            echo ""
        fi

        echo "Usage: $0 [arguments]"
        echo "$0 validates and imports certificates."
        echo ""
        echo "Requred arguments:"
        echo "--database, -d <path>: path to the NSS DB"
        echo "--certificate, -i <path>: path to the certificate to import"
        echo "--nickname, -n <name>: nickname for the certificate"
        echo "--trust, -t <flags>: trust flags for the certificate"
        echo "--usage, -u <flag>: usage flag to verify the certificate with"
        echo ""
        echo "Optional arguments:"
        echo "--ascii, -a: the certificate is in ASCII encoded"
        echo "--chain, -c: check the entire PKCS12 chain; requires --pkcs12"
        echo "--password, -f <path>: password file for the NSS DB"
        echo "--pkcs12, -p: the certificate is a .p12/PKCS12 file"
        echo "--pkcs12-password, -w: password file for the .p12 file; requires --pkcs12"
        echo "--hsm, -h <name>: name of the HSM to use"
        echo ""
        echo "Environment variables:"
        echo "VERBOSE: see certutil commands being run"
        echo ""
        echo "For more information about these options, refer to the" \
             "certutil documentation."
    }

    # Import a certificate into the NSS DB specified on $1. Errors are fatal;
    # uses exit instead of return.
    function _import_cert() {
        local nickname="$1"
        local path="$2"
        local trust="$3"

        local ret=0
        local add_args=("-A")

        # Use a single import command, setting trust as we import.
        add_args+=("-d" "$NSSDB_TYPE$NSSDB")
        add_args+=("-n" "$nickname")
        if [ "x$NSSDB_PASSWORD" != "x" ]; then
            add_args+=("-f" "$NSSDB_PASSWORD")
        fi
        add_args+=("-i" "$path")
        if [ "$CERT_ASCII" == "true" ]; then
            add_args+=("-a")
        fi
        if [ "x$HSM_TOKEN" != "x" ]; then
            add_args+=("-h" "$HSM_TOKEN")
        fi
        add_args+=("-t" "$trust")

        # Import the certificate...
        __v certutil "${add_args[@]}"
        certutil "${add_args[@]}"
        ret=$?
        if (( ret != 0 )); then
            __e "certutil returned non-zero value: $ret"
            __e "Unable to import certificate to NSS DB: $NSSDB."
            exit $ret
        fi
    }

    # Trust certificate
    function _trust_cert() {
        local nickname="$1"
        local trust="$2"

        local ret=0
        local modify_args=("-M")
        modify_args+=("-d" "$NSSDB_TYPE$NSSDB")
        modify_args+=("-n" "$nickname")
        modify_args+=("-t" "$trust")

        # Modify the certificate to have the specified trust flags.
        __v certutil "${modify_args[@]}"
        certutil "${modify_args[@]}"

        # We intentionally ignore the return code on modification.
    }

    # Verify the certificate in the NSS DB specified by $1.
    function _verify_cert() {
        local nickname="$1"
        local usage="$2"

        local ret=0
        local verify_args=("-V")

        verify_args+=("-d" "$NSSDB_TYPE$NSSDB")
        verify_args+=("-n" "$nickname")
        verify_args+=("-u" "$usage")
        if [ "x$HSM_TOKEN" != "x" ]; then
            verify_args+=("-h" "$HSM_TOKEN")
        fi
        if [ "x$NSSDB_PASSWORD" != "x" ]; then
            verify_args+=("-f" "$NSSDB_PASSWORD")
        fi

        # Ensures that the signature is checked as well.
        verify_args+=("-e")

        # Validate the certificate. Note that we have to pattern match on the
        # output of certutil -V; the return code is uncorrelated with the
        # actual result. (It is dependent upon whether or not a HSM is used).
        __v certutil "${verify_args[@]}"

        local certutil_result=""
        certutil_result="$(certutil "${verify_args[@]}" 2>&1)"

        grep -q '^certutil: certificate is valid$' <<< "$certutil_result"
        ret=$?

        if (( ret != 0 )); then
            __e "$certutil_result" 1>&2
        fi

        return $ret
    }

    # Remove the certificate from the NSS DB specified by $1. Errors are fatal;
    # uses exit instead of return.
    function _remove_cert() {
        local nickname="$1"
        local return_no_exit="$2"

        local remove_args=("-D")

        remove_args+=("-d" "$NSSDB_TYPE$NSSDB")
        if [ "x$NSSDB_PASSWORD" != "x" ]; then
            remove_args+=("-f" "$NSSDB_PASSWORD")
        fi

        __v certutil "${remove_args[@]}" "-n" "$nickname"
        certutil "${remove_args[@]}" "-n" "$nickname"
        local ret=$?
        if (( ret != 0 )); then
            __e "certutil returned non-zero result: $ret"
            __e "Unable to delete certificate!"

            if [ "x$return_no_exit" != "xtrue" ]; then
                exit $ret
            else
                return $ret
            fi
        fi

        if [ "x$HSM_TOKEN" != "x" ]; then
            # In the event we have a HSM, we also have to remove it from the
            # HSM token.

            __v certutil "${remove_args[@]}" "-n" "$HSM_TOKEN:$nickname"
            certutil "${remove_args[@]}" "-n" "$HSM_TOKEN:$nickname"
            local ret=$?

            if (( ret != 0 )); then
                __e "certutil returned non-zero result: $ret"
                __e "Unable to delete certificate!"

                if [ "x$return_no_exit" != "xtrue" ]; then
                    exit $ret
                else
                    return $ret
                fi
            fi
        fi

        return 0
    }

    function _split_pkcs12() {
        local pkcs12_args=("pkcs12")
        PKCS12_CERT_PATH="$TMPBASE/certificate.crt"

        # Path to input .p12 file. We assume this is passed by --certificate/-i
        pkcs12_args+=("-in" "$CERT_PATH")

        # Only export the leaf certificate; this is the certificate we're
        # giving a nickname to.
        pkcs12_args+=("-clcerts")

        # Don't export the private key associated with the certificate.
        pkcs12_args+=("-nokeys")

        # Don't encrypt (no DES) the output certificate. It is a public key.
        pkcs12_args+=("-nodes")

        # Specify output path for the exported certificate.
        pkcs12_args+=("-out" "$PKCS12_CERT_PATH")

        if [ "x$arg" != "x$PKCS12_PASSWORD" ]; then
            # When specified, a path to a file containing the PKCS12 password.
            pkcs12_args+=("-passin" "file:$PKCS12_PASSWORD")

            __v openssl "${pkcs12_args[@]}"
            openssl "${pkcs12_args[@]}"
            ret=$?
            if (( ret != 0 )); then
                __e "openssl pkcs12 split returned: $ret"
                __secure_rmtmp
                exit $ret
            fi
        else
            __v openssl "${pkcs12_args[@]}"
            openssl "${pkcs12_args[@]}"
            ret=$?
            if (( ret != 0 )); then
                __e "openssl pkcs12 split returned: $ret"
                __secure_rmtmp
                exit $ret
            fi
        fi
    }

    function _import_pkcs12() {
        local before_listing=""
        local after_listing=""

        # List of known trust flags; combined from man pages and online
        # documentation.
        local tf="pPcCtTuw"

        # Arguments for listing certificates.
        local list_args=("-L")
        list_args+=("-d" "$NSSDB_TYPE$NSSDB")


        # Arguments for import
        local import_args=("-i" "$CERT_PATH")
        import_args+=("-d" "$NSSDB_TYPE$NSSDB")

        # When present, specify NSS DB password.
        if [ "x$NSSDB_PASSWORD" != "x" ]; then
            import_args+=("-k" "$NSSDB_PASSWORD")
        fi

        # When present, specify .p12 file password.
        if [ "x$PKCS12_PASSWORD" != "x" ]; then
            import_args+=("-w" "$PKCS12_PASSWORD")
        fi

        # List certificates prior to import.
        __v certutil "${list_args[@]}"
        before_listing="$(certutil "${list_args[@]}" | grep "[$tf]*,[$tf]*,[$tf]*" | sed "s/[[:space:]]*[$tf]*,[$tf]*,[$tf]*//g" | sed 's/[[:space:]]*$//g' | sort)"

        # Perform import
        __v pk12util "${import_args[@]}"
        pk12util "${import_args[@]}"
        ret=$?

        if (( ret != 0 )); then
            __e "Error importing certificates from .p12 file!"
            _remove_cert "$CERT_NICKNAME"
            __secure_rmtmp
            exit 1
        fi

        __v certutil "${list_args[@]}"
        after_listing="$(certutil "${list_args[@]}" | grep "[$tf]*,[$tf]*,[$tf]*" | sed "s/[[:space:]]*[$tf]*,[$tf]*,[$tf]*//g" | sed 's/[[:space:]]*$//g' | sort)"

        local before_file="$TMPBASE/before.txt"
        local after_file="$TMPBASE/after.txt"
        cat - > "$before_file" <<< "$before_listing"
        cat - > "$after_file" <<< "$after_listing"

        mapfile -t PKCS12_NODES < <(comm -13 "$before_file" "$after_file")
    }

    function _remove_all_certs() {
        # When we're removing all certificates, we don't care about the
        # return code; we only care that the certificates are removed...
        for cert in "${PKCS12_NODES[@]}"; do
            _remove_cert "$cert" "true"
        done

        _remove_cert "$CERT_NICKNAME" "true"
    }

    ## [ program flow ] ##
    local ret=0

    # The program flow of this script is:
    #
    # - Parse arguments
    #   - [print help if required]
    # - Create working directory
    # - Copy files into the working directory
    # - Import certificate into NSS DB
    # - Validate certificate in NSS DB
    #   - [on failure, remove from NSS DB]
    #
    # Import is handled by _import_cert, verification is handled by
    # _verify_cert, and removal is handled by _remove_cert.

    _parse_args "$@"
    ret="$?"
    if (( ret != 0 )); then
        _print_help $ret
        exit 1
    fi

    if [ "$CERT_PKCS12" == "false" ]; then
        _import_cert "$CERT_NICKNAME" "$CERT_PATH" "$CERT_TRUST"
        _verify_cert "$CERT_NICKNAME" "$CERT_USAGE"
        ret=$?

        # Check if the verification failed. If it did, remove it from the NSS DB.
        if (( ret != 0 )); then
            __e "Verification of certificate failed!"
            _remove_cert "$CERT_NICKNAME"
            exit 1
        fi
    else
        __secure_mktmp

        _split_pkcs12
        _import_cert "$CERT_NICKNAME" "$PKCS12_CERT_PATH" "$CERT_TRUST"
        _import_pkcs12

        # Optionally validate each missing certificate in the chain.
        for cert in "${PKCS12_NODES[@]}"; do
            echo "Checking chain certificate: $cert"

            # Trust certificate after validation -- !!UNSAFE!!
            if [ "$PKCS12_UNSAFE" == "true" ]; then
                _trust_cert "$cert" "$PKCS12_CHAIN_TRUST"
            fi

            if [ "$PKCS12_CHAIN" == "true" ]; then
                # When usage is a CA certificate, and since this certificate
                # was part of the chain, we need to ensure this is a "valid ca"
                # so (certutil -V) passes if the signature is valid and chained
                # to a known root.
                if [ "x$PKCS12_CHAIN_USAGE" == "xL" ]; then
                    echo "Initial trust"
                    _trust_cert "$cert" "c,c,"
                fi

                _verify_cert "$cert" "$PKCS12_CHAIN_USAGE"
                ret=$?

                # Check if the verification failed. If it did, remove it from the NSS DB.
                if (( ret != 0 )); then
                    __e "Verification of certificate \`$cert\` failed!"
                    _remove_all_certs
                    __secure_rmtmp
                    exit 1
                fi

                # Trust certificate after validation -- safe.
                if [ "$PKCS12_UNSAFE" == "false" ]; then
                    _trust_cert "$cert" "$PKCS12_CHAIN_TRUST"
                fi
            fi
        done

        # Validate leaf certificate
        _verify_cert "$CERT_NICKNAME" "$CERT_USAGE"
        ret=$?

        # Check if the verification failed. If it did, remove it from the NSS DB.
        if (( ret != 0 )); then
            __e "Verification of certificate \`$CERT_NICKNAME\` failed!"
            _remove_all_certs
            __secure_rmtmp
            exit 1
        fi

        __secure_rmtmp
    fi

    return 0
}

PKICertImport "$@"
