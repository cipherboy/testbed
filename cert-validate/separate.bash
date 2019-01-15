#!/bin/bash

function vti() {
    ## [ globals ] ##

    # Temporary directory base location.
    local TMPBASE=""

    local CERT_PATH=""
    local CERT_NICKNAME=""
    local CERT_ASCII="false"
    local CERT_TRUST=""
    local CERT_USAGE=""

    local NSSDB=""
    local NSSDB_TEMP=""
    local NSSDB_PASSWORD=""

    local HSM_TOKEN=""

    ## [ helper functions ] ##

    # mk_secure_tmp fills the TMPBASE variable with the path to a directory
    # we can use that has permissions restricted to our current user. This
    # will be where we move the NSS DB and the certificate to.
    #
    # Failures are fatal, so use exit instead of return.
    function __mk_secure_tmp() {
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
            echo "Return from mktemp was non-zero: $ret" 1>&2
            echo "$TMPBASE" 1>&2
            echo "Perhaps specify TMPDIR in the environment?" 1>&2
            exit 1
        elif [ ! -d "$TMPBASE" ]; then
            echo "Return from mktemp was zero but invalid directory:" 1>&2
            echo "$TMPBASE" 1>&2
            echo "Perhaps specify TMPDIR in the environment?" 1>&2
            exit 1
        fi

        # We've validated that TMPBASE is now a valid directory. Since
        # we created it, we have ownership. Restrict access to only this
        # user as the original NSS DB might have private keys which we want
        # to keep secure when copying.

        local user=""
        local group=""

        # Acquire curreent username.
        user="$(id --user --name 2>&1)"
        ret=$?
        if (( ret != 0 )); then
            echo "id exited with non-zero result: $ret" 1>&2
            echo "Unable to get current user's name." 1>&2
            ___rm_secure_temp
            exit 1
        fi

        # Acquire curreent primary group.
        group="$(id --group --name 2>&1)"
        ret=$?
        if (( ret != 0 )); then
            echo "id exited with non-zero result: $ret" 1>&2
            echo "Unable to get current user's name." 1>&2
            ___rm_secure_temp
            exit 1
        fi

        chown "$user:$group" -R "$TMPBASE"
        ret=$?
        if (( ret != 0 )); then
            echo "Return from chown on $TMPBASE was non-zero: $ret" 1>&2
            ___rm_secure_temp
            exit 1
        fi

        chmod 700 -R "$TMPBASE"
        ret=$?
        if (( ret != 0 )); then
            echo "Return from chmod on $TMPBASE was non-zero: $ret" 1>&2
            ___rm_secure_temp
            exit 1
        fi

        return 0
    }

    ## rm_secure_temp removes the temporary directory if present.
    function __rm_secure_temp() {
        if [ -d "$TMPBASE" ]; then
            # TODO: Determine if we should shred the contents if the shred
            # utility is present; otherwise, could fall back on dd...
            rm -rf "$TMPBASE"
        fi
    }

    # __e prints error messages.
    function __e() {
        echo "e:" "$@" 1>&2
    }

    # __v prints debug messages in verbose mode.
    function __v() {
        if [ "x$VERBOSE" != "x" ]; then
            echo "v:" "$@" 1>&2
        fi
    }

    ## [ core commands ] ##

    function _parse_args() {
        # Use a read-and-shift approach to parse both "<option>" and
        # "<option> <value>" forms.
        while (( $# > 0 )); do
            local arg="$1"
            shift

            if [ "x$arg" == "x--ascii" ] || [ "x$arg" == "x-a" ]; then
                # If specified, the -a flag is passed when the certificate is
                # imported.
                CERT_ASCII="true"
            elif [ "x$arg" == "x--database" ] || [ "x$arg" == "x-d" ]; then
                NSSDB="$1"
                shift
            elif [ "x$arg" == "x--password" ] || [ "x$arg" == "x-f" ]; then
                NSSDB_PASSWORD="$1"
                shift
            elif [ "x$arg" == "x--hsm" ] || [ "x$arg" == "x-h" ]; then
                HSM_TOKEN="$1"
                shift
            elif [ "x$arg" == "x--certificate" ] || [ "x$arg" == "x-i" ]; then
                CERT_PATH="$1"
                shift
            elif [ "x$arg" == "x--nickname" ] || [ "x$arg" == "x-n" ]; then
                CERT_NICKNAME="$1"
                shift
            elif [ "x$arg" == "x--trust" ] || [ "x$arg" == "x-t" ]; then
                CERT_TRUST="$1"
                shift
            elif [ "x$arg" == "x--usage" ] || [ "x$arg" == "x-u" ]; then
                CERT_USAGE="$1"
                shift
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

        # Ensure that we've seen the required arguments.
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
        fi

        return 0
    }

    # Show help and usage information.
    function _print_help() {
        if (( $1 != 0 )); then
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
        echo "--password, -f <path>: password file for the NSS DB"
        echo "--hsm, -h <name>: name of the HSM to use"
        echo ""
        echo "Environment variables:"
        echo "TMPDIR: specify a location to place a temporary directory"
        echo "VERBOSE: see certutil commands being run"
        echo ""
        echo "For more information about these options, refer to the" \
             "certutil documentation."
    }

    # Copy NSS DB and Certificate to temporary location.
    function _copy_to_temp() {
        local ret=0

        NSSDB_TEMP="$TMPBASE/nssdb"
        cp -r "$NSSDB" "$NSSDB_TEMP"
        ret=$?
        if (( ret != 0 )); then
            __e "Copying $NSSDB to temporary directory failed: $ret"
            exit 1
        fi

        local cert_temp="$TMPBASE/cert"
        cp "$CERT_PATH" "$cert_temp"
        ret=$?
        if (( ret != 0 )); then
            __e "Copying $CERT_PATH to temporary directory failed: $ret"
            exit 1
        fi
        CERT_PATH="$cert_temp"
    }

    # Import a certificate into the NSS DB specified on $1.
    function _import_cert() {
        local database="$1"
        local ret=0
        local common_args=()
        local add_args=("-A")
        local modify_args=("-M")

        common_args+=("-d" "$database")
        common_args+=("-n" "$CERT_NICKNAME")
        add_args+=("-i" "$CERT_PATH")
        add_args+=("-t" ",,")
        if [ "$CERT_ASCII" == "true" ]; then
            add_args+=("-a")
        fi
        if [ "x$HSM_TOKEN" != "x" ]; then
            add_args+=("-h" "$HSM_TOKEN")
        fi
        if [ "x$NSSDB_PASSWORD" != "x" ]; then
            common_args+=("-f" "$NSSDB_PASSWORD")
        fi
        modify_args+=("-t" "$CERT_TRUST")

        __v certutil "${add_args[@]}" "${common_args[@]}"
        certutil "${add_args[@]}" "${common_args[@]}"
        ret=$?
        if (( ret != 0 )); then
            __e "certutil returned non-zero value: $ret"
            __e "Unable to import certificate to NSS DB: $NSSDB."
            exit $ret
        fi

        __v certutil "${modify_args[@]}" "${common_args[@]}"
        certutil "${modify_args[@]}" "${common_args[@]}"
        ret=$?
        if (( ret != 0 )); then
            __e "certutil returned non-zero value: $ret"
            __e "Unable to modify certificate trust in NSS DB: $NSSDB."
            exit $ret
        fi
    }

    # Verify the certificate in the NSS DB specified by $1.
    function _verify_cert() {
        local database="$1"
        local ret=0
        local verify_args=("-V")

        verify_args+=("-d" "$database")
        verify_args+=("-n" "$CERT_NICKNAME")
        verify_args+=("-u" "$CERT_USAGE")
        if [ "x$HSM_TOKEN" != "x" ]; then
            verify_args+=("-h" "$HSM_TOKEN")
        fi
        if [ "x$NSSDB_PASSWORD" != "x" ]; then
            verify_args+=("-f" "$NSSDB_PASSWORD")
        fi

        __v certutil "${verify_args[@]}"
        certutil "${verify_args[@]}"
    }

    # Remove the certificate from the NSS DB specified by $1.
    function _remove_cert() {
        local database="$1"
        local remove_args=("-D")

        remove_args+=("-d" "$database")
        remove_args+=("-n" "$CERT_NICKNAME")
        if [ "x$HSM_TOKEN" != "x" ]; then
            # If the certificate was processed on an HSM, specify the HSM for
            # removal as well so we delete it off the HSM as well.
            remove_args+=("-h" "$HSM_TOKEN")
        fi
        if [ "x$NSSDB_PASSWORD" != "x" ]; then
            remove_args+=("-f" "$NSSDB_PASSWORD")
        fi

        __v certutil "${remove_args[@]}"
        certutil "${remove_args[@]}"
        local ret=$?
        if (( ret != 0 )); then
            __e "certutil returned non-zero result: $ret"
            __e "Unable to delete certificate!"
            exit $?
        fi
    }

    ## [ program flow ] ##
    local ret=0

    # The flow for this script is:
    #
    # - Parse arguments
    #   - [print help if required]
    # - Create working directory
    # - Copy files into the working directory
    # - Import certificate into temporary NSS DB
    # - Modify trust flags in temporary NSS DB
    # - Validate certificate in temporary NSS DB
    #   - [on failure, quit]
    # - Import certificate into real NSS DB
    # - Modify trust flags on real NSS DB
    #
    # Import and Modify are both handled by _import_cert, verification is
    # handled by _verify_cert, and removal is handled by _remove_cert.

    _parse_args "$@"
    ret="$?"
    if (( ret != 0 )); then
        _print_help $ret
        exit 1
    fi

    __mk_secure_tmp
    _copy_to_temp

    _import_cert "$NSSDB_TEMP"
    _verify_cert "$NSSDB_TEMP"
    ret=$?

    # Note that we always have to remove the certificate from the temporary
    # NSS DB--even when import succeeded. Otherwise, if we're using a HSM,
    # the certificate will fail to be imported into the real NSS DB because
    # it already exists on the HSM.
    _remove_cert "$NSSDB_TEMP"

    # Check if the verification failed.
    if (( ret != 0 )); then
        __e "Verification of certificate failed!"
        __rm_secure_temp
        exit 1
    fi

    # Since verification succeeded, we can now import the certificate into
    # the real NSS Database.
    _import_cert "$NSSDB"
    __rm_secure_temp
}

vti "$@"
