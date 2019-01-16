#!/bin/bash

# PKICertImport performs a validate-then-import strategy for importing
# certificates into a NSS DB or HSM Token by creating a copy of the NSS
# DB prior to import. This ensures that the certificate will not be used
# until its signature and usage has been verified. It replaces the
# `certutil -A` and `certutil -V`.
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

    # Temporary directory base location.
    local TMPBASE=""

    # Path to certificate; parsed from arguments, then updated to reflect
    # location under TMPBASE.
    local CERT_PATH=""

    # User-given nickname for the certificate.
    local CERT_NICKNAME=""

    # Whether or not the certificate is in ASCII/PEM format.
    local CERT_ASCII="false"

    # What trust flags to use when importing the certificate.
    local CERT_TRUST=""

    # What usage flags to validate the certificate against.
    local CERT_USAGE=""

    # Location of the original NSS DB.
    local NSSDB=""

    # Type of the NSSDB.
    local NSSDB_TYPE=""

    # Location of the copied NSS DB.
    local NSSDB_TEMP=""

    # Location to the NSS DB Password file, if present.
    local NSSDB_PASSWORD=""

    # Name of the HSM token, if used.
    local HSM_TOKEN=""


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

    # mk_secure_tmp fills the TMPBASE variable with the path to a directory
    # we can use that has permissions restricted to our current user. This
    # will be where we move the NSS DB and the certificate to.
    #
    # Failures are fatal, so use exit instead of return to simplify error
    # handling.
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
        fi

        # Create the temporary directory.
        TMPBASE="$(mktemp --directory --tmpdir="$tmpdir" 2>&1)"
        ret="$?"

        if (( ret != 0 )); then
            # ret being non-zero is a definite failure in mktemp.
            __e "Return from mktemp was non-zero: $ret" 1>&2
            __e "$TMPBASE" 1>&2
            __e "Perhaps specify TMPDIR in the environment?" 1>&2
            exit 1
        elif [ ! -d "$TMPBASE" ]; then
            # Theoretically mktemp should exit with zero status only when
            # creating the directory was successful; however, since we also
            # redirect stderr to join stdout, the output of mktemp could
            # include a warning, causing TMPBASE to not be a valid directory.

            # This ensures we don't continue if that is the case.
            __e "Return from mktemp was zero but invalid directory:" 1>&2
            __e "$TMPBASE" 1>&2
            __e "Perhaps specify TMPDIR in the environment?" 1>&2
            exit 1
        fi

        # We've validated that TMPBASE is now a valid directory. Since
        # we created it, we have ownership. Restrict access to only this
        # user as the original NSS DB might have private keys which we want
        # to keep secure when copying. This ensures other users cannot access
        # our copied files.

        local user=""
        local group=""

        # Acquire curreent username.
        user="$(id --user --name 2>&1)"
        ret=$?
        if (( ret != 0 )); then
            __e "id exited with non-zero result: $ret" 1>&2
            __e "Unable to get current user's name." 1>&2
            __rm_secure_tmp
            exit 1
        fi

        # Acquire curreent primary group.
        group="$(id --group --name 2>&1)"
        ret=$?
        if (( ret != 0 )); then
            __e "id exited with non-zero result: $ret" 1>&2
            __e "Unable to get current user's name." 1>&2
            __rm_secure_tmp
            exit 1
        fi

        # Change ownership prior to permissions; theoretically these should
        # already be the current owner.
        chown "$user:$group" -R "$TMPBASE"
        ret=$?
        if (( ret != 0 )); then
            __e "Return from chown on $TMPBASE was non-zero: $ret" 1>&2
            __rm_secure_tmp
            exit 1
        fi

        # Restrict access only to the owner, preventing any group and world
        # access.
        chmod 700 -R "$TMPBASE"
        ret=$?
        if (( ret != 0 )); then
            __e "Return from chmod on $TMPBASE was non-zero: $ret" 1>&2
            __rm_secure_tmp
            exit 1
        fi

        return 0
    }

    ## rm_secure_tmp removes the temporary directory if present.
    function __rm_secure_tmp() {
        if [ -d "$TMPBASE" ]; then
            # TODO: Determine if we should shred the contents if the shred
            # utility is present; otherwise, could fall back on dd...
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
            elif [ "x$arg" == "x--trust" ] || [ "x$arg" == "x-t" ]; then
                # Always required; certificate trust flags.
                CERT_TRUST="$1"
                shift
            elif [ "x$arg" == "x--usage" ] || [ "x$arg" == "x-u" ]; then
                # Always required; certificate usage flags.
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

        # All good to go.
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

    # Copy NSS DB and Certificate to temporary location. Errors are fatal;
    # uses exit instead of return for simplified error handling.
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

    # Import a certificate into the NSS DB specified on $1. When a HSM is
    # specified and the database is a newer, sqlite format, we run two
    # commands: one for importing the certificate into the HSM, and one for
    # setting trust in the NSS DB. Otherwise, we use a single command and
    # hope the trust flags are adequate for validation and suitable for
    # import (in the case of a HSM with an older NSS DB format). Errors are
    # fatal; uses exit instead of return.
    function _import_cert() {
        local database="$1"
        local ret=0
        local add_args=("-A")

        # Use a single import command, setting trust as we import.
        add_args+=("-d" "$NSSDB_TYPE$database")
        add_args+=("-n" "$CERT_NICKNAME")
        if [ "x$NSSDB_PASSWORD" != "x" ]; then
            add_args+=("-f" "$NSSDB_PASSWORD")
        fi
        add_args+=("-i" "$CERT_PATH")
        if [ "$CERT_ASCII" == "true" ]; then
            add_args+=("-a")
        fi
        if [ "x$HSM_TOKEN" != "x" ]; then
            add_args+=("-h" "$HSM_TOKEN")
        fi
        add_args+=("-t" "$CERT_TRUST")

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

    # Verify the certificate in the NSS DB specified by $1.
    function _verify_cert() {
        local database="$1"
        local ret=0
        local verify_args=("-V")

        verify_args+=("-d" "$NSSDB_TYPE$database")
        verify_args+=("-n" "$CERT_NICKNAME")
        verify_args+=("-u" "$CERT_USAGE")
        if [ "x$HSM_TOKEN" != "x" ]; then
            verify_args+=("-h" "$HSM_TOKEN")
        fi
        if [ "x$NSSDB_PASSWORD" != "x" ]; then
            verify_args+=("-f" "$NSSDB_PASSWORD")
        fi

        # Ensures that the signature is checked as well.
        verify_args+=("-e")

        # Validate the certificate. Note that _verify_cert returns with status
        # equal to the return code of the certutil command; on failure,
        # `certutil -V` returns with non-zero value, so _verify_cert will
        # as well.
        __v certutil "${verify_args[@]}"
        local certutil_result="$(certutil "${verify_args[@]}" 2>&1)"

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
        local database="$1"
        local remove_args=("-D")

        remove_args+=("-d" "$NSSDB_TYPE$database")
        if [ "x$NSSDB_PASSWORD" != "x" ]; then
            remove_args+=("-f" "$NSSDB_PASSWORD")
        fi

        __v certutil "${remove_args[@]}" "-n" "$CERT_NICKNAME"
        certutil "${remove_args[@]}" "-n" "$CERT_NICKNAME"
        local ret=$?
        if (( ret != 0 )); then
            __e "certutil returned non-zero result: $ret"
            __e "Unable to delete certificate!"
            exit $?
        fi

        if [ "x$HSM_TOKEN" != "x" ]; then
            # In the event we have a HSM, we also have to remove it from the
            # HSM token.

            __v certutil "${remove_args[@]}" "-n" "$HSM_TOKEN:$CERT_NICKNAME"
            certutil "${remove_args[@]}" "-n" "$HSM_TOKEN:$CERT_NICKNAME"
            local ret=$?
            if (( ret != 0 )); then
                __e "certutil returned non-zero result: $ret"
                __e "Unable to delete certificate!"
                exit $?
            fi
        fi
    }

    ## [ program flow ] ##
    local ret=0

    # The program flow of this script is:
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
        __rm_secure_tmp
        exit 1
    fi

    # Since verification succeeded, we can now import the certificate into
    # the real NSS Database. If verification did not succeed, we'd have
    # exited prior to reaching this point.
    _import_cert "$NSSDB"

    # Note that we only remove the temporary directory when the script
    # succeeds; or validation failed. For other unexpected errors, the
    # temporary directory persists, enabling the runner to debug any
    # issues if necessary (when coupled with VERBOSE=1 flag).
    __rm_secure_tmp
}

PKICertImport "$@"
