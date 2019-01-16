#!/bin/bash

function vti() {
    ## [ globals ] ##

    # Temporary directory base location.
    local CERT_PATH=""
    local CERT_NICKNAME=""
    local CERT_ASCII="false"
    local CERT_TRUST=""
    local CERT_USAGE=""

    local NSSDB=""
    local NSSDB_PASSWORD=""

    local HSM_TOKEN=""

    ## [ helper functions ] ##

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
        echo "VERBOSE: see certutil commands being run"
        echo ""
        echo "For more information about these options, refer to the" \
             "certutil documentation."
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
    # - Import certificate into NSS DB
    # - Modify trust flags in NSS DB
    # - Validate certificate in NSS DB
    #   - [on failure remove certificate]
    #
    # Import and Modify are both handled by _import_cert, verification is
    # handled by _verify_cert, and removal is handled by _remove_cert.

    _parse_args "$@"
    ret="$?"
    if (( ret != 0 )); then
        _print_help $ret
        exit 1
    fi

    _import_cert "$NSSDB"
    _verify_cert "$NSSDB"
    ret=$?

    # Check if the verification failed.
    if (( ret != 0 )); then
        __e "Verification of certificate failed!"
        _remove_cert "$NSSDB"
        exit 1
    fi
}

vti "$@"
