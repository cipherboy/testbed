#include <nss.h>
#include <prio.h>
#include <prlog.h>
#include <prmem.h>
#include <prnetdb.h>
#include <ssl.h>

// NSPR include files
#include <prerror.h>
#include <prinit.h>

// NSS include files
#include <nss.h>
#include <pk11pub.h>
#include <secmod.h>
#include <ssl.h>
#include <sslproto.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#define DEBUG 1

/* Obtain a backtrace and print it to stdout. */
void print_trace(void)
{
    void* array[25];
    size_t size;
    char** strings;
    size_t i;

    size = backtrace(array, 25);
    strings = backtrace_symbols(array, size);

    printf("Obtained %zd stack frames.\n", size);

    for (i = 0; i < size; i++)
        printf("%s\n", strings[i]);

    free(strings);
}

struct PRFilePrivate {
    uint8_t* read_bytes;
    size_t read_capacity;
    size_t read_ptr;

    uint8_t* write_bytes;
    size_t write_capacity;
    size_t write_ptr;

    bool closed;
};

static PRIntn invalidInternalCall()
{
    /* For debugging; any internal calls get logged and a backtrace is
     * displayed so _hopefully_ we get information about which call was
     * performed. */
#ifdef DEBUG
#if DEBUG
    printf("\n\nI AM DOING AN INVALID CALL\n");
    print_trace();
    printf("\n\n");
#endif
#endif
    PR_ASSERT(!"invalidInternalCall performed!");
}

static PRStatus PRBufferClose(PRFileDesc* fd)
{
    /* This method marks the connection as closed and frees the secret data. */

    if (fd == NULL) {
        return PR_SUCCESS;
    }

    free(fd->secret);
    fd->secret = NULL;

    return PR_SUCCESS;
}

static PRStatus PRBufferGetPeerName(PRFileDesc* fd, PRNetAddr* addr)
{
    /* getPeerName takes a PRFileDesc and modifies the PRNetAddr with the
     * name of the peer. Because of the specifics of the NSS Implementation,
     * we always return a constant/consistent address name here: "buff" * 4.
     * However, it has to be of type ipv6, else it either gets mangled by
     * the IPv4 -> IPv6 translation or a PR_ADDRESS_NOT_SUPPORTED_ERROR is
     * thrown by ssl_GetPeerInfo(...). */

    // https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSPR/Reference/PRNetAddr

    if (addr) {
        addr->ipv6.family = PR_AF_INET6;
        addr->ipv6.port = 0xFFFF;
        addr->ipv6.flowinfo = 0x00000000;
        memcpy(&addr->ipv6.ip, "buffbuffbuffbuff", 16);
        return PR_SUCCESS;
    }

    return PR_FAILURE;
}

static PRInt32 PRBufferSend(PRFileDesc* fd, void* buf, PRInt32 amount, PRIntn flags, PRIntervalTime timeout)
{
    /* Send takes a PRFileDesc and attempts to send some amount of bytes from
     * the start of buf to the other party before timeout is reached. Because
     * we're implementing this as a (large) buffer, copy into the buffer if
     * possible, else ignore it -- never error. */

    PRFilePrivate* internal = fd->secret;
    if (internal->write_ptr < internal->write_capacity) {
        uint8_t* offset = internal->write_bytes + internal->write_ptr;
        size_t write_len = amount;

        /* Write at most max(amount, free_space) bytes. */
        if (write_len > internal->write_capacity - internal->write_ptr) {
            write_len = internal->write_capacity - internal->write_ptr;
        }

        printf("Wrote: %zu of %d bytes\n", write_len, amount);
        memcpy(offset, buf, write_len);

        /* Update ptr to next available byte. */
        internal->write_ptr += write_len;

        return write_len;
    }

    printf("Failed to write %d bytes\n", amount);

    return 0;
}

static PRInt32 PRBufferRecv(PRFileDesc* fd, void* buf, PRInt32 amount, PRIntn flags, PRIntervalTime timeout)
{
    /* Recv takes a PRFileDesc and attempts to read some amount of bytes from
     * the start of buf to return to the caller before timeout is reached.
     * Because we're implementing this as a (large) buffer, copy from the
     * buffer if possible, else ignore it -- never error. */
    PRFilePrivate* internal = fd->secret;

    if (internal->read_ptr > 0) {
        uint8_t read_len = amount;
        uint8_t* offset = internal->read_bytes;
        uint8_t* memset_offset = internal->read_bytes + internal->read_ptr;
        size_t memmove_len = internal->read_ptr - amount;
        if (read_len > internal->read_ptr) {
            read_len = internal->read_ptr;
            memmove_len = 0;
        }
        offset += read_len;

        printf("Read: %zu of %d bytes\n", read_len, amount);
        memcpy(buf, internal->read_bytes, read_len);

        if (memmove_len > 0) {
            memmove(internal->read_bytes, offset, memmove_len);
        }

        memset(memset_offset, 0, internal->read_capacity - internal->read_ptr);

        internal->read_ptr -= read_len;

        return read_len;
    }

    printf("Failed to read %d bytes\n", amount);

    return 0;
}

static PRStatus PRBufferGetSocketOption(PRFileDesc* fd, PRSocketOptionData* data)
{
    /* getSocketOption takes a PRFileDesc and modifies the PRSocketOptionData
     * with the options on this. We set a couple of sane defaults here:
     *
     *   non_blocking = true
     *   reuse_addr = false
     *   keep_alive = false
     *   no_delay = true
     *
     * However the list above is far fom extensive. */

    if (data) {
        PRFilePrivate* internal = fd->secret;

        data->value.non_blocking = PR_TRUE;
        data->value.reuse_addr = PR_FALSE;
        data->value.keep_alive = PR_FALSE;
        data->value.mcast_loopback = PR_FALSE;
        data->value.no_delay = PR_TRUE;
        data->value.max_segment = internal->read_capacity;
        data->value.recv_buffer_size = internal->read_capacity;
        data->value.send_buffer_size = internal->write_capacity;
        return PR_SUCCESS;
    }

    return PR_FAILURE;
}

static const PRIOMethods PRIOBufferMethods = {
    PR_DESC_SOCKET_TCP,
    (PRCloseFN)PRBufferClose,
    (PRReadFN)invalidInternalCall,
    (PRWriteFN)invalidInternalCall,
    (PRAvailableFN)invalidInternalCall,
    (PRAvailable64FN)invalidInternalCall,
    (PRFsyncFN)invalidInternalCall,
    (PRSeekFN)invalidInternalCall,
    (PRSeek64FN)invalidInternalCall,
    (PRFileInfoFN)invalidInternalCall,
    (PRFileInfo64FN)invalidInternalCall,
    (PRWritevFN)invalidInternalCall,
    (PRConnectFN)invalidInternalCall,
    (PRAcceptFN)invalidInternalCall,
    (PRBindFN)invalidInternalCall,
    (PRListenFN)invalidInternalCall,
    (PRShutdownFN)invalidInternalCall,
    (PRRecvFN)PRBufferRecv,
    (PRSendFN)PRBufferSend,
    (PRRecvfromFN)invalidInternalCall,
    (PRSendtoFN)invalidInternalCall,
    (PRPollFN)invalidInternalCall,
    (PRAcceptreadFN)invalidInternalCall,
    (PRTransmitfileFN)invalidInternalCall,
    (PRGetsocknameFN)invalidInternalCall,
    (PRGetpeernameFN)PRBufferGetPeerName,
    (PRReservedFN)invalidInternalCall,
    (PRReservedFN)invalidInternalCall,
    (PRGetsocketoptionFN)PRBufferGetSocketOption,
    (PRSetsocketoptionFN)invalidInternalCall,
    (PRSendfileFN)invalidInternalCall,
    (PRConnectcontinueFN)invalidInternalCall,
    (PRReservedFN)invalidInternalCall,
    (PRReservedFN)invalidInternalCall,
    (PRReservedFN)invalidInternalCall,
    (PRReservedFN)invalidInternalCall
};

static void freeBufferPRFileDesc(PRFileDesc* fd)
{
    /* Leave it to the caller to free the bytes; they should maintain a
     * reference to it as well. */

    /* If fd->secret is none, close() was called first so we can just exit. */
    if (fd->secret == NULL) {
        return;
    }

    fd->secret->read_bytes = NULL;
    fd->secret->read_capacity = 0;

    fd->secret->write_bytes = NULL;
    fd->secret->write_capacity = 0;
}

static PRFileDesc* newBufferPRFileDesc(uint8_t* read_buf, size_t read_capacity, uint8_t* write_buf, size_t write_capacity)
{
    PRFileDesc* fd;

    fd = PR_NEW(PRFileDesc);
    if (fd) {
        fd->methods = &PRIOBufferMethods;
        fd->secret = PR_NEW(PRFilePrivate);
        fd->secret->read_bytes = read_buf;
        fd->secret->write_bytes = write_buf;

        fd->secret->read_capacity = read_capacity;
        fd->secret->write_capacity = write_capacity;
        fd->secret->read_ptr = 0;
        fd->secret->write_ptr = 0;

/*        fd->secret->read_ptr = 93 + 5;
        uint8_t fake_hello[21] = { 0x16, 0x03, 0x03, 0x00, 0x5d, 0x20, 0x00,
            0x00, 0x59, 0x03, 0x03, 0x0a, 0xca, 0x21,
            0x58, 0x8b, 0xe2, 0xd9, 0x9e, 0x13, 0x67 };
        memcpy(fd->secret->read_bytes, fake_hello, 21);*/

        fd->lower = NULL;
        fd->higher = NULL;
        fd->dtor = freeBufferPRFileDesc;
    }

    return fd;
}

int main(int argc, char** argv)
{
    /* Create NSS Context */
    PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 0);
    NSSInitContext* const ctx = NSS_InitContext("sql:/etc/pki/nssdb", "", "", "", NULL,
        NSS_INIT_READONLY | NSS_INIT_PK11RELOAD);

    if (ctx == NULL) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: NSPR error code %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }

    /* Initialize Client Buffers */
    size_t read_size = 2048;
    uint8_t* read_buf = calloc(read_size, sizeof(uint8_t));
    size_t write_size = 2048;
    uint8_t* write_buf = calloc(write_size, sizeof(uint8_t));
    PRIntn optval = 1;
    PRFileDesc* nspr = newBufferPRFileDesc(read_buf, read_size, write_buf, write_size);
    PRSocketOptionData nonblocking;
    nonblocking.option = PR_SockOpt_Nonblocking;
    nonblocking.value.non_blocking = PR_TRUE;
    PR_SetSocketOption(nspr, &nonblocking);

    // Ciphers to enable.
    static const PRUint16 good_ciphers[] = {
        TLS_RSA_WITH_AES_128_CBC_SHA,
        TLS_RSA_WITH_AES_256_CBC_SHA,
        SSL_NULL_WITH_NULL_NULL // sentinel
    };

    // Check if the current policy allows any strong ciphers.  If it
    // doesn't, set the cipher suite policy.  This is not thread-safe
    // and has global impact.  Consequently, we only do it if absolutely
    // necessary.
    int found_good_cipher = 0;
    for (const PRUint16* p = good_ciphers; *p != SSL_NULL_WITH_NULL_NULL;
         ++p) {
        PRInt32 policy;
        if (SSL_CipherPolicyGet(*p, &policy) != SECSuccess) {
            const PRErrorCode err = PR_GetError();
            fprintf(stderr, "error: policy for cipher %u: error %d: %s\n",
                (unsigned)*p, err, PR_ErrorToName(err));
            exit(1);
        }
        if (policy == SSL_ALLOWED) {
            fprintf(stderr, "info: found cipher %x\n", (unsigned)*p);
            found_good_cipher = 1;
            break;
        }
    }
    if (!found_good_cipher) {
        if (NSS_SetDomesticPolicy() != SECSuccess) {
            const PRErrorCode err = PR_GetError();
            fprintf(stderr, "error: NSS_SetDomesticPolicy: error %d: %s\n",
                err, PR_ErrorToName(err));
            exit(1);
        }
    }

    // Initialize the trusted certificate store.
    char module_name[] = "library=libnssckbi.so name=\"Root Certs\"";
    SECMODModule* module = SECMOD_LoadUserModule(module_name, NULL, PR_FALSE);
    if (module == NULL || !module->loaded) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: NSPR error code %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }

    {
        PRFileDesc* model = PR_NewTCPSocket();
        PRFileDesc* newfd = SSL_ImportFD(NULL, model);
        if (newfd == NULL) {
            const PRErrorCode err = PR_GetError();
            fprintf(stderr, "error: NSPR error code %d: %s\n",
                err, PR_ErrorToName(err));
            exit(1);
        }
        model = newfd;
        newfd = NULL;
        if (SSL_OptionSet(model, SSL_ENABLE_SSL2, PR_FALSE) != SECSuccess) {
            const PRErrorCode err = PR_GetError();
            fprintf(stderr, "error: set SSL_ENABLE_SSL2 error %d: %s\n",
                err, PR_ErrorToName(err));
            exit(1);
        }
        if (SSL_OptionSet(model, SSL_V2_COMPATIBLE_HELLO, PR_FALSE) != SECSuccess) {
            const PRErrorCode err = PR_GetError();
            fprintf(stderr, "error: set SSL_V2_COMPATIBLE_HELLO error %d: %s\n",
                err, PR_ErrorToName(err));
            exit(1);
        }
        if (SSL_OptionSet(model, SSL_ENABLE_DEFLATE, PR_FALSE) != SECSuccess) {
            const PRErrorCode err = PR_GetError();
            fprintf(stderr, "error: set SSL_ENABLE_DEFLATE error %d: %s\n",
                err, PR_ErrorToName(err));
            exit(1);
        }

        newfd = SSL_ImportFD(model, nspr);
        PR_SetSocketOption(nspr, &nonblocking);
        if (newfd == NULL) {
            const PRErrorCode err = PR_GetError();
            fprintf(stderr, "error: SSL_ImportFD error %d: %s\n",
                err, PR_ErrorToName(err));
            exit(1);
        }
        nspr = newfd;
        PR_Close(model);
    }

    // Perform the handshake.
    char* host = "buffbuffbuffbuff";
    if (SSL_ResetHandshake(nspr, PR_FALSE) != SECSuccess) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: SSL_ResetHandshake error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }
    if (SSL_SetURL(nspr, host) != SECSuccess) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: SSL_SetURL error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }

    /* This will always fail since we're waiting for the handshake to
     * complete, but we haven't actually attached this to anything... */
    /*if (SSL_ForceHandshake(nspr) != SECSuccess) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: SSL_ForceHandshake error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }*/

    printf("Writing connection...\n");
    char *buf = calloc(0, sizeof(char));
    PRInt32 ret = PR_Write(nspr, buf, 0);
    if (ret < 0) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: PR_Write error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }
    printf("Reading connection...\n");
    ret = PR_Read(nspr, buf, sizeof(buf));
    if (ret < 0) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: PR_Read error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }

    printf("Closing connection...\n");

    // Send close_notify alert.
    if (PR_Shutdown(nspr, PR_SHUTDOWN_BOTH) != PR_SUCCESS) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: PR_Read error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }
    // Closes the underlying POSIX file descriptor, too.
    PR_Close(nspr);

    return 0;
}
