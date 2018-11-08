#include <nss.h>
#include <prio.h>
#include <prlog.h>
#include <prmem.h>
#include <prnetdb.h>
#include <ssl.h>

// NSPR include files
#include <prerror.h>
#include <prinit.h>

// NSS include file
#include <cert.h>
#include <certdb.h>
#include <certt.h>
#include <nss.h>
#include <pk11pub.h>
#include <secmod.h>
#include <ssl.h>
#include <sslproto.h>

// Random includes
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#define DEBUG 0

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
    size_t* read_capacity;
    size_t* read_ptr;

    uint8_t* write_bytes;
    size_t* write_capacity;
    size_t* write_ptr;

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
        memcpy(&addr->ipv6.ip, "ca.cipherboy.com", 16);
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

#ifdef DEBUG
#if DEBUG
    printf("Trying write: [%zu/%zu] - req:%d\n", *internal->write_ptr, *internal->write_capacity, amount);
#endif
#endif

    if (*internal->write_ptr < *internal->write_capacity) {
        uint8_t* offset = internal->write_bytes + *internal->write_ptr;
        size_t write_len = amount;

        /* Write at most max(amount, free_space) bytes. */
        if (write_len > *internal->write_capacity - *internal->write_ptr) {
            write_len = *internal->write_capacity - *internal->write_ptr;
        }

#ifdef DEBUG
#if DEBUG
        printf("Wrote: %zu of %d bytes\n", write_len, amount);
#endif
#endif
        memcpy(offset, buf, write_len);

        /* Update ptr to next available byte. */
        *internal->write_ptr += write_len;

#ifdef DEBUG
#if DEBUG
        printf("Finished write: [%zu/%zu] - req:%d\n", *internal->write_ptr, *internal->write_capacity, amount);
#endif
#endif
        return write_len;
    }

    printf("Failed to write %d bytes\n", amount);

#ifdef DEBUG
#if DEBUG
    printf("Finished write: [%zu/%zu] - req:%d\n", *internal->write_ptr, *internal->write_capacity, amount);
#endif
#endif

    /* Under correct Unix non-blocking socket semantics, if we lack data to
     * read, return a negative length and set EWOULDBLOCK. This is documented
     * in `man 2 recv`. */
    PR_SetError(PR_WOULD_BLOCK_ERROR, EWOULDBLOCK);
    return -1;
}

static PRInt32 PRBufferRecv(PRFileDesc* fd, void* buf, PRInt32 amount, PRIntn flags, PRIntervalTime timeout)
{
    /* Recv takes a PRFileDesc and attempts to read some amount of bytes from
     * the start of buf to return to the caller before timeout is reached.
     * Because we're implementing this as a (large) buffer, copy from the
     * buffer if possible, else ignore it -- never error. */
    PRFilePrivate* internal = fd->secret;
#ifdef DEBUG
#if DEBUG
    printf("Trying read: [%zu/%zu] - req:%d\n", *internal->read_ptr, *internal->read_capacity, amount);
#endif
#endif

    if (*internal->read_ptr > 0) {
        size_t read_len = amount;
        uint8_t* offset = internal->read_bytes;
        size_t memmove_len = *internal->read_ptr - amount;

        if (read_len > (*internal->read_ptr)) {
#ifdef DEBUG
#if DEBUG
            printf("Truncating move due to exceeding internal read ptr\n");
#endif
#endif
            read_len = *internal->read_ptr;
            memmove_len = 0;
        }

        offset += read_len;

#ifdef DEBUG
#if DEBUG
        printf("Read: %zu of %d bytes -- moving %zu\n", read_len, amount, memmove_len);
#endif
#endif
        memcpy(buf, internal->read_bytes, read_len);

        if (memmove_len > 0) {
            memmove(internal->read_bytes, offset, memmove_len);
        }

        *internal->read_ptr -= read_len;

#ifdef DEBUG
#if DEBUG
        printf("Finished read: [%zu/%zu] - req:%d\n", *internal->read_ptr, *internal->read_capacity, amount);
#endif
#endif
        return read_len;
    }

    printf("Failed to read %d bytes\n", amount);

#ifdef DEBUG
#if DEBUG
    printf("Finished read: [%zu/%zu] - req:%d\n", *internal->read_ptr, *internal->read_capacity, amount);
#endif
#endif

    PR_SetError(PR_WOULD_BLOCK_ERROR, EWOULDBLOCK);
    return -1;
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
        data->value.max_segment = *internal->read_capacity;
        data->value.recv_buffer_size = *internal->read_capacity;
        data->value.send_buffer_size = *internal->write_capacity;
        return PR_SUCCESS;
    }

    return PR_FAILURE;
}

static PRStatus PRBufferSetSocketOption(PRFileDesc* fd, PRSocketOptionData* data)
{
    /* This gives the caller control over setting socket options. It is the
     * equivalent of fcntl() with F_SETFL. In our case, O_NONBLOCK is the
     * only thing passed in, which we always return as true anyways, so
     * ignore the result. */
    return PR_SUCCESS;
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
    (PRSetsocketoptionFN)PRBufferSetSocketOption,
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

static PRFileDesc* newBufferPRFileDesc(uint8_t* read_buf, size_t* read_capacity, size_t* read_ptr,
    uint8_t* write_buf, size_t* write_capacity, size_t* write_ptr)
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
        fd->secret->read_ptr = read_ptr;
        fd->secret->write_ptr = write_ptr;

        fd->lower = NULL;
        fd->higher = NULL;
        fd->dtor = freeBufferPRFileDesc;
    }

    return fd;
}

static void setup_nss_context(void)
{
    /* Create NSS Context */
    PR_Init(PR_USER_THREAD, PR_PRIORITY_NORMAL, 0);
    NSSInitContext* const ctx = NSS_InitContext("sql:nssdb", "", "", "", NULL,
        NSS_INIT_READONLY | NSS_INIT_PK11RELOAD);

    if (ctx == NULL) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: NSPR error code %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }
}

static void setup_nss_config(void)
{
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

    if (NSS_Init("nssdb") != SECSuccess) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: NSPR error code when doing NSS_Init %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
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
}

static PRFileDesc* setup_nss_client(PRFileDesc* c_nspr, char* host)
{
    PRSocketOptionData nonblocking;
    nonblocking.option = PR_SockOpt_Nonblocking;
    nonblocking.value.non_blocking = PR_TRUE;
    PR_SetSocketOption(c_nspr, &nonblocking);

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

    newfd = SSL_ImportFD(model, c_nspr);
    PR_SetSocketOption(c_nspr, &nonblocking);

    if (newfd == NULL) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: SSL_ImportFD error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }
    c_nspr = newfd;
    PR_Close(model);

    // Reset the handshake status.
    if (SSL_ResetHandshake(c_nspr, PR_FALSE) != SECSuccess) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: SSL_ResetHandshake error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }
    if (SSL_SetURL(c_nspr, host) != SECSuccess) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: SSL_SetURL error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }

    return c_nspr;
}

static CERTCertificate* get_cert(char* host)
{
    CERTCertList* clist;
    CERTCertListNode* cln;

    clist = PK11_ListCerts(PK11CertListUser, NULL);

    for (cln = CERT_LIST_HEAD(clist); !CERT_LIST_END(cln, clist);
         cln = CERT_LIST_NEXT(cln)) {
        CERTCertificate* cert = cln->cert;
        const char* nickname = (const char*)cln->appData;

        if (!nickname) {
            nickname = cert->nickname;
        }

        if (strcmp(host, nickname) == 0) {
            printf("Found cert with nickname: %s\n", nickname);
            return cert;
        }
    }

    return NULL;
}

static SECKEYPrivateKey* get_privkey(CERTCertificate* cert)
{
    PK11SlotInfo* slot = NULL;

    slot = PK11_FindSlotByName("NSS Certificate DB");
    if (slot == NULL) {
        printf("Error finding slot!\n");
        exit(2);
    }

    PRInt32 rv = PK11_Authenticate(slot, PR_FALSE, "Secret.123");
    if (rv != SECSuccess) {
        printf("Invalid password for slot!\n");
        exit(3);
    }

    return PK11_FindPrivateKeyFromCert(slot, cert, NULL);
}

static PRFileDesc* setup_nss_server(PRFileDesc* s_nspr, char* host)
{
    PRSocketOptionData nonblocking;
    nonblocking.option = PR_SockOpt_Nonblocking;
    nonblocking.value.non_blocking = PR_TRUE;
    PR_SetSocketOption(s_nspr, &nonblocking);

    CERTCertificate* cert = get_cert("NSS Certificate DB:ca.cipherboy.com");
    if (cert == NULL) {
        printf("Failed to find certificate for host: %s\n", host);
        exit(1);
    }

    SECKEYPrivateKey* priv_key = get_privkey(cert);
    if (priv_key == NULL) {
        printf("Failed to find private key for certificate for host: %s\n", host);
        exit(1);
    }

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

    newfd = SSL_ImportFD(model, s_nspr);
    PR_SetSocketOption(s_nspr, &nonblocking);

    if (newfd == NULL) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: SSL_ImportFD error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }
    s_nspr = newfd;
    PR_Close(model);

    if (SSL_ConfigSecureServer(s_nspr, cert, priv_key, kt_rsa) != SECSuccess) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: SSL_ResetHandshake error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }

    SSL_ConfigServerSessionIDCache(1, 100, 100, NULL);

    // Reset the handshake status -- server end
    if (SSL_ResetHandshake(s_nspr, PR_TRUE) != SECSuccess) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: SSL_ResetHandshake error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }

    if (SSL_SetURL(s_nspr, host) != SECSuccess) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: SSL_SetURL error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }

    return s_nspr;
}

bool is_finished(PRFileDesc* c_nspr, PRFileDesc* s_nspr)
{
    int c_sec_status;
    int s_sec_status;
    if (SSL_SecurityStatus(c_nspr, &c_sec_status, NULL, NULL, NULL, NULL, NULL) != SECSuccess) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: SSL_SecurityStatus error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }

    if (SSL_SecurityStatus(s_nspr, &s_sec_status, NULL, NULL, NULL, NULL, NULL) != SECSuccess) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: SSL_SecurityStatus error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }

    return c_sec_status != SSL_SECURITY_STATUS_OFF && s_sec_status != SSL_SECURITY_STATUS_OFF;
}

int main(int argc, char** argv)
{
    setup_nss_context();
    setup_nss_config();

    /* Initialize Client Buffers */
    /* In order to maintain complete control over our buffers, we need to
     * create our buffers, sizes, and pointers here. This means that the
     * PRFileDesc does nothing except hold pointers to our memory and update
     * the contents/values as it sees fit (send/recv). If instead the buffer
     * took access (or created access itself), we'd need to get access to
     * them befor giving it to NSS, as NSS wraps our PRFileDesc in one ofhhh
     * their PRFileDescs, removing our access to fd->secret. */
    size_t c_read_size = 2048;
    size_t c_read_ptr = 0;
    uint8_t* c_read_buf = calloc(c_read_size, sizeof(uint8_t));
    size_t c_write_size = 2048;
    size_t c_write_ptr = 0;
    uint8_t* c_write_buf = calloc(c_write_size, sizeof(uint8_t));

    PRFileDesc* c_nspr = newBufferPRFileDesc(c_read_buf, &c_read_size, &c_read_ptr,
        c_write_buf, &c_write_size, &c_write_ptr);

    /* Initialize Server Buffers */
    PRFileDesc* s_nspr = newBufferPRFileDesc(c_write_buf, &c_write_size, &c_write_ptr,
        c_read_buf, &c_read_size, &c_read_ptr);

    /* Set up client and server sockets with NSSL */
    char* host = "ca.cipherboy.com";
    c_nspr = setup_nss_client(c_nspr, host);
    s_nspr = setup_nss_server(s_nspr, host);

    struct sockaddr_in serv_addr;
    struct hostent* server;

    printf("Trying handshake...\n");
    while (!is_finished(c_nspr, s_nspr)) {
        printf("Client Handshake:\n");
        if (SSL_ForceHandshake(c_nspr) != SECSuccess) {
            const PRErrorCode err = PR_GetError();
            if (err != PR_WOULD_BLOCK_ERROR) {
                fprintf(stderr, "error: SSL_ForceHandshake error %d: %s\n",
                    err, PR_ErrorToName(err));
                exit(1);
            }
        }

        printf("\n\nServer Handshake:\n");
        if (SSL_ForceHandshake(s_nspr) != SECSuccess) {
            const PRErrorCode err = PR_GetError();
            if (err != PR_WOULD_BLOCK_ERROR) {
                fprintf(stderr, "error: SSL_ForceHandshake error %d: %s\n",
                    err, PR_ErrorToName(err));
                exit(1);
            }
        }

        printf("\n\n");
    }

    /*        fd->secret->read_ptr = 93 + 5;
        uint8_t fake_hello[21] = { 0x16, 0x03, 0x03, 0x00, 0x5d, 0x20, 0x00,
            0x00, 0x59, 0x03, 0x03, 0x0a, 0xca, 0x21,
            0x58, 0x8b, 0xe2, 0xd9, 0x9e, 0x13, 0x67 };
        memcpy(fd->secret->read_bytes, fake_hello, 21);*/

    printf("Send a message from the client to the server...\n");
    char* buf = calloc(1024, sizeof(char));
    char* buf2 = calloc(1024, sizeof(char));
    char* client_message = "Cooking MCs";
    char* server_message = "like a pound of bacon";

    memcpy(buf, client_message, strlen(client_message));
    PRInt32 ret = PR_Write(c_nspr, buf, strlen(buf));
    if (ret < 0) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: PR_Write error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }

    ret = PR_Read(s_nspr, buf2, 1024);
    if (ret < 0) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: PR_Read error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }

    memset(buf, 0, 1024);
    memcpy(buf, buf2, ret);
    printf("Received message from client: %s [len: %d]\n", buf, ret);

    printf("\n\n");

    /* Send a message back! */
    printf("Send a message from the server to the client...\n");
    memcpy(buf, server_message, strlen(server_message));
    ret = PR_Write(s_nspr, buf, strlen(buf));
    if (ret < 0) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: PR_Write error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }

    ret = PR_Read(c_nspr, buf2, 1024);
    if (ret < 0) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: PR_Read error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }

    memset(buf, 0, 1024);
    memcpy(buf, buf2, ret);
    printf("Received message from client: %s [len: %d]\n", buf, ret);



    // Send close_notify alert.
    if (PR_Shutdown(c_nspr, PR_SHUTDOWN_BOTH) != PR_SUCCESS) {
        const PRErrorCode err = PR_GetError();
        fprintf(stderr, "error: PR_Shutdown error %d: %s\n",
            err, PR_ErrorToName(err));
        exit(1);
    }
    // Closes the underlying POSIX file descriptor, too.
    PR_Close(c_nspr);

    return 0;
}
