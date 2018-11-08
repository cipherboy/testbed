/* Copied from mod_nss */

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




/*
 * Given a nickname, find the "best" certificate available for that
 * certificate (for the case of multiple CN's with different usages, a
 * renewed cert that is not yet valid, etc). The best is defined as the
 * newest, valid server certificate.
 */
void list_nicknames()
{
    CERTCertList* clist;
    CERTCertificate* bestcert = NULL;

    CERTCertListNode *cln;
    PRUint32 bestCertMatchedUsage = 0;
    PRBool bestCertIsValid = PR_FALSE;

    clist = PK11_ListCerts(PK11CertListUser, NULL);

    for (cln = CERT_LIST_HEAD(clist); !CERT_LIST_END(cln,clist);
        cln = CERT_LIST_NEXT(cln)) {
        CERTCertificate* cert = cln->cert;
        const char* nickname = (const char*) cln->appData;


        if (!nickname) {
            nickname = cert->nickname;
        }
        printf("Nickname: %s\n", nickname);
    }
}

int main(int argc, char** argv)
{
    setup_nss_context();
    setup_nss_config();
    list_nicknames();
}
