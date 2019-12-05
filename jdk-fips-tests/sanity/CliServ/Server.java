import java.io.*;
import java.security.*;
import java.util.*;
import javax.net.ssl.*;

public class Server {
    public final static boolean test_protocols = true;
    public final static boolean test_ciphersuites = true;
    public final static boolean cross_test_protocols_ciphersuites = false;
    public final static boolean test_specific = false;

    public final static String db_password = "nss.SECret.123";

    public final static String[] protocols = {
        "SSL",
        "SSLv2",
        "SSLv3",
        "TLS",
        "TLSv1",
        "TLSv1.0",
        "TLSv1.1",
        "TLSv1.2",
        "TLSv1.3"
    };

    public final static String[] cipher_suites = {
        "SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
        "SSL_DH_anon_EXPORT_WITH_RC4_40_MD5",
        "SSL_DH_anon_WITH_3DES_EDE_CBC_SHA",
        "TLS_DH_anon_WITH_AES_128_CBC_SHA",
        "TLS_DH_anon_WITH_AES_128_CBC_SHA256",
        "TLS_DH_anon_WITH_AES_128_GCM_SHA256",
        "TLS_DH_anon_WITH_AES_256_CBC_SHA",
        "TLS_DH_anon_WITH_AES_256_CBC_SHA256",
        "TLS_DH_anon_WITH_AES_256_GCM_SHA384",
        "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA",
        "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256",
        "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA",
        "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256",
        "SSL_DH_anon_WITH_DES_CBC_SHA",
        "SSL_DH_anon_WITH_RC4_128_MD5",
        "TLS_DH_anon_WITH_SEED_CBC_SHA",
        "SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
        "SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA",
        "TLS_DH_DSS_WITH_AES_128_CBC_SHA",
        "TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
        "TLS_DH_DSS_WITH_AES_128_GCM_SHA256",
        "TLS_DH_DSS_WITH_AES_256_CBC_SHA",
        "TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
        "TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
        "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",
        "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256",
        "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA",
        "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256",
        "SSL_DH_DSS_WITH_DES_CBC_SHA",
        "TLS_DH_DSS_WITH_SEED_CBC_SHA",
        "SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
        "SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
        "TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_DH_RSA_WITH_AES_256_CBC_SHA",
        "TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
        "TLS_DH_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA",
        "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
        "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",
        "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256",
        "SSL_DH_RSA_WITH_DES_CBC_SHA",
        "TLS_DH_RSA_WITH_SEED_CBC_SHA",
        "SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
        "SSL_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA",
        "SSL_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA",
        "SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
        "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
        "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
        "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
        "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
        "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
        "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
        "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
        "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256",
        "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
        "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256",
        "SSL_DHE_DSS_WITH_DES_CBC_SHA",
        "SSL_DHE_DSS_WITH_RC4_128_SHA",
        "TLS_DHE_DSS_WITH_SEED_CBC_SHA",
        "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA",
        "TLS_DHE_PSK_WITH_AES_128_CBC_SHA",
        "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
        "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
        "TLS_DHE_PSK_WITH_AES_256_CBC_SHA",
        "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
        "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
        "TLS_DHE_PSK_WITH_NULL_SHA",
        "TLS_DHE_PSK_WITH_NULL_SHA256",
        "TLS_DHE_PSK_WITH_NULL_SHA384",
        "TLS_DHE_PSK_WITH_RC4_128_SHA",
        "SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
        "SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
        "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
        "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
        "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
        "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
        "SSL_DHE_RSA_WITH_DES_CBC_SHA",
        "TLS_DHE_RSA_WITH_SEED_CBC_SHA",
        "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
        "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
        "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
        "TLS_ECDH_anon_WITH_NULL_SHA",
        "TLS_ECDH_anon_WITH_RC4_128_SHA",
        "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
        "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDH_ECDSA_WITH_NULL_SHA",
        "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
        "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDH_RSA_WITH_NULL_SHA",
        "TLS_ECDH_RSA_WITH_RC4_128_SHA",
        "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
        "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
        "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA",
        "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
        "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
        "TLS_ECDHE_PSK_WITH_NULL_SHA",
        "TLS_ECDHE_PSK_WITH_NULL_SHA256",
        "TLS_ECDHE_PSK_WITH_NULL_SHA384",
        "TLS_ECDHE_PSK_WITH_RC4_128_SHA",
        "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_ECDHE_RSA_WITH_NULL_SHA",
        "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
        "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
        "SSL_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA",
        "SSL_FORTEZZA_DMS_WITH_NULL_SHA",
        "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5",
        "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA",
        "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5",
        "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA",
        "TLS_KRB5_EXPORT_WITH_RC4_40_MD5",
        "TLS_KRB5_EXPORT_WITH_RC4_40_SHA",
        "TLS_KRB5_WITH_3DES_EDE_CBC_MD5",
        "TLS_KRB5_WITH_3DES_EDE_CBC_SHA",
        "TLS_KRB5_WITH_DES_CBC_MD5",
        "TLS_KRB5_WITH_DES_CBC_SHA",
        "TLS_KRB5_WITH_IDEA_CBC_MD5",
        "TLS_KRB5_WITH_IDEA_CBC_SHA",
        "TLS_KRB5_WITH_RC4_128_MD5",
        "TLS_KRB5_WITH_RC4_128_SHA",
        "TLS_PSK_WITH_3DES_EDE_CBC_SHA",
        "TLS_PSK_WITH_AES_128_CBC_SHA",
        "TLS_PSK_WITH_AES_128_CBC_SHA256",
        "TLS_PSK_WITH_AES_128_GCM_SHA256",
        "TLS_PSK_WITH_AES_256_CBC_SHA",
        "TLS_PSK_WITH_AES_256_CBC_SHA384",
        "TLS_PSK_WITH_AES_256_GCM_SHA384",
        "TLS_PSK_WITH_NULL_SHA",
        "TLS_PSK_WITH_NULL_SHA256",
        "TLS_PSK_WITH_NULL_SHA384",
        "TLS_PSK_WITH_RC4_128_SHA",
        "SSL_RSA_EXPORT_WITH_DES40_CBC_SHA",
        "SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
        "SSL_RSA_EXPORT_WITH_RC4_40_MD5",
        "SSL_RSA_EXPORT1024_WITH_DES_CBC_SHA",
        "SSL_RSA_EXPORT1024_WITH_RC4_56_SHA",
        "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA",
        "SSL_RSA_FIPS_WITH_DES_CBC_SHA",
        "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA",
        "TLS_RSA_PSK_WITH_AES_128_CBC_SHA",
        "TLS_RSA_PSK_WITH_AES_128_CBC_SHA256",
        "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256",
        "TLS_RSA_PSK_WITH_AES_256_CBC_SHA",
        "TLS_RSA_PSK_WITH_AES_256_CBC_SHA384",
        "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_PSK_WITH_NULL_SHA",
        "TLS_RSA_PSK_WITH_NULL_SHA256",
        "TLS_RSA_PSK_WITH_NULL_SHA384",
        "TLS_RSA_PSK_WITH_RC4_128_SHA",
        "SSL_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_RSA_WITH_AES_128_CBC_SHA",
        "TLS_RSA_WITH_AES_128_CBC_SHA256",
        "TLS_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_RSA_WITH_AES_256_CBC_SHA",
        "TLS_RSA_WITH_AES_256_CBC_SHA256",
        "TLS_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
        "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
        "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
        "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
        "SSL_RSA_WITH_DES_CBC_SHA",
        "SSL_RSA_WITH_IDEA_CBC_SHA",
        "SSL_RSA_WITH_NULL_MD5",
        "SSL_RSA_WITH_NULL_SHA",
        "TLS_RSA_WITH_NULL_SHA256",
        "SSL_RSA_WITH_RC4_128_MD5",
        "SSL_RSA_WITH_RC4_128_SHA",
        "TLS_RSA_WITH_SEED_CBC_SHA",
        "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA",
        "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA",
        "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA",
        "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA",
        "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA",
        "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA",
        "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA",
        "TLS_SRP_SHA_WITH_AES_128_CBC_SHA",
        "TLS_SRP_SHA_WITH_AES_256_CBC_SHA"
    };

    public static KeyStore ks;
    public static KeyManagerFactory kmf;
    public static TrustManagerFactory tmf;
    public static SecureRandom sr;

    public static void init() throws Exception {
        ks = KeyStore.getInstance("PKCS11", "SunPKCS11-NSS-FIPS");
        kmf = KeyManagerFactory.getInstance("SunX509", "SunJSSE");
        tmf = TrustManagerFactory.getInstance("SunX509", "SunJSSE");
        sr = SecureRandom.getInstance("PKCS11", "SunPKCS11-NSS-FIPS");

        ks.load(null, db_password.toCharArray());
        kmf.init(ks, db_password.toCharArray());
        tmf.init(ks);
        sr.nextBytes(new byte[5]);
    }

    public static void testProtocols() throws Exception {
        System.out.println("Available protocols for use with SSLContext:");

        for (String protocol : protocols) {
            try {
                SSLContext ctx = SSLContext.getInstance(protocol, "SunJSSE");
                KeyManager[] kms = kmf.getKeyManagers();
                TrustManager[] tms = tmf.getTrustManagers();

                ctx.init(kms, tms, sr);

                System.out.println(" - " + protocol + " :: OK");
            } catch (NoSuchAlgorithmException nsae) {
                System.out.println(" - " + protocol + " :: Missing");
            } catch (Exception e) {
                System.out.println(" - " + protocol + " :: Failed");
                throw e;
            }
        }
    }

    public static void testCipherSuites(String protocol) throws Exception {
        System.out.println("Testing under protocol: " + protocol);

        String[] enabled_protocols;

        if (protocol.equals("SSL")) {
            enabled_protocols = new String[] { "SSLv2", "SSLv3" };
        } else if (protocol.equals("TLS")) {
            enabled_protocols = new String[] { "TLSv1", "TLSv1.1", "TLSv1.2" };
        } else {
            enabled_protocols = new String[] { protocol };
        }

        for (String cipher_suite : cipher_suites) {
            try {
                SSLContext ctx = SSLContext.getInstance(protocol, "SunJSSE");
                KeyManager[] kms = kmf.getKeyManagers();
                TrustManager[] tms = tmf.getTrustManagers();

                ctx.init(kms, tms, sr);

                SSLEngine engine = ctx.createSSLEngine();
                engine.setEnabledProtocols(enabled_protocols);
                engine.setEnabledCipherSuites(new String[] { cipher_suite } );
                engine.setUseClientMode(false);
                engine.beginHandshake();

                System.out.println(" - " + cipher_suite + " :: OK");
            } catch (IllegalArgumentException iae) {
                // System.out.println(" - " + cipher_suite + " :: Unsupported");
            } catch (SSLHandshakeException she) {
                // System.out.println(" - " + cipher_suite + " :: Failed - " + she.getMessage());
            } catch (Exception e) {
                System.out.println(" - " + cipher_suite + " :: Failed");
                throw e;
            }
        }
    }

    public static void main(String[] args) throws Exception {
        init();

        System.out.println("Known protocols: " + protocols.length);
        System.out.println("Known cipher suites: " + cipher_suites.length);

        if (test_protocols) {
            testProtocols();
        }
        if (test_ciphersuites) {
            String protocol = "TLS";
            if (args.length >= 1) {
                protocol = args[0];
            }

            testCipherSuites(protocol);
        }
    }
}
