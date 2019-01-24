
import java.net.InetAddress;

import org.mozilla.jss.*;
import org.mozilla.jss.CryptoManager;
import org.mozilla.jss.ssl.SSLSocket;

public class TriggerClientHello {
    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            System.out.println("Usage: TriggerClientHello <hostname> <port>");
            System.out.println("Try to initiate a TLS connection to <hostname>:<port>");
            return;
        }

        Integer port = Integer.parseInt(args[1]);
        System.out.println("JSS Version: " + CryptoManager.JAR_JSS_VERSION);
        System.out.println("Connecting to " + args[0] + ":" + port);

        InitializationValues vals = new
                    InitializationValues("/etc/pki/nssdb");
        CryptoManager.initialize(vals);
        CryptoManager cm = CryptoManager.getInstance();

        SSLSocket.setCipherPolicy(org.mozilla.jss.ssl.CipherPolicy.DOMESTIC);
        for (Integer suite : SSLSocket.getImplementedCipherSuites()) {
            SSLSocket.setCipherPreferenceDefault(suite, true);
        }

        SSLSocket sock = new SSLSocket(InetAddress.getByName(args[0]).getHostAddress(), port);
        System.out.println("Local port: " + sock.getLocalPort());
        System.out.println("Connection options: " + sock.getSSLOptions());
        System.out.println("Default options: " + sock.getSSLDefaultOptions());

        for (Integer suite : sock.getImplementedCipherSuites()) {
            sock.setCipherPreference(suite, true);
            // System.out.println("Suite: " + suite + " -- enabled: " + sock.getCipherPreference(suite));
        }

        sock.setUseClientMode(true);
        sock.requireClientAuth(false, false);
        sock.forceHandshake();
    }
}
