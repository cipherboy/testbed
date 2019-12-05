import java.io.*;
import java.util.*;
import java.security.*;
import javax.net.ssl.*;

class Main {
	public static String db_password = "nss.SECret.123";

	public static void main(String[] args) throws Exception {
		listProviderFeatures();
		// tryKeyStore();
		// tryKeyManagerFactory();
	}

	public static void tryKeyStore() throws Exception {
		KeyStore ks = KeyStore.getInstance("PKCS11", "SunPKCS11-NSS-FIPS");
		ks.load(null, db_password.toCharArray());

		System.out.println("Got KeyStore: " + ks.getType() + "@" + ks.getProvider().getName());

		System.out.println("All known SunJSSE.PKCS12 aliases:");
		for (Enumeration<String> e = ks.aliases(); e.hasMoreElements(); ) {
			System.out.println(" - " + e.nextElement());
		}
		System.out.println();

		System.out.println("Contains: " + ks.containsAlias("a.cipherboy.com"));
	}

	public static void tryKeyManagerFactory() throws Exception {
		KeyStore ks = KeyStore.getInstance("PKCS11", "SunPKCS11-NSS-FIPS");
		ks.load(null, db_password.toCharArray());
		
		KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509", "SunJSSE");
		System.out.println("Got KeymanagerFactory: " + kmf.getAlgorithm() + "@" + kmf.getProvider().getName());

		kmf.init(ks, db_password.toCharArray());

		System.out.println("Available KeyManagers:");
		for (KeyManager km : kmf.getKeyManagers()) {
			X509ExtendedKeyManager ekm;
			if (!(km instanceof X509ExtendedKeyManager)) {
				System.out.println(" - KM of unknown type: " + km.getClass().getName());
				continue;
			} else {
				ekm = (X509ExtendedKeyManager) km;
			}
			System.out.println(" - " + ekm);
			for (String alias : ekm.getServerAliases("RSA", null)) {
				System.out.println("   - server::" + alias);
			}
			for (String alias : ekm.getClientAliases("RSA", null)) {
				System.out.println("   - client::" + alias);
			}
		}
	}

	public static void listProviderFeatures() throws Exception {
		for (Provider p : Security.getProviders()) {
			System.out.println("Got provider: " + p.getName());
			for (Object elem : p.keySet()) {
				System.out.println(" - " + elem.toString());
			}
		}
	}
}
