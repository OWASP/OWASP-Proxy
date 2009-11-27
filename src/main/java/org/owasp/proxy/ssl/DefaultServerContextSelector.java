package org.owasp.proxy.ssl;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;


public class DefaultServerContextSelector implements SSLContextSelector {

	private SSLContext sslContext = null;

	public DefaultServerContextSelector() throws GeneralSecurityException,
			IOException {
		this(null, "password", "password");
	}

	public DefaultServerContextSelector(String resource, String storePassword,
			String keyPassword) throws GeneralSecurityException, IOException {
		if (resource == null) {
			resource = getClass().getPackage().getName().replace('.', '/')
					+ "/server.p12";
		}

		KeyStore ks = KeyStore.getInstance("PKCS12");
		InputStream is = getClass().getClassLoader().getResourceAsStream(
				resource);
		if (is != null) {
			char[] ksp = storePassword.toCharArray();
			ks.load(is, ksp);
			KeyManagerFactory kmf = KeyManagerFactory.getInstance("X509");
			char[] kp = keyPassword.toCharArray();
			kmf.init(ks, kp);
			sslContext = SSLContext.getInstance("SSLv3");
			sslContext.init(kmf.getKeyManagers(), null, null);
		} else
			throw new GeneralSecurityException("Couldn't find resource: "
					+ resource);
	}

	/**
	 * This default implementation uses the same certificate for all hosts.
	 * 
	 * @return an SSLSocketFactory generated from the relevant server key
	 *         material
	 */
	public SSLContext select(InetSocketAddress target) {
		if (sslContext == null) {
			throw new NullPointerException("sslContext is null!");
		}
		return sslContext;
	}

}
