package org.owasp.proxy.daemon;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

public class DefaultCertificateProvider implements CertificateProvider {

	private SSLSocketFactory sslSocketFactory = null;

	public DefaultCertificateProvider() throws GeneralSecurityException,
			IOException {
		this(null, "password", "password");
	}

	public DefaultCertificateProvider(String resource, String storePassword,
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
			KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
			char[] kp = keyPassword.toCharArray();
			kmf.init(ks, kp);
			SSLContext sslcontext = SSLContext.getInstance("SSLv3");
			sslcontext.init(kmf.getKeyManagers(), null, null);
			sslSocketFactory = sslcontext.getSocketFactory();
		} else
			throw new GeneralSecurityException("Couldn't find resource: "
					+ resource);
	}

	/**
	 * This default implementation uses the same certificate for all hosts.
	 * 
	 * @param host
	 *            the host that the client wishes to CONNECT to
	 * @param port
	 *            the port that the client wishes to CONNECT to
	 * @return an SSLSocketFactory generated from the relevant server key
	 *         material
	 */
	public SSLSocketFactory getSocketFactory(String host, int port)
			throws IOException {
		if (sslSocketFactory == null) {
			throw new NullPointerException("sslSocketFactory is null!");
		}
		return sslSocketFactory;
	}

}
